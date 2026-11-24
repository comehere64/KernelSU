
#![allow(clippy::all, clippy::pedantic, clippy::nursery)]

use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use anyhow::{Context, Result, bail};

const MAX_SESSIONS: usize = 4;
const BUFFER_CAP: usize = 256 * 1024;

/// 网页 shell 的环境白名单。
///
/// ksud 常驻进程如果是从 Termux / 调试会话里拉起来的，environ 里就带着
/// TERMUX_VERSION、PREFIX、TERMUX_APP__* 这些标记；子 shell 一旦继承，脚本里
/// 一句 `env` 就能证明"这段跑在 Termux 里"，比 /data/adb/ksu 目录还显眼。
/// 所以这里彻底清空，再按 Android root shell 的常态重建。
#[cfg(target_os = "android")]
const ROOT_SHELL_PATH: &str = "/product/bin:/apex/com.android.runtime/bin:/apex/com.android.art/bin:/system_ext/bin:/system/bin:/system/xbin:/odm/bin:/vendor/bin:/vendor/xbin";

#[cfg(target_os = "android")]
fn shell_env(dir: &str) -> Vec<(String, String)> {
    vec![
        ("PATH".into(), ROOT_SHELL_PATH.into()),
        ("SHELL".into(), crate::defs::SHELL_PATH.into()),
        ("TERM".into(), "xterm-256color".into()),
        ("HOME".into(), "/data/local/tmp".into()),
        ("PWD".into(), dir.into()),
        ("TMPDIR".into(), "/data/local/tmp".into()),
        ("USER".into(), "root".into()),
        ("LOGNAME".into(), "root".into()),
        ("HISTFILE".into(), "/dev/null".into()),
        ("ANDROID_ROOT".into(), "/system".into()),
        ("ANDROID_DATA".into(), "/data".into()),
    ]
}

#[cfg(not(target_os = "android"))]
fn shell_env(dir: &str) -> Vec<(String, String)> {
    // 本地测试机（Termux / Linux）沿用本机 PATH，否则相对名 "sh" 解析不到。
    // 真机走 android 分支，那条路径是写死的白名单，不会带出宿主。
    let path = std::env::var("PATH").unwrap_or_else(|_| "/usr/local/bin:/usr/bin:/bin".into());
    vec![
        ("PATH".into(), path),
        ("SHELL".into(), crate::defs::SHELL_PATH.into()),
        ("TERM".into(), "xterm-256color".into()),
        ("PWD".into(), dir.into()),
        ("HOME".into(), dir.into()),
    ]
}

/// 工作目录也要挡一道：Termux 的家目录本身就是强特征，
/// 网页那边万一传进来，一律回落到 `/`。
fn safe_cwd(cwd: &str) -> &str {
    let leaky = cwd.contains("com.termux")
        || cwd.starts_with("/data/data/")
        || cwd.starts_with("/data/user/");
    if leaky || !Path::new(cwd).is_dir() { "/" } else { cwd }
}

struct Output {
    text: String,
    read_at: usize,
}

#[cfg(unix)]
struct Pty {
    pid: libc::pid_t,
    master: std::fs::File,
}

enum Backend {
    Pipe {
        child: Child,
        stdin: ChildStdin,
    },
    #[cfg(unix)]
    Pty(Box<Pty>),
}

struct Session {
    backend: Backend,
    output: Arc<Mutex<Output>>,
}

static SESSIONS: Mutex<Option<HashMap<u32, Session>>> = Mutex::new(None);
static NEXT_ID: AtomicU32 = AtomicU32::new(1);

fn with_sessions<T>(f: impl FnOnce(&mut HashMap<u32, Session>) -> T) -> T {
    let mut guard = SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
    let sessions = guard.get_or_insert_with(HashMap::new);
    f(sessions)
}

fn push_output(output: &Arc<Mutex<Output>>, text: &str) {
    let mut out = output.lock().unwrap_or_else(|e| e.into_inner());
    out.text.push_str(text);

    if out.text.len() > BUFFER_CAP {
        let mut cut = out.text.len() - BUFFER_CAP;
        while cut < out.text.len() && !out.text.is_char_boundary(cut) {
            cut += 1;
        }
        out.text.drain(..cut);
        out.read_at = out.read_at.saturating_sub(cut);
    }
}

fn spawn_reader(mut source: impl Read + Send + 'static, output: Arc<Mutex<Output>>) {
    thread::spawn(move || {
        let mut chunk = [0u8; 4096];
        while let Ok(n) = source.read(&mut chunk) {
            if n == 0 {
                break;
            }
            let text = String::from_utf8_lossy(&chunk[..n]).into_owned();
            push_output(&output, &text);
        }
    });
}

/// `execve` 不像 `execvp` 那样搜 PATH，相对名会直接 ENOENT。
/// 这里按我们即将交给子进程的那条 PATH 自己解析一遍。
fn resolve_program(program: &str, path_env: &str) -> Option<String> {
    if program.contains('/') {
        return Path::new(program).is_file().then(|| program.to_string());
    }
    for dir in path_env.split(':').filter(|d| !d.is_empty()) {
        let candidate = format!("{dir}/{program}");
        if Path::new(&candidate).is_file() {
            return Some(candidate);
        }
    }
    None
}

#[cfg(unix)]
fn spawn_pty(dir: &str) -> Result<Box<Pty>> {
    use std::ffi::CString;
    use std::os::fd::FromRawFd;

    let env_pairs = shell_env(dir);
    let path_env = env_pairs
        .iter()
        .find(|(k, _)| k == "PATH")
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    let resolved = resolve_program(crate::defs::SHELL_PATH, path_env)
        .with_context(|| format!("在 PATH={path_env} 里找不到 {}", crate::defs::SHELL_PATH))?;
    let program = CString::new(resolved)?;
    let interactive = CString::new("-i")?;
    let workdir = CString::new(dir)?;
    let root = CString::new("/")?;

    // 环境只给下面这一份，宿主的一点都不带。
    let env_c: Vec<CString> = env_pairs
        .into_iter()
        .filter_map(|(k, v)| CString::new(format!("{k}={v}")).ok())
        .collect();
    let mut envp: Vec<*const libc::c_char> = env_c.iter().map(|c| c.as_ptr()).collect();
    envp.push(std::ptr::null());

    unsafe {
        let mut master: libc::c_int = -1;
        let mut slave: libc::c_int = -1;
        if libc::openpty(
            &raw mut master,
            &raw mut slave,
            std::ptr::null_mut(),
            // apple/bsd 的 openpty 签名是 *mut termios / *mut winsize，
            // Android(bionic) 是 *const：null_mut 两边都能隐式转，null() 在 mac 上编不过。
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        ) != 0
        {
            return Err(std::io::Error::last_os_error()).with_context(|| "openpty 失败");
        }

        let mut fds = [0 as libc::c_int; 2];
        if libc::pipe(fds.as_mut_ptr()) != 0 {
            let err = std::io::Error::last_os_error();
            libc::close(master);
            libc::close(slave);
            return Err(err).with_context(|| "pipe 失败");
        }

        // 双 fork：中间进程只把孙进程的 pid 递回来就退出。
        // 结果 shell 的父进程是 init(1)，按 PPID 顺藤摸瓜找不到 ksud。
        let mid = libc::fork();
        if mid < 0 {
            let err = std::io::Error::last_os_error();
            libc::close(master);
            libc::close(slave);
            libc::close(fds[0]);
            libc::close(fds[1]);
            return Err(err).with_context(|| "fork 失败");
        }

        if mid == 0 {
            libc::close(master);
            libc::close(fds[0]);

            let pid = libc::fork();
            if pid < 0 {
                libc::_exit(127);
            }
            if pid == 0 {
                libc::close(fds[1]);
                libc::setsid();
                libc::ioctl(slave, libc::TIOCSCTTY as _, 0);
                libc::dup2(slave, 0);
                libc::dup2(slave, 1);
                libc::dup2(slave, 2);
                if slave > 2 {
                    libc::close(slave);
                }
                // 关键：把 3 以后所有 fd 全关掉。
                //
                // 只 dup2 0/1/2 是不够的——ksud 的监听 socket、日志 fd、
                // 各种内部句柄都会被这个 shell 继承，然后顺着 fork 传到每一条
                // 用户命令里。等于把面板的连接句柄发给脚本，脚本随手一个
                // `curl`/`nc` 就能接住面板流量，`ls /proc/self/fd` 也能看见。
                // close_range 在 5.9+ 有，老内核退回逐个 close。
                #[cfg(target_os = "android")]
                {
                    if libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32) != 0 {
                        for fd in 3..1024 {
                            libc::close(fd);
                        }
                    }
                }
                if libc::chdir(workdir.as_ptr()) != 0 {
                    libc::chdir(root.as_ptr());
                }
                let argv = [program.as_ptr(), interactive.as_ptr(), std::ptr::null()];
                libc::execve(program.as_ptr(), argv.as_ptr(), envp.as_ptr());
                libc::_exit(127);
            }

            let bytes = pid.to_ne_bytes();
            libc::write(fds[1], bytes.as_ptr() as *const libc::c_void, 4);
            libc::close(fds[1]);
            libc::_exit(0);
        }

        libc::close(slave);
        libc::close(fds[1]);

        let mut buf = [0u8; 4];
        let got = libc::read(fds[0], buf.as_mut_ptr() as *mut libc::c_void, 4);
        libc::close(fds[0]);
        let mut status = 0;
        libc::waitpid(mid, &raw mut status, 0);

        if got != 4 {
            libc::close(master);
            bail!("无法取得 shell 进程号");
        }

        Ok(Box::new(Pty {
            pid: i32::from_ne_bytes(buf),
            master: std::fs::File::from_raw_fd(master),
        }))
    }
}

fn spawn_pipe(dir: &str, output: &Arc<Mutex<Output>>) -> Result<Backend> {
    let mut cmd = Command::new(crate::defs::SHELL_PATH);
    // 先清空再注入，宿主环境一点不漏。
    cmd.env_clear();
    for (k, v) in shell_env(dir) {
        cmd.env(k, v);
    }
    let mut child = cmd
        .current_dir(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("无法启动 {}（工作目录 {dir}）", crate::defs::SHELL_PATH))?;

    let stdin = child.stdin.take().context("无法获取 shell 的 stdin")?;
    if let Some(stdout) = child.stdout.take() {
        spawn_reader(stdout, Arc::clone(output));
    }
    if let Some(stderr) = child.stderr.take() {
        spawn_reader(stderr, Arc::clone(output));
    }
    Ok(Backend::Pipe { child, stdin })
}

pub fn open(cwd: &str) -> Result<(u32, bool)> {
    let dir = safe_cwd(cwd);
    let output = Arc::new(Mutex::new(Output {
        text: String::new(),
        read_at: 0,
    }));

    #[cfg(unix)]
    let backend = match spawn_pty(dir) {
        Ok(pty_handle) => {
            if let Ok(reader) = pty_handle.master.try_clone() {
                spawn_reader(reader, Arc::clone(&output));
            }
            Backend::Pty(pty_handle)
        }
        Err(e) => {
            log::warn!("terminal: 无法创建 pty（{e:#}），改用管道");
            spawn_pipe(dir, &output)?
        }
    };

    #[cfg(not(unix))]
    let backend = spawn_pipe(dir, &output)?;

    #[cfg(unix)]
    let pty = matches!(backend, Backend::Pty(_));
    #[cfg(not(unix))]
    let pty = false;

    if !pty {
        push_output(
            &output,
            "[提示] 拿不到 PTY，终端运行在管道模式：\n\
             [提示] 脚本可能不显示输出、也可能把你的输入当成命令。\n\n",
        );
    }

    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    with_sessions(|sessions| {
        if sessions.len() >= MAX_SESSIONS {
            if let Some(oldest) = sessions.keys().copied().min() {
                close_in(sessions, oldest);
            }
        }
        sessions.insert(id, Session { backend, output });
    });
    Ok((id, pty))
}

fn alive(backend: &mut Backend) -> bool {
    match backend {
        Backend::Pipe { child, .. } => matches!(child.try_wait(), Ok(None)),
        #[cfg(unix)]
        // double fork 之后 shell 挂在 init 下，waitpid 会直接 ECHILD，
        // 所以这里只能靠 kill(pid, 0) 探活。
        Backend::Pty(pty) => unsafe { libc::kill(pty.pid, 0) == 0 },
    }
}

pub fn write(id: u32, data: &str) -> Result<()> {
    with_sessions(|sessions| {
        let session = sessions
            .get_mut(&id)
            .with_context(|| format!("终端会话 {id} 不存在（可能已关闭）"))?;
        match &mut session.backend {
            Backend::Pipe { stdin, .. } => {
                stdin
                    .write_all(data.as_bytes())
                    .context("写入 shell 失败")?;
                stdin.flush().context("刷新 shell 输入失败")
            }
            #[cfg(unix)]
            Backend::Pty(pty) => {
                pty.master
                    .write_all(data.as_bytes())
                    .context("写入 pty 失败")?;
                pty.master.flush().context("刷新 pty 失败")
            }
        }
    })
}

pub fn read(id: u32) -> Result<(String, bool)> {
    with_sessions(|sessions| {
        let session = sessions
            .get_mut(&id)
            .with_context(|| format!("终端会话 {id} 不存在（可能已关闭）"))?;
        let running = alive(&mut session.backend);

        let mut out = session.output.lock().unwrap_or_else(|e| e.into_inner());
        let from = out.read_at.min(out.text.len());
        let fresh = out.text[from..].to_string();
        out.read_at = out.text.len();
        Ok((fresh, running))
    })
}

fn close_in(sessions: &mut HashMap<u32, Session>, id: u32) {
    if let Some(session) = sessions.remove(&id) {
        match session.backend {
            Backend::Pipe { mut child, .. } => {
                let _ = child.kill();
                let _ = child.wait();
            }
            #[cfg(unix)]
            // 不是我们的子进程，kill 完由 init 回收，不要再 waitpid。
            Backend::Pty(pty) => unsafe {
                libc::kill(pty.pid, libc::SIGKILL);
            },
        }
    }
}

pub fn close(id: u32) -> Result<()> {
    with_sessions(|sessions| -> Result<()> {
        if !sessions.contains_key(&id) {
            bail!("终端会话 {id} 不存在");
        }
        close_in(sessions, id);
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn shell_available() -> bool {
        if Command::new(crate::defs::SHELL_PATH)
            .arg("-c")
            .arg("true")
            .status()
            .is_ok()
        {
            true
        } else {
            eprintln!("skipping: no `sh` on this host");
            false
        }
    }

    fn read_until(id: u32, needle: &str) -> String {
        let mut seen = String::new();
        for _ in 0..100 {
            if let Ok((chunk, _)) = read(id) {
                seen.push_str(&chunk);
            }
            if seen.contains(needle) {
                return seen;
            }
            thread::sleep(Duration::from_millis(50));
        }
        seen
    }

    #[test]
    fn runs_a_command_and_returns_its_output() {
        if !shell_available() {
            return;
        }
        let (id, _) = open("/").expect("open session");
        write(id, "echo ksu-shell-ok\n").expect("write");
        let seen = read_until(id, "ksu-shell-ok");
        assert!(seen.contains("ksu-shell-ok"), "got: {seen:?}");
        close(id).expect("close");
    }

    #[test]
    fn typed_input_reaches_a_script_read() {
        if !shell_available() {
            return;
        }
        let (id, _) = open("/").expect("open session");
        write(id, "read answer; echo \"you said $answer\"\n").expect("write");
        thread::sleep(Duration::from_millis(300));
        write(id, "42\n").expect("write input");
        let seen = read_until(id, "you said 42");
        assert!(seen.contains("you said 42"), "got: {seen:?}");
        close(id).expect("close");
    }

    #[test]
    fn reading_twice_does_not_repeat_output() {
        if !shell_available() {
            return;
        }
        let (id, _) = open("/").expect("open session");
        write(id, "echo once-only\n").expect("write");
        let first = read_until(id, "once-only");
        assert!(first.contains("once-only"));
        let (second, _) = read(id).expect("read");
        assert!(!second.contains("once-only"), "output repeated: {second:?}");
        close(id).expect("close");
    }

    #[test]
    fn closing_removes_the_session() {
        if !shell_available() {
            return;
        }
        let (id, _) = open("/").expect("open session");
        close(id).expect("close");
        assert!(read(id).is_err(), "session should be gone after close");
    }

    /// 网页 shell 不许把宿主的身份带出来。
    #[test]
    fn shell_does_not_inherit_the_host_environment() {
        if !shell_available() {
            return;
        }
        let (id, _) = open("/").expect("open session");
        write(id, "env\n").expect("write");
        thread::sleep(Duration::from_millis(400));
        let (seen, _) = read(id).expect("read");
        for leak in ["TERMUX", "PREFIX=", "com.termux", "files/home"] {
            assert!(
                !seen.contains(leak),
                "宿主环境泄漏了 {leak}: {seen:?}"
            );
        }
        assert!(seen.contains("PWD=/") || seen.contains("PWD=/\r"), "缺少 PWD: {seen:?}");
        close(id).expect("close");
    }

    /// shell 不能挂在 ksud 下面，否则按 PPID 一扫就露。
    #[cfg(target_os = "android")]
    #[test]
    fn shell_is_reparented_to_init() {
        if !shell_available() {
            return;
        }
        let (id, _) = open("/").expect("open session");
        write(id, "grep PPid /proc/$$/status\n").expect("write");
        let seen = read_until(id, "PPid:");
        assert!(seen.contains("PPid:\t1") || seen.contains("PPid: 1") || seen.contains("PPid:\t 1"),
            "shell 的父进程不是 init: {seen:?}");
        close(id).expect("close");
    }

    #[cfg(unix)]
    #[test]
    fn pty_reports_itself_and_accepts_a_bare_newline() {
        if !shell_available() {
            return;
        }
        let (id, pty) = open("/").expect("open session");
        assert!(pty, "expected a pty on unix");

        // 不能写在 $( ) 里：命令替换的 stdout 是管道，-t 1 永远为假。
        write(id, "[ -t 1 ] && echo in-tty=YES || echo in-tty=NO\n").expect("write");
        let seen = read_until(id, "in-tty=");
        assert!(
            seen.contains("in-tty=YES"),
            "child did not see a tty: {seen:?}"
        );

        write(id, "read x; echo \"got=[$x]\"\n").expect("write");
        thread::sleep(Duration::from_millis(300));
        write(id, "\n").expect("bare newline");
        let seen = read_until(id, "got=[]");
        assert!(
            seen.contains("got=[]"),
            "bare newline did not satisfy read: {seen:?}"
        );
        close(id).expect("close");
    }
}
