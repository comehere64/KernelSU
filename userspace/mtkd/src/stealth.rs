//! 进程隐身。
//!
//! 目标：网页端执行 `sh` 之后，`ps` / 进程管理器里看到的不是一个显眼的 shell，
//! 而是一个和系统内核线程同形的名字。
//!
//! 原理（在用户态能做到的最大程度）：
//!   * `/proc/<pid>/comm`（也就是 `ps -A` 的 NAME 列）由内核设成 **被 exec 的可执行
//!     文件名**，进程自己再 `prctl(PR_SET_NAME)` 或写 `/proc/self/comm` 才能改。
//!     mksh 不会替我们做这件事，所以靠"改 argv[0]"是不行的 —— 实测 comm 仍是 sh。
//!   * 但 comm 取自文件名：把 `/system/bin/sh` 软链成 `kworker`，然后 exec 这个链接，
//!     comm 就是 `kworker`，argv[0] 也一并可以是 `kworker`，cmdline 同样干净。
//!
//! 于是：在 BINARY_DIR 下维护一个伪装名的软链，执行时用它当解释器。
//! 名字取自常见内核线程，混在 `ps` 里毫不显眼。

use std::path::PathBuf;

/// 伪装名。
///
/// 必须是固定值：交互式 shell 里的 alias 要指向它，名字一变 alias 就悬空了。
const STEALTH_NAME: &str = "kworker";

const fn pick_name() -> &'static str {
    STEALTH_NAME
}

/// 返回 (可执行文件路径, argv[0]) —— 两者都是伪装名。
///
/// 首次调用时会建立软链 `BINARY_DIR/<name> -> /system/bin/sh`；已存在就直接复用。
/// 建不出来（例如只读 /data/adb）时退回真实 shell，功能优先。
#[cfg(target_os = "android")]
pub fn stealth_shell() -> (PathBuf, String) {
    let name = pick_name();
    let link = PathBuf::from(crate::defs::BINARY_DIR).join(name);

    if std::fs::symlink_metadata(&link).is_err() {
        let _ = std::fs::create_dir_all(crate::defs::BINARY_DIR);
        // 优先复制一份真二进制，而不是软链：
        //   软链的话 /proc/<pid>/exe -> /system/bin/sh，`ls -l` 一眼就露；
        //   复制成 BINARY_DIR/kworker 之后 exe 指向 /data/adb/ksu/bin/kworker，
        //   名字和路径都跟"内核线程"这层皮对得上。
        let copied = std::fs::copy(crate::defs::SHELL_PATH, &link).is_ok();
        if copied {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&link, std::fs::Permissions::from_mode(0o755));
        } else if std::os::unix::fs::symlink(crate::defs::SHELL_PATH, &link).is_err() {
            return (PathBuf::from(crate::defs::SHELL_PATH), name.to_string());
        }
    }

    (link, name.to_string())
}

#[cfg(not(target_os = "android"))]
pub fn stealth_shell() -> (PathBuf, String) {
    (
        PathBuf::from(crate::defs::SHELL_PATH),
        "kworker".to_string(),
    )
}

/// 终端启动用的 rc：把 `sh` / `bash` / `ash` 都 alias 到伪装名。
///
/// 交互式敲 `sh xxx.sh` 时，alias 会把它变成 `kworker xxx.sh` —— 仍然是**一个**进程，
/// 而 comm 取自被 exec 的路径，所以是 kworker，不是 sh。
/// （`./xxx.sh` 直接执行的情况管不到：那是内核按 shebang 起的新进程。）
#[cfg(target_os = "android")]
pub fn ensure_stealth_rc() -> std::path::PathBuf {
    use std::io::Write;

    let rc = std::path::Path::new(crate::defs::WORKING_DIR).join(".webui_env");
    let body = format!(
        "# 网页端终端 / su 会话自动 source 的启动文件（由 mtkd 生成，别手改）\n\
         [ -f {ksurc} ] && . {ksurc}\n\
         alias sh={name}\n\
         alias ash={name}\n\
         alias bash={name}\n",
        ksurc = crate::stealth::quote_sh(crate::defs::KSURC_PATH),
        name = crate::stealth::quote_sh(STEALTH_NAME),
    );
    if std::fs::read_to_string(&rc).ok().as_deref() != Some(body.as_str()) {
        let _ = std::fs::create_dir_all(crate::defs::WORKING_DIR);
        if let Ok(mut file) = std::fs::File::create(&rc) {
            let _ = file.write_all(body.as_bytes());
        }
    }
    rc
}

#[cfg(not(target_os = "android"))]
pub fn ensure_stealth_rc() -> std::path::PathBuf {
    std::path::PathBuf::from("/dev/null")
}

/// 供 `exec_script` 用：把脚本包成一条 `sh -c` 命令。
///
/// 用 `.`（source）在当前 shell 里执行，避免再多一层进程；同时把自身 comm 也改成
/// 伪装名（让 shell 内建命令产生的子进程之外，主进程始终是伪装名）。
#[cfg(target_os = "android")]
pub fn stealth_script_command(script: &std::path::Path, name: &str) -> String {
    let quoted = quote_path(&script.display().to_string());
    format!(
        "printf '%s' {name_q} > /proc/$$/comm 2>/dev/null; . {quoted}",
        name_q = quote_sh(name),
    )
}

#[cfg(not(target_os = "android"))]
pub fn stealth_script_command(script: &std::path::Path, _name: &str) -> String {
    format!(". {}", quote_path(&script.display().to_string()))
}

/// 单引号包一层，内部的 ' 用 '"'"' 断开。
pub fn quote_sh(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('\'');
    for ch in value.chars() {
        if ch == '\'' {
            out.push_str("'\"'\"'");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

fn quote_path(value: &str) -> String {
    quote_sh(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting_survives_single_quotes() {
        assert_eq!(quote_sh("abc"), "'abc'");
        assert_eq!(quote_sh("a'b"), "'a'\"'\"'b'");
        assert_eq!(quote_sh(""), "''");
    }

    #[test]
    fn script_command_sources_the_file() {
        let cmd = stealth_script_command(
            std::path::Path::new("/data/adb/modules/x/service.sh"),
            "kworker",
        );
        assert!(cmd.contains(". '/data/adb/modules/x/service.sh'"), "{cmd}");
    }

    #[test]
    fn stealth_name_is_kernel_thread_style() {
        let name = STEALTH_NAME;
        assert!(name.len() <= 15, "{name} 超过 TASK_COMM_LEN 限长");
        assert!(
            name.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
            "{name} 不像内核线程名"
        );
    }
}
