use anyhow::{Context, Error, Ok, Result, bail};
use rustix::fs::{Mode, OFlags, open};
use rustix::process::setpgid;
use rustix::stdio::{dup2_stderr, dup2_stdin, dup2_stdout};
use std::{
    ffi::{CStr, CString, c_char, c_void},
    fs::{File, OpenOptions, create_dir_all, remove_file, write},
    io::{
        ErrorKind::{AlreadyExists, NotFound},
        Write,
    },
    path::Path,
    process::Command,
};

use crate::defs::KSU_TEMP_BACKUP_DIR_NAME;
use crate::{assets, boot_patch, defs, ksucalls, module, restorecon};
#[allow(unused_imports)]
use std::fs::{Permissions, set_permissions};
use std::os::unix::prelude::PermissionsExt;

use std::path::PathBuf;

use crate::boot_patch::BootRestoreArgs;

use rustix::{
    process,
    thread::{LinkNameSpaceType, move_into_link_name_space},
};

type PropertyReadCallback = unsafe extern "C" fn(*mut c_void, *const c_char, *const c_char, u32);

unsafe extern "C" {
    fn __system_property_find(name: *const c_char) -> *const c_void;
    fn __system_property_read_callback(
        property_info: *const c_void,
        callback: PropertyReadCallback,
        cookie: *mut c_void,
    );
}

#[macro_export]
macro_rules! debug_select {
    ($debug:expr, $release:expr) => {{
        #[cfg(debug_assertions)]
        {
            $debug
        }
        #[cfg(not(debug_assertions))]
        {
            $release
        }
    }};
}

pub fn ensure_clean_dir(dir: impl AsRef<Path>) -> Result<()> {
    let path = dir.as_ref();
    log::debug!("ensure_clean_dir: {}", path.display());
    if path.exists() {
        log::debug!("ensure_clean_dir: {} exists, remove it", path.display());
        std::fs::remove_dir_all(path)?;
    }
    Ok(std::fs::create_dir_all(path)?)
}

pub fn ensure_file_exists<T: AsRef<Path>>(file: T) -> Result<()> {
    match File::options().write(true).create_new(true).open(&file) {
        std::result::Result::Ok(_) => Ok(()),
        Err(err) => {
            if err.kind() == AlreadyExists && file.as_ref().is_file() {
                Ok(())
            } else {
                Err(Error::from(err))
                    .with_context(|| format!("{} is not a regular file", file.as_ref().display()))
            }
        }
    }
}

pub fn ensure_dir_exists<T: AsRef<Path>>(dir: T) -> Result<()> {
    let result = create_dir_all(&dir);
    if dir.as_ref().is_dir() && result.is_ok() {
        Ok(())
    } else {
        bail!("{} is not a regular directory", dir.as_ref().display())
    }
}

pub fn ensure_binary<T: AsRef<Path>>(
    path: T,
    contents: &[u8],
    ignore_if_exist: bool,
) -> Result<()> {
    if ignore_if_exist && path.as_ref().exists() {
        return Ok(());
    }

    ensure_dir_exists(path.as_ref().parent().ok_or_else(|| {
        anyhow::anyhow!(
            "{} does not have parent directory",
            path.as_ref().to_string_lossy()
        )
    })?)?;

    if let Err(e) = remove_file(path.as_ref())
        && e.kind() != NotFound
    {
        return Err(Error::from(e))
            .with_context(|| format!("failed to unlink {}", path.as_ref().display()));
    }

    write(&path, contents)?;
    set_permissions(&path, Permissions::from_mode(0o755))?;
    Ok(())
}

unsafe extern "C" fn property_read_callback(
    cookie: *mut c_void,
    _name: *const c_char,
    value: *const c_char,
    _serial: u32,
) {
    if cookie.is_null() || value.is_null() {
        return;
    }

    let result = unsafe { &mut *cookie.cast::<Option<String>>() };
    let value = unsafe { CStr::from_ptr(value) };
    *result = Some(value.to_string_lossy().into_owned());
}

pub fn getprop(name: &str) -> Option<String> {
    let name = CString::new(name).ok()?;
    let property_info = unsafe { __system_property_find(name.as_ptr()) };
    if property_info.is_null() {
        return None;
    }

    let mut value = None;
    unsafe {
        __system_property_read_callback(
            property_info,
            property_read_callback,
            std::ptr::addr_of_mut!(value).cast(),
        );
    }
    value
}

pub fn is_safe_mode() -> bool {
    let safemode = getprop("persist.sys.safemode")
        .as_ref()
        .is_some_and(|prop| prop == "1")
        || getprop("ro.sys.safemode")
            .as_ref()
            .is_some_and(|prop| prop == "1");
    log::info!("safemode: {safemode}");
    if safemode {
        return true;
    }
    let safemode = ksucalls::check_kernel_safemode();
    log::info!("kernel_safemode: {safemode}");
    safemode
}

pub fn get_zip_uncompressed_size(zip_path: &str) -> Result<u64> {
    let mut zip = zip::ZipArchive::new(std::fs::File::open(zip_path)?)?;
    let mut total: u64 = 0;
    for i in 0..zip.len() {
        total += zip.by_index(i)?.size();
    }
    Ok(total)
}

pub fn switch_mnt_ns(pid: i32) -> Result<()> {
    use rustix::{
        fd::AsFd,
        fs::{Mode, OFlags, open},
    };
    let path = format!("/proc/{pid}/ns/mnt");
    let fd = open(path, OFlags::RDONLY, Mode::from_raw_mode(0))?;
    let current_dir = std::env::current_dir();
    move_into_link_name_space(fd.as_fd(), Some(LinkNameSpaceType::Mount))?;
    if let std::result::Result::Ok(current_dir) = current_dir {
        let _ = std::env::set_current_dir(current_dir);
    }
    Ok(())
}

fn switch_cgroup(grp: &str, pid: u32) {
    let path = Path::new(grp).join("cgroup.procs");
    if !path.exists() {
        return;
    }

    let fp = OpenOptions::new().append(true).open(path);
    if let std::result::Result::Ok(mut fp) = fp {
        let _ = write!(fp, "{pid}");
    }
}

pub fn switch_cgroups() {
    let pid = std::process::id();
    switch_cgroup("/acct", pid);
    switch_cgroup("/dev/cg2_bpf", pid);
    switch_cgroup("/sys/fs/cgroup", pid);

    if getprop("ro.config.per_app_memcg")
        .as_ref()
        .is_none_or(|prop| prop != "false")
    {
        switch_cgroup("/dev/memcg/apps", pid);
    }
}

pub fn umask(mask: u32) {
    process::umask(rustix::fs::Mode::from_raw_mode(mask));
}

pub fn has_magisk() -> bool {
    which::which("magisk").is_ok()
}

fn link_ksud_to_bin() -> Result<()> {
    let ksu_bin = PathBuf::from(defs::DAEMON_PATH);
    let ksu_bin_link = PathBuf::from(defs::DAEMON_LINK_PATH);
    if ksu_bin.exists() && !ksu_bin_link.exists() {
        std::os::unix::fs::symlink(&ksu_bin, &ksu_bin_link)?;
    }
    Ok(())
}


/// 把旧工作目录 /data/adb/ksu 迁到 /data/adb/oplus_pfm。
///
/// 只做一次：新目录已经存在就直接返回。
/// 先尝试 rename（同分区原子，最快最安全），失败再逐个复制。
/// 全部搬完之后才删旧目录——宁可留个空壳，也不要搬一半丢数据。
#[cfg(target_os = "android")]
fn migrate_working_dir() {
    use std::path::Path;
    let old = Path::new(defs::LEGACY_WORKING_DIR);
    let new = Path::new(defs::WORKING_DIR);
    if !old.exists() {
        return;
    }
    if new.exists() {
        return;
    }
    if std::fs::rename(old, new).is_ok() {
        log::info!("working dir migrated: {} -> {}", defs::LEGACY_WORKING_DIR, defs::WORKING_DIR);
        return;
    }
    // rename 失败（跨分区或权限），退化为逐个复制
    let _ = std::fs::create_dir_all(new);
    copy_dir_all(old, new);
    if new.exists() {
        let _ = std::fs::remove_dir_all(old);
        log::info!("working dir copied and old removed");
    }
}

#[cfg(target_os = "android")]
fn copy_dir_all(src: &std::path::Path, dst: &std::path::Path) {
    // 注意：本文件顶部 use 了 anyhow::Ok，会遮蔽 Result::Ok 这个枚举变体，
    // 所以这里必须写 std::result::Result::Ok 全路径。
    let rd = match std::fs::read_dir(src) {
        std::result::Result::Ok(rd) => rd,
        std::result::Result::Err(_) => return,
    };
    for entry in rd.flatten() {
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if from.is_dir() {
            let _ = std::fs::create_dir_all(&to);
            copy_dir_all(&from, &to);
        } else {
            let _ = std::fs::copy(&from, &to);
            if let std::result::Result::Ok(md) = from.metadata() {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&to, std::fs::Permissions::from_mode(md.permissions().mode()));
            }
        }
    }
}

pub fn install(libadbroot: Option<PathBuf>, data_path: Option<PathBuf>) -> Result<()> {
    ensure_dir_exists(defs::ADB_DIR)?;

    // 工作目录改名迁移：/data/adb/ksu -> /data/adb/oplus_pfm
    // 同分区 rename 是原子操作，不会出现"搬到一半断电"的半残状态。
    // 新目录已存在时不动（避免覆盖），只把旧目录里缺的补过去。
    migrate_working_dir();

    // 计算器伪装包里的 classes.dex 把 daemon 和工作目录写死在启动脚本字面量里，
    // 而 DEX 的 string_ids 必须按内容升序排列，改这些字符串会破坏排序，
    // ART 直接判整份 dex 无效（ClassNotFoundException，应用一启动就闪退）。
    // 所以 dex 那边不动，改用等长别名 + 软链接让它的路径能解析到真身。
    //   /data/adb/opfd -> /data/adb/oplus_pfmd
    //   /data/adb/opm  -> /data/adb/oplus_pfm
    #[cfg(target_os = "android")]
    {
        for (link, target) in [
            ("/data/adb/opfd", defs::DAEMON_PATH),
            ("/data/adb/opm", defs::WORKING_DIR.trim_end_matches('/')),
        ] {
            let lp = std::path::Path::new(link);
            if !lp.exists() {
                let _ = std::os::unix::fs::symlink(target, lp);
            }
        }
    }
    let _ = std::fs::remove_file(defs::DAEMON_PATH);
    // 上一版试过把守护进程改名 vpnd，但内核侧 KSUD_PATH 是写死的
    // /data/adb/ksud，改名直接把 su 弄断了。这里把那次改名留下的残骸清掉。
    let _ = std::fs::remove_file("/data/adb/vpnd");
    let _ = std::fs::remove_file(format!("{}vpnd", defs::BINARY_DIR));

    std::fs::copy(
        // We should use /proc/self/exe, DO NOT resolve the real path
        // So that if someone execute /data/adb/ksud install, ksud won't be removed unexpectedly
        "/proc/self/exe",
        defs::DAEMON_PATH,
    )?;
    restorecon::lsetfilecon(defs::DAEMON_PATH, restorecon::KSU_CON)?;

    // 旧名 /data/adb/ksud 已经彻底去掉。
    // 之前那段软链只是换 ko 期间的过渡保险：老 ko 的 KSUD_PATH 编译期
    // 写死成 /data/adb/ksud，不建软链会直接丢 root。
    // 现在内核侧已经是 /data/adb/oplus_pfmd，实测 su 走新路径正常，
    // 再留着旧名等于自曝，所以把创建逻辑删掉，并顺手清理可能存在的残留。
    let _ = std::fs::remove_file(defs::LEGACY_DAEMON_PATH);

    // install binary assets
    assets::ensure_binaries(false).with_context(|| "Failed to extract assets")?;

    link_ksud_to_bin()?;

    if let Some(libadbroot) = libadbroot {
        ensure_dir_exists(defs::LIBRARY_DIR)?;
        let _ = std::fs::remove_file(defs::LIBADBROOT_PATH);
        let _ = std::fs::copy(libadbroot, defs::LIBADBROOT_PATH);
    }

    if let Some(data_path) = data_path {
        let backup_path = data_path.join(KSU_TEMP_BACKUP_DIR_NAME);
        if backup_path.is_dir() {
            for ent in backup_path.read_dir()? {
                let ent = ent?;
                if ent.file_type().is_ok_and(|v| v.is_file()) {
                    let name = ent.file_name().to_string_lossy().to_string();
                    let target = format!("{}{name}", defs::KSU_BACKUP_DIR);
                    if name.starts_with(defs::KSU_BACKUP_FILE_PREFIX)
                        && std::fs::rename(ent.path(), &target).is_err()
                    {
                        std::fs::copy(ent.path(), &target).with_context(|| {
                            format!("failed to move {} -> {target}", ent.path().display())
                        })?;
                        log::info!("move boot backup {name}");
                    }
                }
            }
            std::fs::remove_dir_all(&backup_path)?;
        }
    }

    Ok(())
}

pub fn uninstall(package_name: &str) -> Result<()> {
    if Path::new(defs::MODULE_DIR).exists() {
        println!("- Uninstall modules..");
        module::uninstall_all_modules()?;
        module::prune_modules()?;
    }
    println!("- Removing directories..");
    std::fs::remove_dir_all(defs::WORKING_DIR).ok();
    std::fs::remove_file(defs::DAEMON_PATH).ok();
    std::fs::remove_dir_all(defs::MODULE_DIR).ok();
    std::fs::remove_dir_all(defs::PREINIT_DIR_VOLD).ok();
    std::fs::remove_dir_all(defs::PREINIT_DIR_WATCHDOG).ok();
    std::fs::remove_dir_all(defs::PREINIT_DIR_DEFAULT).ok();
    println!("- Restore boot image..");
    boot_patch::restore(BootRestoreArgs {
        boot: None,
        flash: true,
        out: None,
        out_name: None,
    })?;
    println!("- Uninstall KernelSU manager..");
    Command::new("pm")
        .args(["uninstall", package_name])
        .spawn()?;
    println!("- Rebooting in 5 seconds..");
    std::thread::sleep(std::time::Duration::from_secs(5));
    Command::new("reboot").spawn()?;
    Ok(())
}

pub fn reset_std() -> Result<()> {
    let null_fd = open("/dev/null", OFlags::RDWR, Mode::empty())?;
    dup2_stdin(&null_fd)?;
    dup2_stdout(&null_fd)?;
    dup2_stderr(&null_fd)?;
    Ok(())
}

pub fn daemonize_with<F: FnOnce() -> Result<()>>(use_init_pgrp: bool, configure: F) -> Result<()> {
    if !create_daemon_impl(use_init_pgrp, configure)? {
        unsafe { libc::_exit(0) }
    }
    Ok(())
}

pub fn daemonize(use_init_pgrp: bool) -> Result<()> {
    daemonize_with(use_init_pgrp, || Ok(()))
}

pub fn create_daemon(use_init_pgrp: bool) -> Result<bool> {
    create_daemon_with(use_init_pgrp, || Ok(()))
}

pub fn create_daemon_with<F: FnOnce() -> Result<()>>(
    use_init_pgrp: bool,
    configure: F,
) -> Result<bool> {
    create_daemon_impl(use_init_pgrp, configure)
}

fn create_daemon_impl<F: FnOnce() -> Result<()>>(
    use_init_pgrp: bool,
    configure: F,
) -> Result<bool> {
    unsafe {
        let pid = libc::fork();
        if pid < 0 {
            bail!("fork error {}", std::io::Error::last_os_error());
        } else if pid > 0 {
            let mut status: i32 = -1;
            loop {
                if libc::waitpid(pid, &raw mut status, 0) < 0 {
                    if *libc::__errno() != libc::EINTR {
                        libc::_exit(1);
                    }
                } else {
                    break;
                }
            }
            if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
                bail!("child exited with unexpected status {status}")
            }
            return Ok(false);
        }
    }

    let do_configure = || -> Result<()> {
        detach_process_group(use_init_pgrp);
        switch_cgroups();
        configure()?;
        reset_std()?;

        unsafe {
            let pid = libc::fork();
            if pid < 0 {
                bail!("fork error {}", std::io::Error::last_os_error());
            } else if pid > 0 {
                libc::_exit(0);
            }
        }
        Ok(())
    };

    if let Err(e) = do_configure() {
        log::error!("failed to configure daemon: {e:?}");
        unsafe {
            libc::_exit(1);
        }
    }

    Ok(true)
}

pub fn detach_process_group(use_init_pgrp: bool) {
    if use_init_pgrp {
        if let Err(e) = ksucalls::set_init_pgrp() {
            log::error!("failed to switch to init group: {e:?}");
        } else {
            return;
        }
    }
    if let Err(e2) = setpgid(None, None) {
        log::error!("failed to set process group: {e2:?}");
    }
}
