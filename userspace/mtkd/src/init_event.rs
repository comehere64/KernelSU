use crate::module::{ScriptWait, handle_updated_modules, prune_modules};
use crate::utils::is_safe_mode;
use crate::{
    assets, defs, ksucalls, metamodule, restorecon,
    utils::{self},
};
use anyhow::{Context, Result};
use log::{error, info, warn};
use std::{path::Path, time::Instant};

pub fn on_post_fs_data() -> Result<()> {
    if let Err(e) = ksucalls::ensure_uapi_version_matched() {
        error!("{e:#}, skip on_post_fs_data");
        return Ok(());
    }

    ksucalls::report_post_fs_data();

    utils::umask(0);

    // Clear all temporary module configs early
    if let Err(e) = crate::module_config::clear_all_temp_configs() {
        warn!("clear temp configs failed: {e}");
    }

    let _ = catch_bootlog("logcat", &["logcat", "-b", "all"]);
    let _ = catch_bootlog("dmesg", &["dmesg", "-w", "-r"]);

    if utils::has_magisk() {
        warn!("Magisk detected, skip post-fs-data!");
        return Ok(());
    }

    let safe_mode = crate::utils::is_safe_mode();
    let wait = ScriptWait::Until(Instant::now() + defs::BOOT_STAGE_TIMEOUT);

    if safe_mode {
        // we should still ensure module directory exists in safe mode
        // because we may need to operate the module dir in safe mode
        warn!("safe mode, skip common post-fs-data.d scripts");
    } else {
        // Then exec common post-fs-data scripts
        if let Err(e) = crate::module::exec_common_scripts("post-fs-data.d", wait) {
            warn!("exec common post-fs-data scripts failed: {e}");
        }
    }

    let module_dir = defs::MODULE_DIR;

    assets::ensure_binaries(true).with_context(|| "Failed to extract bin assets")?;

    crate::hot_install::clean_trash();

    // if we are in safe mode, we should disable all modules
    if safe_mode {
        warn!("safe mode, skip post-fs-data scripts and disable all modules!");
        if let Err(e) = crate::module::disable_all_modules() {
            warn!("disable all modules failed: {e}");
        }
        return Ok(());
    }

    if let Err(e) = handle_updated_modules() {
        warn!("handle updated modules failed: {e}");
    }

    if let Err(e) = prune_modules() {
        warn!("prune modules failed: {e}");
    }

    // Refresh /metadata/watchdog/ksu/{modules.rc,preinit/} so the next boot's kernel hook sees the
    // current module set. Acts as a safety net when state was changed outside
    // of ksud's normal mutation commands.
    if let Err(e) = crate::module::regenerate_preinit() {
        warn!("regenerate preinit failed: {e:#}");
    }

    if let Err(e) = restorecon::restorecon() {
        warn!("restorecon failed: {e}");
    }

    // load sepolicy.rule
    if crate::module::load_sepolicy_rule().is_err() {
        warn!("load sepolicy.rule failed");
    }

    if let Err(e) = crate::profile::apply_sepolies() {
        warn!("apply root profile sepolicy failed: {e}");
    }

    crate::feature::init_forced_features();

    // load feature config
    if is_safe_mode() {
        warn!("safe mode, skip load feature config");
    } else if let Err(e) = crate::feature::init_features() {
        warn!("init features failed: {e}");
    }

    // execute metamodule post-fs-data script first (priority)
    if let Err(e) = metamodule::exec_stage_script("post-fs-data", wait) {
        warn!("exec metamodule post-fs-data script failed: {e}");
    }

    // exec modules post-fs-data scripts
    if let Err(e) = crate::module::exec_stage_script("post-fs-data", wait) {
        warn!("exec post-fs-data scripts failed: {e}");
    }

    // load system.prop
    if let Err(e) = crate::module::load_system_prop() {
        warn!("load system.prop failed: {e}");
    }

    // execute metamodule mount script
    if let Err(e) = metamodule::exec_mount_script(module_dir) {
        warn!("execute metamodule mount failed: {e}");
    }

    run_stage("post-mount", wait);

    std::env::set_current_dir("/").with_context(|| "failed to chdir to /")?;

    Ok(())
}

pub fn run_stage(stage: &str, wait: ScriptWait) {
    utils::umask(0);

    if utils::has_magisk() {
        warn!("Magisk detected, skip {stage}");
        return;
    }

    if crate::utils::is_safe_mode() {
        warn!("safe mode, skip {stage} scripts");
        return;
    }

    if let Err(e) = crate::module::exec_common_scripts(&format!("{stage}.d"), wait) {
        warn!("Failed to exec common {stage} scripts: {e}");
    }

    // execute metamodule stage script first (priority)
    if let Err(e) = metamodule::exec_stage_script(stage, wait) {
        warn!("Failed to exec metamodule {stage} script: {e}");
    }

    // execute regular modules stage scripts
    if let Err(e) = crate::module::exec_stage_script(stage, wait) {
        warn!("Failed to exec {stage} scripts: {e}");
    }
}

pub fn on_services() {
    if let Err(e) = ksucalls::ensure_uapi_version_matched() {
        error!("{e:#}, skip on_services");
        return;
    }

    match ksucalls::report_services() {
        Ok(true) => {}
        Ok(false) => {
            info!("services already started, skipping");
            return;
        }
        Err(e) => {
            error!("Failed to report services: {e:#}");
            return;
        }
    }

    info!("on_services triggered!");
    run_stage("service", ScriptWait::NoWait);
}

pub fn on_boot_completed() {
    if let Err(e) = ksucalls::ensure_uapi_version_matched() {
        error!("{e:#}, skip on_boot_completed");
        return;
    }

    ksucalls::report_boot_complete();
    info!("on_boot_completed triggered!");

    crate::preinit::on_boot_completed();

    run_stage("boot-completed", ScriptWait::NoWait);

    tighten_zygisksu_perms();
}

/// ZygiskNext 用 umask 0000 建文件，落地就是 0666，任何 App 都能改它的配置。
/// 这里收到 0600；modules_info 是 0 字节说明模块没登记上，记一笔备查。
fn tighten_zygisksu_perms() {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::path::Path::new("/data/adb/zygisksu");
    let std::result::Result::Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_file() {
            let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
        }
    }
    if let Ok(m) = std::fs::metadata(dir.join("modules_info")) {
        if m.len() == 0 {
            warn!("zygisksu modules_info is empty; zygisk modules may not be registered");
        }
    }
}

fn catch_bootlog(logname: &str, command: &[&str]) -> Result<()> {
    use std::os::unix::process::CommandExt;
    use std::process::Stdio;

    let logdir = Path::new(defs::LOG_DIR);
    utils::ensure_dir_exists(logdir)?;
    // 启动日志里有 dmesg / logcat 原文，权限必须收紧：
    // 原来这里只 ensure_dir_exists（不设 mode），目录按 umask 落地成 0777，
    // 任何 App 都能列目录、读日志、甚至往里写。这里显式压到 0700。
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(logdir, std::fs::Permissions::from_mode(0o700));
    }
    let bootlog = logdir.join(format!("{logname}.log"));
    let oldbootlog = logdir.join(format!("{logname}.old.log"));

    // logcat -b all / dmesg -w 是把整段系统日志落盘，单次就能写到 20M 以上。
    // 只留一份 .old.log 挡不住总量，实测攒到过 52M。
    // 先看体积：超上限就把新旧一起删掉重新开始，而不是再轮转一份。
    if bootlog.exists() {
        let too_big = std::fs::metadata(&bootlog)
            .map(|m| m.len() > defs::BOOTLOG_MAX_BYTES)
            .unwrap_or(false);
        if too_big {
            let _ = std::fs::remove_file(&bootlog);
            let _ = std::fs::remove_file(&oldbootlog);
        } else {
            std::fs::rename(&bootlog, oldbootlog)?;
        }
    }

    let bootlog = std::fs::File::create(bootlog)?;
    {
        use std::os::unix::fs::PermissionsExt;
        // 日志文件同样只给 root 读写。
        let _ = bootlog.set_permissions(std::fs::Permissions::from_mode(0o600));
    }

    // timeout -s 9 30s logcat -b all | head -c <cap>
    //
    // 只靠下次开机的预检不够：logcat -b all 是把整段系统日志落盘，单次就能写到
    // 20M 以上，等下次开机再删，日志早就把 /data 撑爆了。必须边写边截断：
    // head 写满 cap 就退出，logcat 收到 SIGPIPE 跟着结束。
    let cap = defs::BOOTLOG_MAX_BYTES.to_string();
    let inner = command.join(" ");
    let shell_cmd = format!(
        "exec timeout -s 9 {} {} | head -c {}",
        defs::BOOTLOG_TIMEOUT, inner, cap
    );
    let result = unsafe {
        std::process::Command::new("sh")
            .process_group(0)
            .pre_exec(|| {
                utils::switch_cgroups();
                Ok(())
            })
            .arg("-c")
            .arg(shell_cmd)
            .stdout(Stdio::from(bootlog))
            .spawn()
    };

    if let Err(e) = result {
        warn!("Failed to start logcat: {e:#}");
    }

    Ok(())
}
