//! 网页端文件管理器的「属性」与「分享」。
//!
//! 目标是把 MT 管理器那套属性页/分享页搬进浏览器：
//!   · 属性：名称、路径、类型、MIME、大小、占用、权限（含 suid/sgid/sticky）、
//!     属主/属组（uid/gid + 名字）、三个时间戳、inode/硬链接、SELinux 上下文；
//!     APK 额外给包名/版本/API/签名方案与证书指纹；图片给分辨率；
//!     另外 MD5 / SHA1 / SHA256 按需计算。
//!   · 分享：下载链接、复制路径、系统分享（am start SEND）、打包成 zip。

// 属性/分享只在 Android 上有意义；桌面目标仍会编译这个模块（webui 那一串都是
// 无条件编译的），那里的辅助函数自然没人调用，别让 dead_code 刷屏。
#![cfg_attr(not(target_os = "android"), allow(dead_code))]

use anyhow::{Context, Result, bail};
use serde::Serialize;

// 属性页是纯展示用的数据载体，字段多、bool 多是它的本质，不是设计问题。
#[allow(clippy::struct_excessive_bools)]
#[derive(Serialize, Default, Clone)]
pub struct Props {
    pub name: String,
    pub path: String,
    /// 人类可读的类型，例如「文件夹」「APK 安装包」「文本文件」
    pub kind: String,
    pub mime: String,
    pub size: u64,
    pub size_text: String,
    pub disk_usage: u64,
    pub disk_usage_text: String,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub symlink_target: Option<String>,
    pub mode: u32,
    pub mode_text: String,
    pub suid: bool,
    pub sgid: bool,
    pub sticky: bool,
    pub uid: u32,
    pub gid: u32,
    pub user_name: String,
    pub group_name: String,
    pub nlink: u64,
    pub inode: u64,
    pub mtime: i64,
    pub atime: i64,
    pub ctime: i64,
    pub selinux: String,
    pub apk: Option<ApkProps>,
    pub image: Option<ImageProps>,
}

#[derive(Serialize, Default, Clone)]
pub struct ApkProps {
    pub package: String,
    pub label: String,
    pub version_name: String,
    pub version_code: u32,
    pub min_sdk: u32,
    pub target_sdk: u32,
    /// 签名方案，如 "v2 / v3"
    pub schemes: String,
    /// 签名证书的 MD5 / SHA-1 / SHA-256（十六进制）
    pub cert_md5: String,
    pub cert_sha1: String,
    pub cert_sha256: String,
    pub signed: bool,
}

#[derive(Serialize, Default, Clone)]
pub struct ImageProps {
    pub width: u32,
    pub height: u32,
    pub format: String,
}

pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.2} {}", UNITS[unit])
    }
}

#[cfg(unix)]
fn user_name(uid: u32) -> String {
    // 先试试 getpwuid_r；Android 上多数 uid 没有 passwd 条目，退回数字。
    use std::os::raw::c_char;
    unsafe {
        let mut buf = [0 as c_char; 1024];
        let mut pwd: libc::passwd = std::mem::zeroed();
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        let rc = libc::getpwuid_r(
            uid,
            std::ptr::from_mut(&mut pwd),
            buf.as_mut_ptr(),
            buf.len(),
            std::ptr::from_mut(&mut result),
        );
        if rc == 0
            && !result.is_null()
            && !pwd.pw_name.is_null()
            && let Ok(name) = std::ffi::CStr::from_ptr(pwd.pw_name).to_str()
            && !name.is_empty()
        {
            return name.to_string();
        }
    }
    uid.to_string()
}

#[cfg(unix)]
fn group_name(gid: u32) -> String {
    use std::os::raw::c_char;
    unsafe {
        let mut buf = [0 as c_char; 1024];
        let mut grp: libc::group = std::mem::zeroed();
        let mut result: *mut libc::group = std::ptr::null_mut();
        let rc = libc::getgrgid_r(
            gid,
            std::ptr::from_mut(&mut grp),
            buf.as_mut_ptr(),
            buf.len(),
            std::ptr::from_mut(&mut result),
        );
        if rc == 0
            && !result.is_null()
            && !grp.gr_name.is_null()
            && let Ok(name) = std::ffi::CStr::from_ptr(grp.gr_name).to_str()
            && !name.is_empty()
        {
            return name.to_string();
        }
    }
    gid.to_string()
}

#[cfg(not(unix))]
fn user_name(uid: u32) -> String {
    uid.to_string()
}

#[cfg(not(unix))]
fn group_name(gid: u32) -> String {
    gid.to_string()
}

/// 读 security.selinux 扩展属性。读不到就返回空串（非 SELinux 环境）。
///
/// 只给 Linux/Android 编：macOS 的 getxattr 是 6 个参数（多 position/options），
/// 而且那边本来也没有 SELinux 上下文可读。
#[cfg(any(target_os = "android", target_os = "linux"))]
fn selinux_context(path: &std::path::Path) -> String {
    use std::os::unix::ffi::OsStrExt;
    let Ok(cpath) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return String::new();
    };
    let name = std::ffi::CString::new("security.selinux").unwrap();
    let mut buf = vec![0u8; 256];
    let n = unsafe {
        libc::getxattr(
            cpath.as_ptr(),
            name.as_ptr(),
            buf.as_mut_ptr().cast::<std::os::raw::c_void>(),
            buf.len(),
        )
    };
    if n <= 0 {
        return String::new();
    }
    let raw = &buf[..n as usize];
    // 内核给的是带结尾 NUL 的字符串
    let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..end]).into_owned()
}

#[cfg(not(any(target_os = "android", target_os = "linux")))]
fn selinux_context(_path: &std::path::Path) -> String {
    String::new()
}

fn kind_of(path: &std::path::Path, is_dir: bool, mime: &str) -> String {
    if is_dir {
        return "文件夹".to_string();
    }
    let ext = path
        .extension()
        .map_or_else(String::new, |e| e.to_string_lossy().to_lowercase());
    let named = match ext.as_str() {
        "apk" | "apks" | "xapk" | "apkm" => "APK 安装包",
        "zip" | "jar" | "7z" | "rar" | "tar" | "gz" | "xz" | "bz2" | "zst" => "压缩包",
        "so" => "动态库",
        "ko" => "内核模块",
        "sh" | "bash" => "Shell 脚本",
        "py" => "Python 脚本",
        "json" => "JSON 文件",
        "xml" => "XML 文件",
        "toml" => "TOML 文件",
        "txt" | "md" | "log" | "conf" | "ini" | "prop" | "cfg" => "文本文件",
        "jpg" | "jpeg" | "png" | "webp" | "gif" | "bmp" | "heic" | "avif" => "图片",
        "mp4" | "mkv" | "mov" | "avi" | "webm" => "视频",
        "mp3" | "flac" | "wav" | "ogg" | "m4a" | "aac" => "音频",
        "ttf" | "otf" | "woff" | "woff2" => "字体",
        "dex" | "odex" | "vdex" | "oat" | "art" => "DEX / 运行时文件",
        "img" => "镜像文件",
        _ => {
            if mime.starts_with("text/") {
                "文本文件"
            } else if mime.starts_with("image/") {
                "图片"
            } else if mime.starts_with("video/") {
                "视频"
            } else if mime.starts_with("audio/") {
                "音频"
            } else {
                "文件"
            }
        }
    };
    named.to_string()
}

// ---------- 图片尺寸 ----------

fn image_dims(path: &std::path::Path) -> Option<ImageProps> {
    use std::io::Read;

    let mut file = std::fs::File::open(path).ok()?;
    let mut head = [0u8; 64];
    let read = file.read(&mut head).ok()?;
    let buf = &head[..read];

    let dims = |width: u32, height: u32, format: &str| {
        Some(ImageProps {
            width,
            height,
            format: format.to_string(),
        })
    };

    if buf.len() >= 24 && buf.starts_with(&[0x89, b'P', b'N', b'G']) {
        let width = u32::from_be_bytes([buf[16], buf[17], buf[18], buf[19]]);
        let height = u32::from_be_bytes([buf[20], buf[21], buf[22], buf[23]]);
        return dims(width, height, "PNG");
    }
    if buf.len() >= 10 && (buf.starts_with(b"GIF87a") || buf.starts_with(b"GIF89a")) {
        let width = u32::from(u16::from_le_bytes([buf[6], buf[7]]));
        let height = u32::from(u16::from_le_bytes([buf[8], buf[9]]));
        return dims(width, height, "GIF");
    }
    if buf.len() >= 26 && buf.starts_with(b"BM") {
        let width = i32::from_le_bytes([buf[18], buf[19], buf[20], buf[21]]).unsigned_abs();
        let height = i32::from_le_bytes([buf[22], buf[23], buf[24], buf[25]]).unsigned_abs();
        return dims(width, height, "BMP");
    }
    if buf.len() >= 30 && buf.starts_with(b"RIFF") && &buf[8..12] == b"WEBP" {
        match &buf[12..16] {
            b"VP8X" => {
                let width = 1 + u32::from_le_bytes([buf[24], buf[25], buf[26], 0]);
                let height = 1 + u32::from_le_bytes([buf[27], buf[28], buf[29], 0]);
                return dims(width, height, "WebP");
            }
            b"VP8 " => {
                let width = u32::from(u16::from_le_bytes([buf[26], buf[27]]) & 0x3fff);
                let height = u32::from(u16::from_le_bytes([buf[28], buf[29]]) & 0x3fff);
                return dims(width, height, "WebP");
            }
            b"VP8L" => {
                let quad = &buf[21..25];
                let bits = u32::from_le_bytes([quad[0], quad[1], quad[2], quad[3]]);
                let width = (bits & 0x3fff) + 1;
                let height = ((bits >> 14) & 0x3fff) + 1;
                return dims(width, height, "WebP");
            }
            _ => {}
        }
    }
    if buf.len() >= 4 && buf[0] == 0xFF && buf[1] == 0xD8 {
        let mut data = Vec::new();
        file.rewind_ok();
        let _ = file.read_to_end(&mut data);
        let mut i = 2usize;
        while i + 9 < data.len() {
            if data[i] != 0xFF {
                i += 1;
                continue;
            }
            let marker = data[i + 1];
            if matches!(marker, 0xC0..=0xC3 | 0xC5..=0xC7 | 0xC9..=0xCB | 0xCD..=0xCF) {
                let height = u32::from(u16::from_be_bytes([data[i + 5], data[i + 6]]));
                let width = u32::from(u16::from_be_bytes([data[i + 7], data[i + 8]]));
                return dims(width, height, "JPEG");
            }
            let len = u16::from_be_bytes([data[i + 2], data[i + 3]]) as usize;
            if len < 2 {
                break;
            }
            i += 2 + len;
        }
    }
    None
}

trait Rewind {
    fn rewind_ok(&mut self);
}
impl Rewind for std::fs::File {
    fn rewind_ok(&mut self) {
        use std::io::Seek;
        let _ = self.seek(std::io::SeekFrom::Start(0));
    }
}

// ---------- APK ----------

/// 从 APK 里取 v2 签名方案携带的签名证书（DER）。
fn v2_signing_cert(data: &[u8]) -> Option<Vec<u8>> {
    const MAGIC: &[u8] = b"APK Sig Block 42";
    let magic_at = data.len().checked_sub(MAGIC.len())?;
    if &data[magic_at..] != MAGIC {
        return None;
    }
    // 签名块尾部：uint64 size | 各种 pair | uint64 size | magic
    let footer = magic_at.checked_sub(8)?;
    let block_size = u64::from_le_bytes(data[footer..footer + 8].try_into().ok()?) as usize;
    let block_start = footer.checked_sub(block_size)?;

    let mut pos = block_start + 8;
    while pos + 12 <= footer {
        let pair_len = u64::from_le_bytes(data[pos..pos + 8].try_into().ok()?) as usize;
        if pair_len < 4 || pos + 8 + pair_len > footer {
            break;
        }
        let id = u32::from_le_bytes(data[pos + 8..pos + 12].try_into().ok()?);
        let value = &data[pos + 12..pos + 8 + pair_len];
        if id == 0x7109_871a {
            // v2 block: sequence of signers
            let mut p = 0usize;
            let signers_len = le_u32(value, &mut p)? as usize;
            let _ = signers_len;
            // signer: signed data | signatures | public key
            let signed_len = le_u32(value, &mut p)? as usize;
            let signed = &value[p..p.checked_add(signed_len)?];
            let mut q = 0usize;
            let digests_len = le_u32(signed, &mut q)? as usize;
            q += digests_len;
            let certs_len = le_u32(signed, &mut q)? as usize;
            let certs = &signed[q..q.checked_add(certs_len)?];
            let mut r = 0usize;
            let first_len = le_u32(certs, &mut r)? as usize;
            return certs.get(r..r + first_len).map(<[u8]>::to_vec);
        }
        pos += 8 + pair_len;
    }
    None
}

fn le_u32(data: &[u8], pos: &mut usize) -> Option<u32> {
    let end = pos.checked_add(4)?;
    let slice = data.get(*pos..end)?;
    *pos = end;
    Some(u32::from_le_bytes(slice.try_into().ok()?))
}

// 读不到就是 None —— 调用方据此决定不显示 APK 那一段。
#[allow(clippy::unnecessary_wraps)]
fn apk_props(path: &std::path::Path) -> Option<ApkProps> {
    use std::io::Read;

    let mut props = ApkProps::default();
    if let Ok(f) = std::fs::File::open(path)
        && let Some(facts) = crate::apkparser::extract_manifest_facts(f)
    {
        props.package = facts.package.unwrap_or_default();
        props.version_name = facts.version_name.unwrap_or_default();
        props.version_code = facts.version_code.unwrap_or(0);
        props.min_sdk = facts.min_sdk.unwrap_or(0);
        props.target_sdk = facts.target_sdk.unwrap_or(0);
        props.label = facts.label.unwrap_or_default();
    }

    // 签名方案与证书指纹
    let mut data = Vec::new();
    if let Ok(mut f) = std::fs::File::open(path) {
        let _ = f.read_to_end(&mut data);
    }

    // v1（JAR 签名）以 META-INF/<name>.RSA/.DSA/.EC 是否存在为准。
    let has_v1 = std::fs::File::open(path)
        .ok()
        .and_then(|f| zip::ZipArchive::new(f).ok())
        .is_some_and(|archive| {
            archive.file_names().any(|name| {
                let in_meta_inf = name
                    .get(..9)
                    .is_some_and(|head| head.eq_ignore_ascii_case("meta-inf/"));
                let is_signature = std::path::Path::new(name)
                    .extension()
                    .and_then(std::ffi::OsStr::to_str)
                    .is_some_and(|ext| {
                        ext.eq_ignore_ascii_case("rsa")
                            || ext.eq_ignore_ascii_case("dsa")
                            || ext.eq_ignore_ascii_case("ec")
                    });
                in_meta_inf && is_signature
            })
        });
    let cert = v2_signing_cert(&data);
    let mut schemes = Vec::new();
    if has_v1 {
        schemes.push("v1");
    }
    if cert.is_some() {
        schemes.push("v2");
    }
    if let Some(c) = cert.as_deref() {
        props.signed = true;
        props.cert_md5 = hex(&md5::digest(c));
        {
            use sha1::Digest;
            props.cert_sha1 = hex(&sha1::Sha1::digest(c));
        }
        props.cert_sha256 = hex(&sha256::digest(c).into_bytes());
    }
    // v3/v3.1 的存在性只需看签名块里的 pair id
    if data.ends_with(b"APK Sig Block 42") && data.len() > 24 {
        let l = data.len();
        if let Ok(sz) = data[l - 24..l - 16].try_into() {
            let block_size = u64::from_le_bytes(sz) as usize;
            if l > block_size + 8 {
                let start = l - 8 - block_size;
                if start > 8 {
                    let mut pos = start + 8;
                    while pos + 12 <= l - 24 {
                        let Ok(pl) = data[pos..pos + 8].try_into() else {
                            break;
                        };
                        let pair_len = u64::from_le_bytes(pl) as usize;
                        if pair_len < 4 || pos + 8 + pair_len > l - 24 {
                            break;
                        }
                        let Ok(idb) = data[pos + 8..pos + 12].try_into() else {
                            break;
                        };
                        let id = u32::from_le_bytes(idb);
                        if id == 0xf053_68ba {
                            schemes.push("v3");
                        } else if id == 0x1b93_ad61 {
                            schemes.push("v31");
                        }
                        pos += 8 + pair_len;
                    }
                }
            }
        }
    }
    props.schemes = schemes.join(" / ");
    if props.schemes == "v1" {
        props.signed = true;
    }
    Some(props)
}

/// 十六进制小写
pub fn hex(bytes: &[u8]) -> String {
    const T: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(T[(b >> 4) as usize] as char);
        s.push(T[(b & 0x0f) as usize] as char);
    }
    s
}

// ---------- 属性入口 ----------

#[cfg(target_os = "android")]
pub fn props(path: &str, mime: &str) -> Result<Props> {
    use std::os::unix::fs::MetadataExt;

    let target = std::path::Path::new(path);
    let link_md =
        std::fs::symlink_metadata(target).with_context(|| format!("读取 {path} 的属性失败"))?;
    let is_symlink = link_md.file_type().is_symlink();
    let md = std::fs::metadata(target).unwrap_or_else(|_| link_md.clone());
    let symlink_target = is_symlink
        .then(|| {
            std::fs::read_link(target)
                .ok()
                .map(|p| p.display().to_string())
        })
        .flatten();

    let mode = md.mode();
    let mut p = Props {
        name: target
            .file_name()
            .map_or_else(|| path.to_string(), |n| n.to_string_lossy().into_owned()),
        path: path.to_string(),
        kind: kind_of(target, md.is_dir(), mime),
        mime: mime.to_string(),
        size: md.len(),
        size_text: human_size(md.len()),
        disk_usage: md.blocks() * 512,
        disk_usage_text: human_size(md.blocks() * 512),
        is_dir: md.is_dir(),
        is_symlink,
        symlink_target,
        mode,
        mode_text: mode_text_custom(mode, md.is_dir()),
        suid: mode & 0o4000 != 0,
        sgid: mode & 0o2000 != 0,
        sticky: mode & 0o1000 != 0,
        uid: md.uid(),
        gid: md.gid(),
        user_name: user_name(md.uid()),
        group_name: group_name(md.gid()),
        nlink: md.nlink(),
        inode: md.ino(),
        mtime: md.mtime(),
        atime: md.atime(),
        ctime: md.ctime(),
        selinux: selinux_context(target),
        apk: None,
        image: None,
    };

    if !p.is_dir {
        let ext = target
            .extension()
            .map_or_else(String::new, |e| e.to_string_lossy().to_lowercase());
        if matches!(ext.as_str(), "apk" | "apks") {
            p.apk = apk_props(target);
        }
        if p.mime.starts_with("image/")
            || matches!(
                ext.as_str(),
                "png" | "jpg" | "jpeg" | "webp" | "gif" | "bmp"
            )
        {
            p.image = image_dims(target);
        }
    }
    Ok(p)
}

#[cfg(not(target_os = "android"))]
pub fn props(_path: &str, _mime: &str) -> Result<Props> {
    bail!("当前平台不支持查看属性")
}

#[cfg(unix)]
fn mode_text_custom(mode: u32, is_dir: bool) -> String {
    let mut out = String::with_capacity(10);
    out.push(if is_dir { 'd' } else { '-' });
    for (bit, ch) in [
        (0o400, 'r'),
        (0o200, 'w'),
        (0o100, 'x'),
        (0o040, 'r'),
        (0o020, 'w'),
        (0o010, 'x'),
        (0o004, 'r'),
        (0o002, 'w'),
        (0o001, 'x'),
    ] {
        out.push(if mode & bit != 0 { ch } else { '-' });
    }
    if mode & 0o4000 != 0 {
        out.replace_range(3..4, "s");
    }
    if mode & 0o2000 != 0 {
        out.replace_range(6..7, "s");
    }
    if mode & 0o1000 != 0 {
        out.replace_range(9..10, "t");
    }
    out
}

#[cfg(not(unix))]
fn mode_text_custom(_mode: u32, _is_dir: bool) -> String {
    String::new()
}

// ---------- 哈希 ----------

/// MD5（RFC 1321）。属性页要显示 MD5，而依赖里只有 sha1/sha256，
/// 为了不给构建链再加一个 crate，这里自带一份紧凑实现。
pub mod md5 {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    const K: [u32; 64] = [
        0xd76a_a478,
        0xe8c7_b756,
        0x2420_70db,
        0xc1bd_ceee,
        0xf57c_0faf,
        0x4787_c62a,
        0xa830_4613,
        0xfd46_9501,
        0x6980_98d8,
        0x8b44_f7af,
        0xffff_5bb1,
        0x895c_d7be,
        0x6b90_1122,
        0xfd98_7193,
        0xa679_438e,
        0x49b4_0821,
        0xf61e_2562,
        0xc040_b340,
        0x265e_5a51,
        0xe9b6_c7aa,
        0xd62f_105d,
        0x0244_1453,
        0xd8a1_e681,
        0xe7d3_fbc8,
        0x21e1_cde6,
        0xc337_07d6,
        0xf4d5_0d87,
        0x455a_14ed,
        0xa9e3_e905,
        0xfcef_a3f8,
        0x676f_02d9,
        0x8d2a_4c8a,
        0xfffa_3942,
        0x8771_f681,
        0x6d9d_6122,
        0xfde5_380c,
        0xa4be_ea44,
        0x4bde_cfa9,
        0xf6bb_4b60,
        0xbebf_bc70,
        0x289b_7ec6,
        0xeaa1_27fa,
        0xd4ef_3085,
        0x0488_1d05,
        0xd9d4_d039,
        0xe6db_99e5,
        0x1fa2_7cf8,
        0xc4ac_5665,
        0xf429_2244,
        0x432a_ff97,
        0xab94_23a7,
        0xfc93_a039,
        0x655b_59c3,
        0x8f0c_cc92,
        0xffef_f47d,
        0x8584_5dd1,
        0x6fa8_7e4f,
        0xfe2c_e6e0,
        0xa301_4314,
        0x4e08_11a1,
        0xf753_7e82,
        0xbd3a_f235,
        0x2ad7_d2bb,
        0xeb86_d391,
    ];

    pub fn digest(data: &[u8]) -> [u8; 16] {
        let mut state: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];
        let mut msg = data.to_vec();
        let bit_len = (data.len() as u64).wrapping_mul(8);
        msg.push(0x80);
        while msg.len() % 64 != 56 {
            msg.push(0);
        }
        msg.extend_from_slice(&bit_len.to_le_bytes());

        for chunk in msg.chunks(64) {
            let mut words = [0u32; 16];
            for (index, word) in words.iter_mut().enumerate() {
                *word = u32::from_le_bytes([
                    chunk[index * 4],
                    chunk[index * 4 + 1],
                    chunk[index * 4 + 2],
                    chunk[index * 4 + 3],
                ]);
            }
            let [mut reg_a, mut reg_b, mut reg_c, mut reg_d] = state;
            for step in 0..64 {
                let (mix, pick) = match step {
                    0..=15 => ((reg_b & reg_c) | (!reg_b & reg_d), step),
                    16..=31 => ((reg_d & reg_b) | (!reg_d & reg_c), (5 * step + 1) % 16),
                    32..=47 => (reg_b ^ reg_c ^ reg_d, (3 * step + 5) % 16),
                    _ => (reg_c ^ (reg_b | !reg_d), (7 * step) % 16),
                };
                let carried = reg_d;
                reg_d = reg_c;
                reg_c = reg_b;
                reg_b = reg_b.wrapping_add(
                    reg_a
                        .wrapping_add(mix)
                        .wrapping_add(K[step])
                        .wrapping_add(words[pick])
                        .rotate_left(S[step]),
                );
                reg_a = carried;
            }
            state[0] = state[0].wrapping_add(reg_a);
            state[1] = state[1].wrapping_add(reg_b);
            state[2] = state[2].wrapping_add(reg_c);
            state[3] = state[3].wrapping_add(reg_d);
        }

        let mut out = [0u8; 16];
        for (i, word) in state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        out
    }
}

#[cfg(target_os = "android")]
pub fn hash_file(path: &str, algo: &str) -> Result<String> {
    use std::io::Read;

    let mut file = std::fs::File::open(path).with_context(|| format!("打开 {path} 失败"))?;
    let mut buf = vec![0u8; 1 << 20];

    match algo.to_ascii_lowercase().as_str() {
        "md5" => {
            let mut acc = Vec::new();
            loop {
                let n = file.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                acc.extend_from_slice(&buf[..n]);
            }
            Ok(hex(&md5::digest(&acc)))
        }
        "sha1" => {
            use sha1::Digest;
            let mut hasher = sha1::Sha1::new();
            loop {
                let n = file.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
            }
            Ok(hex(&hasher.finalize()))
        }
        "sha256" => {
            let mut acc = Vec::new();
            loop {
                let n = file.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                acc.extend_from_slice(&buf[..n]);
            }
            Ok(hex(&sha256::digest(&acc).into_bytes()))
        }
        other => bail!("不支持的算法：{other}"),
    }
}

#[cfg(not(target_os = "android"))]
pub fn hash_file(_path: &str, _algo: &str) -> Result<String> {
    bail!("当前平台不支持计算哈希")
}

// ---------- 属主 / 用户组候选列表 ----------

#[derive(Serialize, Default, Clone)]
pub struct OwnerEntry {
    pub id: u32,
    pub name: String,
    /// 应用名（uid 对应到某个已安装应用时才有），MT 里显示在第二行
    pub label: String,
}

/// 读 passwd 风格的文本，返回 (id, name)。
#[cfg(target_os = "android")]
fn parse_passwd_file(path: &str) -> Vec<(u32, String)> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    text.lines()
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| {
            let mut parts = line.split(':');
            let name = parts.next()?.trim().to_string();
            parts.next()?; // 密码占位
            let id = parts.next()?.trim().parse::<u32>().ok()?;
            (!name.is_empty()).then_some((id, name))
        })
        .collect()
}

/// Android 的固定 AID。设备上不一定有 /system/etc/group，这些是 AOSP 里的常量，
/// MT 列表里那一串 media_rw / mtp / nfc … 就来自这里。
const KNOWN_GROUPS: &[(u32, &str)] = &[
    (0, "root"),
    (1000, "system"),
    (1001, "radio"),
    (1002, "bluetooth"),
    (1003, "graphics"),
    (1004, "input"),
    (1005, "audio"),
    (1006, "camera"),
    (1007, "log"),
    (1008, "compass"),
    (1009, "mount"),
    (1010, "wifi"),
    (1011, "adb"),
    (1012, "install"),
    (1013, "media"),
    (1014, "dhcp"),
    (1015, "sdcard_rw"),
    (1016, "vpn"),
    (1017, "keystore"),
    (1018, "usb"),
    (1019, "drm"),
    (1020, "mdnsr"),
    (1021, "gps"),
    (1022, "media_rw"),
    (1023, "media_rw"),
    (1024, "mtp"),
    (1025, "nfc"),
    (1026, "drmrpc"),
    (1028, "sdcard_r"),
    (1029, "clat"),
    (1030, "loop_radio"),
    (1031, "mediadrm"),
    (1032, "package_info"),
    (1033, "sdcard_pics"),
    (1034, "sdcard_av"),
    (1035, "sdcard_audio"),
    (1036, "sdcard_all"),
    (1037, "logd"),
    (1038, "shared_relro"),
    (1039, "bd_list"),
    (1040, "webview_zygote"),
    (1041, "media_audio"),
    (1042, "media_video"),
    (1043, "media_image"),
    (1044, "tombstoned"),
    (1045, "media_gid"),
    (1046, "external_storage"),
    (1047, "ext_data_rw"),
    (1048, "ext_obb_rw"),
    (1049, "traced_producer"),
    (1050, "traced_consumer"),
    (1051, "incidentd"),
    (1052, "default_system"),
    (1053, "media_codec"),
    (2000, "shell"),
    (2001, "cache"),
    (3001, "net_bt_admin"),
    (3002, "net_bt"),
    (3003, "inet"),
    (3004, "net_raw"),
    (3005, "net_admin"),
    (3009, "readproc"),
    (3010, "wakelock"),
    (3011, "uhid"),
];

#[cfg(target_os = "android")]
pub fn list_owners() -> Vec<OwnerEntry> {
    use std::collections::BTreeMap;

    // uid -> (name, label)
    let mut map: BTreeMap<u32, (String, String)> = BTreeMap::new();

    for path in [
        "/system/etc/passwd",
        "/vendor/etc/passwd",
        "/product/etc/passwd",
    ] {
        for (id, name) in parse_passwd_file(path) {
            map.insert(id, (name, String::new()));
        }
    }

    // 已安装应用：uid 在 10000 以上，MT 会在第二行显示应用名。
    for (uid, label) in crate::webui::apps_snapshot() {
        let name = format!("u{}_{}", uid / 100_000, uid % 100_000);
        map.insert(uid, (name, label));
    }

    map.into_iter()
        .map(|(id, (name, label))| OwnerEntry { id, name, label })
        .collect()
}

#[cfg(not(target_os = "android"))]
pub fn list_owners() -> Vec<OwnerEntry> {
    Vec::new()
}

#[cfg(target_os = "android")]
pub fn list_groups() -> Vec<OwnerEntry> {
    use std::collections::BTreeMap;

    let mut map: BTreeMap<u32, (String, String)> = BTreeMap::new();
    for path in [
        "/system/etc/group",
        "/vendor/etc/group",
        "/product/etc/group",
    ] {
        for (id, name) in parse_passwd_file(path) {
            map.insert(id, (name, "系统".to_string()));
        }
    }
    for &(id, name) in KNOWN_GROUPS {
        map.entry(id)
            .or_insert_with(|| (name.to_string(), "系统".to_string()));
    }

    map.into_iter()
        .map(|(id, (name, label))| OwnerEntry { id, name, label })
        .collect()
}

#[cfg(not(target_os = "android"))]
pub fn list_groups() -> Vec<OwnerEntry> {
    Vec::new()
}

/// 改修改时间（`touch -d` 的等价物）。秒级。
#[cfg(unix)]
pub fn set_mtime(path: &str, mtime: i64) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let cpath = std::ffi::CString::new(std::path::Path::new(path).as_os_str().as_bytes())?;
    let times = [
        libc::timespec {
            tv_sec: mtime as libc::time_t,
            tv_nsec: 0,
        },
        libc::timespec {
            tv_sec: mtime as libc::time_t,
            tv_nsec: 0,
        },
    ];
    let rc = unsafe { libc::utimensat(libc::AT_FDCWD, cpath.as_ptr(), times.as_ptr(), 0) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("修改 {path} 的时间失败"));
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn set_mtime(_path: &str, _mtime: i64) -> Result<()> {
    bail!("当前平台不支持修改时间")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md5_matches_rfc1321_vectors() {
        assert_eq!(hex(&md5::digest(b"")), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(
            hex(&md5::digest(b"abc")),
            "900150983cd24fb0d6963f7d28e17f72"
        );
        assert_eq!(
            hex(&md5::digest(b"The quick brown fox jumps over the lazy dog")),
            "9e107d9d372bb6826bd81d3542a419d6"
        );
        // 跨块边界：56 字节正好触发补位
        assert_eq!(
            hex(&md5::digest(&[b'a'; 56])),
            "3b0c8ac703f828b04c6c197006d17218"
        );
    }

    #[test]
    fn human_size_reads_naturally() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(999), "999 B");
        assert_eq!(human_size(1024), "1.00 KB");
        assert_eq!(human_size(1536), "1.50 KB");
        assert_eq!(human_size(1024 * 1024), "1.00 MB");
    }

    #[test]
    fn mode_text_marks_special_bits() {
        assert_eq!(mode_text_custom(0o644, false), "-rw-r--r--");
        assert_eq!(mode_text_custom(0o755, true), "drwxr-xr-x");
        assert_eq!(mode_text_custom(0o4755, false), "-rwsr-xr-x");
        assert_eq!(mode_text_custom(0o1777, true), "drwxrwxrwt");
    }
}
