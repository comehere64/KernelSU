#ifndef __KSU_H_SELINUX
#define __KSU_H_SELINUX

#include <linux/types.h>
#include <linux/version.h>
#include <linux/cred.h>

// 域名原来是 "ksu"，su 会话的上下文 u:r:ksu:s0 一眼就暴露。
//
// 注意：这里**不能**复用系统已有的域名（比如 shell / system_app）。
// 本模块会用 ksu_permissive() 把该域设成 permissive，若指向系统已有域，
// 就等于把 adb shell 之类的真实域改成宽容模式——削弱全局策略，
// 而且"某系统域是 permissive"本身就是极显眼的异常。
// 同时 ksu_type() 是重复声明，可能与现有 type 冲突导致策略加载失败。
//
// 所以用一个系统里不存在、风格像厂商私有的名字。
#define KERNEL_SU_DOMAIN "oplus_pfm_d"
#define KERNEL_SU_FILE "oplus_pfm_file"

#define KERNEL_SU_CONTEXT "u:r:" KERNEL_SU_DOMAIN ":s0"
#define KSU_FILE_CONTEXT "u:object_r:" KERNEL_SU_FILE ":s0"
#define ZYGOTE_CONTEXT "u:r:zygote:s0"
#define INIT_CONTEXT "u:r:init:s0"
#define ADBD_CONTEXT "u:r:adbd:s0"

void setup_selinux(const char *, struct cred *);

void setenforce(bool);

bool getenforce();

void cache_sid(void);

bool is_task_ksu_domain(const struct cred *cred);

bool is_ksu_domain();

bool is_zygote(const struct cred *cred);

bool is_init(const struct cred *cred);

bool is_adbd(const struct cred *cred);

void apply_kernelsu_rules();

int handle_sepolicy(void __user *user_data, u64 data_len);

void setup_ksu_cred();

void escape_to_root_for_adb_root();

struct inode;
struct inode_security_struct;
struct inode_security_struct *ksu_selinux_inode(const struct inode *inode);

struct super_block;
struct superblock_security_struct;
struct superblock_security_struct *ksu_selinux_superblock(const struct super_block *sb);

#if defined(MODULE) && defined(CONFIG_DEBUG_INFO_BTF)
int __init ksu_selinux_inode_init(void);
#else
static inline int ksu_selinux_inode_init(void)
{
    return 0;
}
#endif

#if defined(MODULE) && defined(CONFIG_DEBUG_INFO_BTF) && LINUX_VERSION_CODE >= KERNEL_VERSION(5, 13, 0)
int ksu_selinux_superblock_init(void);
#else
static inline int ksu_selinux_superblock_init(void)
{
    return 0;
}
#endif

extern u32 ksu_file_sid;

#endif
