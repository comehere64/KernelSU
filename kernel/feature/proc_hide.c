// SPDX-License-Identifier: GPL-2.0
/*
 * 进程级隐身：把「伪装名启动的 root 进程」从 /proc 里抹掉。
 *
 * 为什么必须在核层做：
 *   用户态能改 argv[0] 和 comm，但脚本按 shebang 自己 exec 出来的进程、脚本内部
 *   fork 出去的守护进程，名字是内核在 exec 时定的，用户态来不及改。只有拦截
 *   目录枚举和读取这一层，ps / top / 进程管理器才读不到这些 pid。
 *
 * 为什么只 hook getdents64 而不摘 task_struct 链表：
 *   摘链（改 task->tasks.prev/next）会让 release_task() 再摘一次同样的节点，
 *   直接踩坏内核链表；依赖它的调度、统计子系统也都会受影响。
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
#include <linux/uaccess.h>
#include <linux/pid.h>
#include <linux/cred.h>
#include <linux/string.h>
#include <linux/moduleparam.h>
#include <linux/build_bug.h>
#include <linux/uio.h>
#include <linux/minmax.h>
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
 * 伪装的 cmdline。
 * 内核把 argv 拷进 mm 的 arg 区之后进程自己改不了，/proc/<pid>/cmdline 只能
 * 在读取这一层给假内容，否则 `ps -ef` 的 COMMAND 列会把整条脚本路径打出来。
 */
#define KSU_FAKE_CMDLINE "kworker"

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
/*
 * hook 全部装好之前什么都不碰。
 * ksu_sys_read 是 __NR_read 的全局 hook，init.rc 注入就发生在它上面，早于
 * proc_hide 初始化完成；那段窗口里走 fget 是给自己找麻烦。
 */
static bool ksu_proc_hide_ready;

/* 被我们替换掉的原始 syscall；调用它们才是真正的实现 */
static syscall_fn_t ksu_orig_getdents64;
static syscall_fn_t ksu_orig_pread64;
static syscall_fn_t ksu_orig_readv;

module_param_named(stealth_hide, ksu_stealth_hide, bool, 0600);
MODULE_PARM_DESC(stealth_hide, "hide kworker-named root processes from /proc listings");

/* hook 全部就绪、且总开关打开时才算启用；四个 hook 共用这一道判断 */
static bool ksu_stealth_active(void)
{
    return READ_ONCE(ksu_stealth_hide) && READ_ONCE(ksu_proc_hide_ready);
}

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

/* dentry 名与给定字符串是否完全相同；d_name.name 不保证 NUL 结尾，按 len 比 */
static bool ksu_dentry_is(const struct dentry *dentry, const char *name)
{
    size_t len = strlen(name);

    return dentry->d_name.len == len && memcmp(dentry->d_name.name, name, len) == 0;
}

/* fd 是否开在 procfs 上（getdents64 用） */
static bool ksu_fd_is_procfs_dir(int fd)
{
    struct file *file;
    bool hit;

    file = fget(fd);
    if (!file)
        return false;
    hit = d_is_dir(file->f_path.dentry) && file->f_path.dentry->d_sb &&
          file->f_path.dentry->d_sb->s_magic == PROC_SUPER_MAGIC;
    fput(file);
    return hit;
}

/*
 * 判定 fd 是不是「某个伪装进程的 /proc/<pid>/cmdline 或 /proc/<pid>/environ」。
 *
 * 命中返回持有引用的 file（调用方负责 fput），不命中返回 NULL。
 * 三个读取 hook（read / pread64 / readv）共用这一份判定，别再各抄一遍。
 *
 * 判定收窄到四条同时成立，避免误伤：
 *   目录项名是 cmdline / environ、父目录名是纯数字、pid 不是自己、该 pid 命中隐身。
 */
static struct file *ksu_stealth_proc_file(int fd, bool *is_environ)
{
    struct file *file;
    const struct dentry *dentry;
    int pid;

    file = fget(fd);
    if (!file)
        return NULL;

    dentry = file->f_path.dentry;
    if (!dentry || !dentry->d_sb || dentry->d_sb->s_magic != PROC_SUPER_MAGIC)
        goto miss;

    if (ksu_dentry_is(dentry, "cmdline"))
        *is_environ = false;
    else if (ksu_dentry_is(dentry, "environ"))
        *is_environ = true;
    else
        goto miss;

    /* 父目录就是 /proc/<pid>；d_parent 理论上不会空，但不是我们的代码说了算 */
    if (!dentry->d_parent)
        goto miss;
    pid = ksu_dirent_pid(dentry->d_parent->d_name.name, dentry->d_parent->d_name.len);
    /* pid == 自己时放行：脚本读 /proc/self/cmdline 做判断不会被弄坏 */
    if (pid <= 0 || pid == current->pid)
        goto miss;
    if (!ksu_stealth_should_hide(pid))
        goto miss;

    return file;

miss:
    fput(file);
    return NULL;
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
    if (ret <= 0 || !ksu_stealth_active())
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

/*
 * /proc/<pid>/cmdline 与 /proc/<pid>/environ 的伪造（__NR_read 走这条）。
 *
 * 为什么必须在这里：
 *   内核把 argv 拷进 mm 的 arg 区之后进程自己再也改不了。用户态能改的只有
 *   comm 和 argv[0]，而 `ps -ef` 打的是 COMMAND 列 = cmdline = 完整的 argv 串。
 *
 * 返回值语义：
 *   返回 true 表示「已经处理完，用 *result 当 syscall 返回值，别再调原 syscall」。
 */
bool ksu_proc_pseudo_read(int fd, char __user **buf_ptr, size_t *count_ptr, long *result)
{
    struct file *file;
    const char *fake = KSU_FAKE_CMDLINE;
    size_t count, pos, len, n;
    bool is_environ = false;

    if (!ksu_stealth_active())
        return false;
    /* pid 1（init）与内核线程：开机路径上一个都别动 */
    if (current->pid <= 1)
        return false;

    file = ksu_stealth_proc_file(fd, &is_environ);
    if (!file)
        return false;

    /* environ 直接给 EOF：env 里有 .webui_env 之类路径，也一并抹掉 */
    if (is_environ) {
        fput(file);
        *result = 0;
        return true;
    }

    count = count_ptr ? *count_ptr : 0;
    pos = (size_t)file->f_pos;
    len = strlen(fake);

    /* 假 cmdline 只有 7 字节：读完了就是 EOF，count 为 0 也直接回 0 */
    if (count == 0 || pos >= len) {
        fput(file);
        *result = 0;
        return true;
    }

    n = min(len - pos, count);
    if (copy_to_user(*buf_ptr, fake + pos, n)) {
        fput(file);
        *result = -EFAULT;
        return true;
    }
    file->f_pos = (loff_t)(pos + n);
    fput(file);
    *result = (long)n;
    return true;
}

/* pread64：偏移由调用者给，不动 f_pos */
long __nocfi ksu_hook_pread64(const struct pt_regs *regs)
{
    int fd = (int)PT_REGS_PARM1(regs);
    char __user *buf = (char __user *)(unsigned long)PT_REGS_PARM2(regs);
    size_t count = (size_t)PT_REGS_PARM3(regs);
    loff_t offset = (loff_t)PT_REGS_SYSCALL_PARM4(regs);
    struct file *file;
    const char *fake = KSU_FAKE_CMDLINE;
    size_t len, n;
    bool is_environ = false;

    if (!ksu_orig_pread64)
        return -ENOSYS;

    if (!ksu_stealth_active() || !buf || offset < 0)
        goto plain;

    file = ksu_stealth_proc_file(fd, &is_environ);
    if (!file)
        goto plain;
    fput(file);

    /* environ 与 cmdline 同处理：cmdline 给假内容，environ 给 EOF */
    if (is_environ)
        return 0;

    len = strlen(fake);
    if (offset >= (loff_t)len || count == 0)
        return 0;
    n = min(len - (size_t)offset, count);
    if (copy_to_user(buf, fake + offset, n))
        return -EFAULT;
    return (long)n;

plain:
    return ksu_orig_pread64(regs);
}

/* readv：多数工具不用，但库函数会；只处理第一个 iovec 就够 */
long __nocfi ksu_hook_readv(const struct pt_regs *regs)
{
    int fd = (int)PT_REGS_PARM1(regs);
    struct iovec __user *iov = (struct iovec __user *)(unsigned long)PT_REGS_PARM2(regs);
    int iovcnt = (int)PT_REGS_PARM3(regs);
    struct file *file;
    struct iovec first;
    const char *fake = KSU_FAKE_CMDLINE;
    size_t pos, len, n;
    bool is_environ = false;

    if (!ksu_orig_readv)
        return -ENOSYS;

    if (!ksu_stealth_active() || !iov || iovcnt < 1 || iovcnt > 8)
        goto plain;

    file = ksu_stealth_proc_file(fd, &is_environ);
    if (!file)
        goto plain;

    if (copy_from_user(&first, iov, sizeof(first))) {
        fput(file);
        return -EFAULT;
    }

    pos = (size_t)file->f_pos;
    len = strlen(fake);
    if (is_environ || pos >= len || first.iov_len == 0) {
        fput(file);
        return 0;
    }
    n = min(len - pos, (size_t)first.iov_len);
    if (copy_to_user(first.iov_base, fake + pos, n)) {
        fput(file);
        return -EFAULT;
    }
    file->f_pos = (loff_t)(pos + n);
    fput(file);
    return (long)n;

plain:
    return ksu_orig_readv(regs);
}

void ksu_proc_hide_init(void)
{
    /* 布局错了就别挂 hook：宁可进程可见，也不能把 /proc 枚举改坏 */
    BUILD_BUG_ON(sizeof(struct ksu_dirent64) != 19);

    ksu_syscall_table_hook(__NR_getdents64, (syscall_fn_t)ksu_hook_getdents64, &ksu_orig_getdents64);
    ksu_syscall_table_hook(__NR_pread64, (syscall_fn_t)ksu_hook_pread64, &ksu_orig_pread64);
    ksu_syscall_table_hook(__NR_readv, (syscall_fn_t)ksu_hook_readv, &ksu_orig_readv);

    /* 三个 hook 都挂完才开门，中间那段窗口一律放行 */
    WRITE_ONCE(ksu_proc_hide_ready, true);
    pr_info("proc_hide: getdents64=%d pread64=%d readv=%d\n", ksu_orig_getdents64 != NULL, ksu_orig_pread64 != NULL,
            ksu_orig_readv != NULL);
}

void ksu_proc_hide_exit(void)
{
    /* 先关门：让所有 hook 立刻走放行分支，再拆表 */
    WRITE_ONCE(ksu_proc_hide_ready, false);

    if (ksu_orig_getdents64)
        ksu_syscall_table_unhook(__NR_getdents64);
    ksu_orig_getdents64 = NULL;
    if (ksu_orig_pread64)
        ksu_syscall_table_unhook(__NR_pread64);
    ksu_orig_pread64 = NULL;
    if (ksu_orig_readv)
        ksu_syscall_table_unhook(__NR_readv);
    ksu_orig_readv = NULL;
}
