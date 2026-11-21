#ifndef __KSU_H_KLOG
#define __KSU_H_KLOG

#include <linux/printk.h>

#ifdef pr_fmt
#undef pr_fmt
#define pr_fmt(fmt) "KernelSU: " fmt
#endif

/*
 * 默认静默。
 *
 * 内核日志是最好用的自曝渠道：一句
 *     dmesg | grep -i kernelsu
 * 就能看出这个内核装了什么、什么版本、什么时候加载过、执行过哪些提权动作
 * （faccessat su->ksud、sys_execve su found、ksu fd installed ...）。
 *
 * 所以非调试构建下把 pr_info 全部编译成 no_printk：
 * 保留编译期的格式串检查，运行时一条也不落进 ring buffer。
 * 需要排查问题时用 KSU_DEBUG_LOG=1 重新编一次即可恢复。
 */
#ifndef KSU_DEBUG_LOG
#undef pr_info
#define pr_info(fmt, ...) no_printk(fmt, ##__VA_ARGS__)
#endif

#endif