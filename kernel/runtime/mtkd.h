#ifndef __KSU_H_KSUD
#define __KSU_H_KSUD

#include <asm/syscall.h>

// 守护进程路径。原来叫 /data/adb/ksud，/proc/*/cmdline 与 ps 一眼就能看出
// 这是 KernelSU。换成系统里像模像样的名字。
// 迁移期由用户态在 /data/adb/mtkd 建软链指过来。
// ksud 不是常驻守护进程——由 ksud_integration.c 注入的 init 脚本
// 在 post-fs-data / services(x2) / boot-completed 四个时点各 exec 一次，
// 用完即退；只有 `webui --daemon` 是长驻进程，由计算器触发。
#define KSUD_PATH "/data/adb/mtkd"

void ksu_ksud_init();
void ksu_ksud_exit();

void ksu_execve_hook_ksud(const struct pt_regs *regs);
void ksu_execveat_hook_ksud(const struct pt_regs *regs);
void ksu_stop_input_hook_runtime(void);

#endif
