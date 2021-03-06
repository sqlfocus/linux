/* 
 * Copyright (C) 2000 - 2007 Jeff Dike (jdike@{addtoit,linux.intel}.com)
 * Licensed under the GPL
 */

#ifndef __UM_PROCESSOR_GENERIC_H
#define __UM_PROCESSOR_GENERIC_H

struct pt_regs;

struct task_struct;

#include <asm/ptrace.h>
#include <registers.h>
#include <sysdep/archsetjmp.h>

#include <linux/prefetch.h>

struct mm_struct;

struct thread_struct {
	struct pt_regs regs;
	struct pt_regs *segv_regs;
	int singlestep_syscall;
	void *fault_addr;
	jmp_buf *fault_catcher;
	struct task_struct *prev_sched;
	struct arch_thread arch;
	jmp_buf switch_buf;
	struct {
		int op;
		union {
			struct {
				int pid;
			} fork, exec;
			struct {
				int (*proc)(void *);
				void *arg;
			} thread;
			struct {
				void (*proc)(void *);
				void *arg;
			} cb;
		} u;
	} request;
};

#define INIT_THREAD \
{ \
	.regs		   	= EMPTY_REGS,	\
	.fault_addr		= NULL, \
	.prev_sched		= NULL, \
	.arch			= INIT_ARCH_THREAD, \
	.request		= { 0 } \
}

static inline void release_thread(struct task_struct *task)
{
}

extern unsigned long thread_saved_pc(struct task_struct *t);

static inline void mm_copy_segments(struct mm_struct *from_mm,
				    struct mm_struct *new_mm)
{
}

#define init_stack	(init_thread_union.stack)

/*
 * User space process size: 3GB (default).
 *//* linux内核将虚拟地址空间分为两部分，内核空间＋用户空间；以TASK_SIZE分界，
一般32位系统此值为3g；

另外，地址空间和cpu特权级别存在关联；IA-32系统分4个等级，但linux仅利用了0和3,
分别对应内核态和用户态；两种状态的差别，主要在对高于TASK_SIZE的内存区域的访问
：用户态禁止访问内核空间。

从用户态到内核态切换需借助系统调用实现。 */
extern unsigned long task_size;
#define TASK_SIZE (task_size)

#undef STACK_TOP
#undef STACK_TOP_MAX

extern unsigned long stacksizelim;

#define STACK_ROOM	(stacksizelim)
#define STACK_TOP	(TASK_SIZE - 2 * PAGE_SIZE)
#define STACK_TOP_MAX	STACK_TOP

/* This decides where the kernel will search for a free chunk of vm
 * space during mmap's.
 */
#define TASK_UNMAPPED_BASE	(0x40000000)

extern void start_thread(struct pt_regs *regs, unsigned long entry, 
			 unsigned long stack);

struct cpuinfo_um {
	unsigned long loops_per_jiffy;
	int ipi_pipe[2];
};

extern struct cpuinfo_um boot_cpu_data;

#define cpu_data (&boot_cpu_data)
#define current_cpu_data boot_cpu_data

#define KSTK_REG(tsk, reg) get_thread_reg(reg, &tsk->thread.switch_buf)
extern unsigned long get_wchan(struct task_struct *p);

#endif
