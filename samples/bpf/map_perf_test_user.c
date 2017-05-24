/* Copyright (c) 2016 Facebook
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <sys/types.h>
#include <asm/unistd.h>
#include <unistd.h>
#include <assert.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <signal.h>
#include <linux/bpf.h>
#include <string.h>
#include <time.h>
#include <sys/resource.h>
#include "libbpf.h"
#include "bpf_load.h"

#define MAX_CNT 1000000

static __u64 time_get_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000000ull + ts.tv_nsec;
}

/* 测试用例标志 */
#define HASH_PREALLOC		(1 << 0)
#define PERCPU_HASH_PREALLOC	(1 << 1)
#define HASH_KMALLOC		(1 << 2)
#define PERCPU_HASH_KMALLOC	(1 << 3)

static int test_flags = ~0;

static void test_hash_prealloc(int cpu)
{
	__u64 start_time;
	int i;

	start_time = time_get_ns();     /* 记录启动时间 */
	for (i = 0; i < MAX_CNT; i++)
		syscall(__NR_getuid);       /* 循环执行系统调用，以便被kprobe捕捉 */
	printf("%d:hash_map_perf pre-alloc %lld events per sec\n",
	       cpu, MAX_CNT * 1000000000ll / (time_get_ns() - start_time));
}                                   /* 打印执行时间 */

static void test_percpu_hash_prealloc(int cpu)
{
	__u64 start_time;
	int i;

	start_time = time_get_ns();
	for (i = 0; i < MAX_CNT; i++)
		syscall(__NR_geteuid);
	printf("%d:percpu_hash_map_perf pre-alloc %lld events per sec\n",
	       cpu, MAX_CNT * 1000000000ll / (time_get_ns() - start_time));
}

static void test_hash_kmalloc(int cpu)
{
	__u64 start_time;
	int i;

	start_time = time_get_ns();
	for (i = 0; i < MAX_CNT; i++)
		syscall(__NR_getgid);
	printf("%d:hash_map_perf kmalloc %lld events per sec\n",
	       cpu, MAX_CNT * 1000000000ll / (time_get_ns() - start_time));
}

static void test_percpu_hash_kmalloc(int cpu)
{
	__u64 start_time;
	int i;

	start_time = time_get_ns();
	for (i = 0; i < MAX_CNT; i++)
		syscall(__NR_getegid);
	printf("%d:percpu_hash_map_perf kmalloc %lld events per sec\n",
	       cpu, MAX_CNT * 1000000000ll / (time_get_ns() - start_time));
}

static void loop(int cpu)
{
	cpu_set_t cpuset;

	CPU_ZERO(&cpuset);               /* 核绑定 */
	CPU_SET(cpu, &cpuset);
	sched_setaffinity(0, sizeof(cpuset), &cpuset);

	if (test_flags & HASH_PREALLOC)  /* 启动测试例程 */
		test_hash_prealloc(cpu);

	if (test_flags & PERCPU_HASH_PREALLOC)
		test_percpu_hash_prealloc(cpu);

	if (test_flags & HASH_KMALLOC)
		test_hash_kmalloc(cpu);

	if (test_flags & PERCPU_HASH_KMALLOC)
		test_percpu_hash_kmalloc(cpu);
}

static void run_perf_test(int tasks)
{
	pid_t pid[tasks];
	int i;

	for (i = 0; i < tasks; i++) {
		pid[i] = fork();
		if (pid[i] == 0) {
			loop(i);                 /* 每个CPU启动子进程 */
			exit(0);
		} else if (pid[i] == -1) {
			printf("couldn't spawn #%d process\n", i);
			exit(1);
		}
	}
	for (i = 0; i < tasks; i++) {
		int status;

		assert(waitpid(pid[i], &status, 0) == pid[i]);
		assert(status == 0);         /* 等待子进程退出 */
	}
}

int main(int argc, char **argv)
{
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	char filename[256];
	int num_cpu = 8;

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
	setrlimit(RLIMIT_MEMLOCK, &r);

	if (argc > 1)   /* 参数1: 选择测试用例，HASH_PREALLOC等  */
		test_flags = atoi(argv[1]) ? : test_flags;

	if (argc > 2)   /* 参数2: 指定CPU核数 */
		num_cpu = atoi(argv[2]) ? : num_cpu;

	if (load_bpf_file(filename)) {   /* 加载内核ebpf部分 */
		printf("%s", bpf_log_buf);
		return 1;
	}

	run_perf_test(num_cpu);          /* 启动测试用例 */

	return 0;
}
