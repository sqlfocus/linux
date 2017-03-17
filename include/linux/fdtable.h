/*
 * descriptor table internals; you almost certainly want file.h instead.
 */

#ifndef __LINUX_FDTABLE_H
#define __LINUX_FDTABLE_H

#include <linux/posix_types.h>
#include <linux/compiler.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/fs.h>

#include <linux/atomic.h>

/*
 * The default fd array needs to be at least BITS_PER_LONG,
 * as this is the granularity returned by copy_fdset().
 */
#define NR_OPEN_DEFAULT BITS_PER_LONG

struct fdtable {
	unsigned int max_fds;         /* 当前进程允许打开的最大文件数 */
	struct file __rcu **fd;       /* struct files_struct->fd_array */
	unsigned long *close_on_exec; /* bitmap, struct files_struct->close_on_exec_init */
	unsigned long *open_fds;      /* bitmap */
	unsigned long *full_fds_bits; /* bitmap */
	struct rcu_head rcu;
};

static inline bool close_on_exec(unsigned int fd, const struct fdtable *fdt)
{
	return test_bit(fd, fdt->close_on_exec);
}

static inline bool fd_is_open(unsigned int fd, const struct fdtable *fdt)
{
	return test_bit(fd, fdt->open_fds);
}

/*
 * Open file table structure
 *//* 进程关联用户态的fd和内核文件描述结构 */
struct files_struct {
  /*
   * read mostly part
   */
	atomic_t count;
	bool resize_in_progress;
	wait_queue_head_t resize_wait;

	struct fdtable __rcu *fdt;
	struct fdtable fdtab;           /* 重要数据结构，维护进程的文件描述符句柄 */
  /*
   * written part on a separate cache line in SMP
   */
	spinlock_t file_lock ____cacheline_aligned_in_smp;
	unsigned int next_fd;                  /* 新打开文件的句柄 */
	unsigned long close_on_exec_init[1];   /* bitmap，执行exec()族时需要关闭的文件句柄 */
	unsigned long open_fds_init[1];        /* */
	unsigned long full_fds_bits_init[1];
	struct file __rcu * fd_array[NR_OPEN_DEFAULT];
                                           /* 描述进程打开的文件，索引为fd句柄 */
};

struct file_operations;
struct vfsmount;
struct dentry;

#define rcu_dereference_check_fdtable(files, fdtfd) \
	rcu_dereference_check((fdtfd), lockdep_is_held(&(files)->file_lock))

#define files_fdtable(files) \
	rcu_dereference_check_fdtable((files), (files)->fdt)

/*
 * The caller must ensure that fd table isn't shared or hold rcu or file lock
 */
static inline struct file *__fcheck_files(struct files_struct *files, unsigned int fd)
{
	struct fdtable *fdt = rcu_dereference_raw(files->fdt);

	if (fd < fdt->max_fds)
		return rcu_dereference_raw(fdt->fd[fd]);
	return NULL;
}

static inline struct file *fcheck_files(struct files_struct *files, unsigned int fd)
{
	RCU_LOCKDEP_WARN(!rcu_read_lock_held() &&
			   !lockdep_is_held(&files->file_lock),
			   "suspicious rcu_dereference_check() usage");
	return __fcheck_files(files, fd);
}

/*
 * Check whether the specified fd has an open file.
 */
#define fcheck(fd)	fcheck_files(current->files, fd)

struct task_struct;

struct files_struct *get_files_struct(struct task_struct *);
void put_files_struct(struct files_struct *fs);
void reset_files_struct(struct files_struct *);
int unshare_files(struct files_struct **);
struct files_struct *dup_fd(struct files_struct *, int *) __latent_entropy;
void do_close_on_exec(struct files_struct *);
int iterate_fd(struct files_struct *, unsigned,
		int (*)(const void *, struct file *, unsigned),
		const void *);

extern int __alloc_fd(struct files_struct *files,
		      unsigned start, unsigned end, unsigned flags);
extern void __fd_install(struct files_struct *files,
		      unsigned int fd, struct file *file);
extern int __close_fd(struct files_struct *files,
		      unsigned int fd);

extern struct kmem_cache *files_cachep;

#endif /* __LINUX_FDTABLE_H */
