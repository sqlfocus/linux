#include <linux/module.h>
#include <linux/kthread.h>

/*
 * Any file that uses trace points, must include the header.
 * But only one file, must include the header by defining
 * CREATE_TRACE_POINTS first.  This will make the C code that
 * creates the handles for the trace points.
 */
#define CREATE_TRACE_POINTS
#include "trace-events-sample.h"            /* 声明并定义静态跟踪点 */

static const char *random_strings[] = {
	"Mother Goose",
	"Snoopy",
	"Gandalf",
	"Frodo",
	"One ring to rule them all"
};

/* 启动模块儿时，加载的内核线程主入口函数 */
static void simple_thread_func(int cnt)
{
	int array[6];
	int len = cnt % 5;
	int i;

	set_current_state(TASK_INTERRUPTIBLE);
	schedule_timeout(HZ);                   /* 每秒执行一次 */

	for (i = 0; i < len; i++)
		array[i] = i + 1;                   /* 根据计数初始化数组 */
	array[i] = 0;

	
	trace_foo_bar("hello", cnt, array, random_strings[len],
		      tsk_cpus_allowed(current));  /* 插入tracepoint跟踪点 */

	trace_foo_with_template_simple("HELLO", cnt);

	trace_foo_bar_with_cond("Some times print", cnt);

	trace_foo_with_template_cond("prints other times", cnt);

	trace_foo_with_template_print("I have to be different", cnt);
}

static int simple_thread(void *arg)
{
	int cnt = 0;

	while (!kthread_should_stop())
		simple_thread_func(cnt++);     /* 内核线程主函数 */

	return 0;
}

static struct task_struct *simple_tsk;
static struct task_struct *simple_tsk_fn;

static void simple_thread_func_fn(int cnt)
{
	set_current_state(TASK_INTERRUPTIBLE);
	schedule_timeout(HZ);

	/* More silly tracepoints */
	trace_foo_bar_with_fn("Look at me", cnt);
	trace_foo_with_template_fn("Look at me too", cnt);
}

static int simple_thread_fn(void *arg)
{
	int cnt = 0;

	while (!kthread_should_stop())
		simple_thread_func_fn(cnt++);

	return 0;
}

static DEFINE_MUTEX(thread_mutex);

void foo_bar_reg(void)
{
	pr_info("Starting thread for foo_bar_fn\n");
	/*
	 * We shouldn't be able to start a trace when the module is
	 * unloading (there's other locks to prevent that). But
	 * for consistency sake, we still take the thread_mutex.
	 */
	mutex_lock(&thread_mutex);
	simple_tsk_fn = kthread_run(simple_thread_fn, NULL, "event-sample-fn");
	mutex_unlock(&thread_mutex);
}

void foo_bar_unreg(void)
{
	pr_info("Killing thread for foo_bar_fn\n");
	/* protect against module unloading */
	mutex_lock(&thread_mutex);
	if (simple_tsk_fn)
		kthread_stop(simple_tsk_fn);
	simple_tsk_fn = NULL;
	mutex_unlock(&thread_mutex);
}

static int __init trace_event_init(void)
{
    /* 启动内核线程 */
	simple_tsk = kthread_run(simple_thread, NULL, "event-sample");
	if (IS_ERR(simple_tsk))
		return -1;

	return 0;
}

static void __exit trace_event_exit(void)
{
	kthread_stop(simple_tsk);            /* 退出内核线程 */
	mutex_lock(&thread_mutex);
	if (simple_tsk_fn)
		kthread_stop(simple_tsk_fn);
	simple_tsk_fn = NULL;
	mutex_unlock(&thread_mutex);
}

/* 加载模块时调用 */
module_init(trace_event_init);
/* 卸载模块时调用 */
module_exit(trace_event_exit);

MODULE_AUTHOR("Steven Rostedt");
MODULE_DESCRIPTION("trace-events-sample");
MODULE_LICENSE("GPL");
