/*
 * Trace files that want to automate creation of all tracepoints defined
 * in their file should include this file. The following are macros that the
 * trace file may define:
 *
 * TRACE_SYSTEM defines the system the tracepoint is for
 *              定义系统跟踪点所在的子系统(group)
 *
 * TRACE_INCLUDE_FILE if the file name is something other than TRACE_SYSTEM.h
 *     This macro may be defined to tell define_trace.h what file to include.
 *     Note, leave off the ".h".
 *              当头文件名不是TRACE_SYSTEM.h，利用此宏定义头文件名
 *
 * TRACE_INCLUDE_PATH if the path is something other than core kernel include/trace
 *     then this macro can define the path to use. Note, the path is relative to
 *     define_trace.h, not the file including it. Full path names for out of tree
 *     modules must be used.
 *              定义头文件搜索路径，未指定则默认为内核目录include/trace；注意
 *              1)此路径相对于define_trace.h，而非定义它的文件；2)如果路径为源
 *              码树外的模块，则必须为全路径名
 */

/* <TAKECARE!!!>只有定义了此宏，此文件才有意义；
                一般在某个.c文件，先定义此宏，再引用头文件；
                其他的.c文件则只引用头文件即可 */
#ifdef CREATE_TRACE_POINTS

/* Prevent recursion */
#undef CREATE_TRACE_POINTS

#include <linux/stringify.h>

#undef TRACE_EVENT
#define TRACE_EVENT(name, proto, args, tstruct, assign, print)	\
	DEFINE_TRACE(name)            /* 定义tracepoint点 */

#undef TRACE_EVENT_CONDITION
#define TRACE_EVENT_CONDITION(name, proto, args, cond, tstruct, assign, print) \
	TRACE_EVENT(name,						\
		PARAMS(proto),						\
		PARAMS(args),						\
		PARAMS(tstruct),					\
		PARAMS(assign),						\
		PARAMS(print))

#undef TRACE_EVENT_FN
#define TRACE_EVENT_FN(name, proto, args, tstruct,		\
		assign, print, reg, unreg)			\
	DEFINE_TRACE_FN(name, reg, unreg)

#undef TRACE_EVENT_FN_COND
#define TRACE_EVENT_FN_COND(name, proto, args, cond, tstruct,		\
		assign, print, reg, unreg)			\
	DEFINE_TRACE_FN(name, reg, unreg)

#undef DEFINE_EVENT
#define DEFINE_EVENT(template, name, proto, args) \
	DEFINE_TRACE(name)

#undef DEFINE_EVENT_FN
#define DEFINE_EVENT_FN(template, name, proto, args, reg, unreg) \
	DEFINE_TRACE_FN(name, reg, unreg)

#undef DEFINE_EVENT_PRINT
#define DEFINE_EVENT_PRINT(template, name, proto, args, print)	\
	DEFINE_TRACE(name)

#undef DEFINE_EVENT_CONDITION
#define DEFINE_EVENT_CONDITION(template, name, proto, args, cond) \
	DEFINE_EVENT(template, name, PARAMS(proto), PARAMS(args))

#undef DECLARE_TRACE
#define DECLARE_TRACE(name, proto, args)	\
	DEFINE_TRACE(name)

#undef TRACE_INCLUDE
#undef __TRACE_INCLUDE

#ifndef TRACE_INCLUDE_FILE
# define TRACE_INCLUDE_FILE TRACE_SYSTEM
# define UNDEF_TRACE_INCLUDE_FILE
#endif

#ifndef TRACE_INCLUDE_PATH
# define __TRACE_INCLUDE(system) <trace/events/system.h>
# define UNDEF_TRACE_INCLUDE_PATH
#else
# define __TRACE_INCLUDE(system) __stringify(TRACE_INCLUDE_PATH/system.h)
#endif

# define TRACE_INCLUDE(system) __TRACE_INCLUDE(system)

/* 定义此宏，允许定义静态跟踪点的头文件被重新读入，Let the trace headers be reread */
#define TRACE_HEADER_MULTI_READ
/* <TAKECARE!!!>第2次重新加载头文件 */
#include TRACE_INCLUDE(TRACE_INCLUDE_FILE)

/* Make all open coded DECLARE_TRACE nops */
#undef DECLARE_TRACE
#define DECLARE_TRACE(name, proto, args)

/* 实现事件跟踪及格式化 */
#ifdef TRACEPOINTS_ENABLED
#include <trace/trace_events.h>     /* 第3~9次重新加载头文件 */
#include <trace/perf.h>             /* 第10次重新加载头文件 */
#endif

#undef TRACE_EVENT
#undef TRACE_EVENT_FN
#undef TRACE_EVENT_FN_COND
#undef TRACE_EVENT_CONDITION
#undef DECLARE_EVENT_CLASS
#undef DEFINE_EVENT
#undef DEFINE_EVENT_FN
#undef DEFINE_EVENT_PRINT
#undef DEFINE_EVENT_CONDITION
#undef TRACE_HEADER_MULTI_READ
#undef DECLARE_TRACE

/* Only undef what we defined in this file */
#ifdef UNDEF_TRACE_INCLUDE_FILE
# undef TRACE_INCLUDE_FILE
# undef UNDEF_TRACE_INCLUDE_FILE
#endif

#ifdef UNDEF_TRACE_INCLUDE_PATH
# undef TRACE_INCLUDE_PATH
# undef UNDEF_TRACE_INCLUDE_PATH
#endif

/* We may be processing more files */
#define CREATE_TRACE_POINTS

#endif /* CREATE_TRACE_POINTS */
