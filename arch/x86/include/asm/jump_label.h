#ifndef _ASM_X86_JUMP_LABEL_H
#define _ASM_X86_JUMP_LABEL_H

#ifndef HAVE_JUMP_LABEL
/*
 * For better or for worse, if jump labels (the gcc extension) are missing,
 * then the entire static branch patching infrastructure is compiled out.
 * If that happens, the code in here will malfunction.  Raise a compiler
 * error instead.
 *
 * In theory, jump labels and the static branch patching infrastructure
 * could be decoupled to fix this.
 */
#error asm/jump_label.h included on a non-jump-label kernel
#endif

#define JUMP_LABEL_NOP_SIZE 5

#ifdef CONFIG_X86_64
# define STATIC_KEY_INIT_NOP P6_NOP5_ATOMIC
#else
# define STATIC_KEY_INIT_NOP GENERIC_NOP5_ATOMIC
#endif

#include <asm/asm.h>
#include <asm/nops.h>

#ifndef __ASSEMBLY__

#include <linux/stringify.h>
#include <linux/types.h>

/* 实现NOP指令的跳转方式；条件成立继续执行 */
static __always_inline bool arch_static_branch(struct static_key *key, bool branch)
{
    /* .pushsection指令，用于在其他段定义跳转表；*/
    /* 跳转表为三元数组：[instruction address] [jump target] [tracepoint key] */
	asm_volatile_goto("1:"
        ".byte " __stringify(STATIC_KEY_INIT_NOP) "\n\t"   /* NOP */
        ".pushsection __jump_table,  \"aw\" \n\t"
		_ASM_ALIGN "\n\t"
		_ASM_PTR "1b, %l[l_yes], %c0 + %c1 \n\t"
		".popsection \n\t"
        : :  "i" (key), "i" (branch) : : l_yes);           /* 引入跳转标签 */

	return false;
l_yes:
	return true;
}

/* 实现JUMP指令的跳转方式；条件不成立执行跳转 */
static __always_inline bool arch_static_branch_jump(struct static_key *key, bool branch)
{
	asm_volatile_goto("1:"
		".byte 0xe9\n\t .long %l[l_yes] - 2f\n\t"
		"2:\n\t"
		".pushsection __jump_table,  \"aw\" \n\t"
		_ASM_ALIGN "\n\t"
		_ASM_PTR "1b, %l[l_yes], %c0 + %c1 \n\t"
		".popsection \n\t"
		: :  "i" (key), "i" (branch) : : l_yes);

	return false;
l_yes:
	return true;
}

#ifdef CONFIG_X86_64
typedef u64 jump_label_t;
#else
typedef u32 jump_label_t;
#endif

struct jump_entry {
	jump_label_t code;    /* 指令地址，instruction address */
	jump_label_t target;  /* 跳转表，jump target */
	jump_label_t key;     /* 回指包含它的struct static_key结构，tracepoint key */
};

#else	/* __ASSEMBLY__ */

.macro STATIC_JUMP_IF_TRUE target, key, def
.Lstatic_jump_\@:
	.if \def
	/* Equivalent to "jmp.d32 \target" */
	.byte		0xe9
	.long		\target - .Lstatic_jump_after_\@
.Lstatic_jump_after_\@:
	.else
	.byte		STATIC_KEY_INIT_NOP
	.endif
	.pushsection __jump_table, "aw"
	_ASM_ALIGN
	_ASM_PTR	.Lstatic_jump_\@, \target, \key
	.popsection
.endm

.macro STATIC_JUMP_IF_FALSE target, key, def
.Lstatic_jump_\@:
	.if \def
	.byte		STATIC_KEY_INIT_NOP
	.else
	/* Equivalent to "jmp.d32 \target" */
	.byte		0xe9
	.long		\target - .Lstatic_jump_after_\@
.Lstatic_jump_after_\@:
	.endif
	.pushsection __jump_table, "aw"
	_ASM_ALIGN
	_ASM_PTR	.Lstatic_jump_\@, \target, \key + 1
	.popsection
.endm

#endif	/* __ASSEMBLY__ */

#endif
