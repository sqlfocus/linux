#ifndef _UAPI__LINUX_BPF_COMMON_H__
#define _UAPI__LINUX_BPF_COMMON_H__

/* 本头文件定义cBPF的指令集结构sock_filter->code; 由~/include/uapi/linux/filter.h
   文件引用，实现cBPF功能 */
/* 本头文件也被~/include/uapi/linux/bpf.h引用，并在此基础上拓展为eBPF的指令结构 */

/* Instruction classes */
#define BPF_CLASS(code) ((code) & 0x07)
#define		BPF_LD		0x00
#define		BPF_LDX		0x01
#define		BPF_ST		0x02
#define		BPF_STX		0x03
#define		BPF_ALU		0x04
#define		BPF_JMP		0x05
#define		BPF_RET		0x06
#define		BPF_MISC        0x07

/* ld/ldx fields */
#define BPF_SIZE(code)  ((code) & 0x18)
#define		BPF_W		0x00
#define		BPF_H		0x08
#define		BPF_B		0x10
#define BPF_MODE(code)  ((code) & 0xe0)
#define		BPF_IMM		0x00    /* 加载立即数 */
#define		BPF_ABS		0x20    /* 访问报文数据，直接访问, BPF_LD_ABS() */
#define		BPF_IND		0x40    /* 访问报文数据，间接访问，BPF_LD_IND() */
#define		BPF_MEM		0x60
#define		BPF_LEN		0x80    /* 仅用于cbpf */
#define		BPF_MSH		0xa0    /* 仅用于cbpf */

/* alu/jmp fields */
#define BPF_OP(code)    ((code) & 0xf0)
#define		BPF_ADD		0x00
#define		BPF_SUB		0x10
#define		BPF_MUL		0x20
#define		BPF_DIV		0x30
#define		BPF_OR		0x40
#define		BPF_AND		0x50
#define		BPF_LSH		0x60
#define		BPF_RSH		0x70
#define		BPF_NEG		0x80
#define		BPF_MOD		0x90
#define		BPF_XOR		0xa0

#define		BPF_JA		0x00
#define		BPF_JEQ		0x10
#define		BPF_JGT		0x20
#define		BPF_JGE		0x30
#define		BPF_JSET        0x40
#define BPF_SRC(code)   ((code) & 0x08)
#define		BPF_K		0x00   /* cbpf:32-bit immediate as source operand */
                               /* ebpf: use 32-bit immediate as source operand */
#define		BPF_X		0x08   /* cbpf:register X as source operand */
                               /* ebpf:use 'src_reg' register as source operand */

#ifndef BPF_MAXINSNS
#define BPF_MAXINSNS 4096
#endif

#endif /* _UAPI__LINUX_BPF_COMMON_H__ */
