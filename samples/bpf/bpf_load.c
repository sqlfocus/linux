#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libelf.h>
#include <gelf.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <poll.h>
#include <ctype.h>
#include "libbpf.h"
#include "bpf_helpers.h"
#include "bpf_load.h"

#define DEBUGFS "/sys/kernel/debug/tracing/"

static char license[128];           /* elf文件的license段 */
static int kern_version;            /* 内核版本，elf文件的version段 */
static bool processed_sec[128];     /* 标识处理过的elf段(section) */
int map_fd[MAX_MAPS];               /* 加载elf文件maps段，生成的共享表 */
int prog_fd[MAX_PROGS];             /* 加载elf文件段，生成的ebpf程序 */
int event_fd[MAX_PROGS];            /* */
int prog_cnt;
int prog_array_fd = -1;             /* map_fd[]中对应的ebpf程序数组 */

static int populate_prog_array(const char *event, int prog_fd)
{
	int ind = atoi(event), err;

	err = bpf_update_elem(prog_array_fd, &ind, &prog_fd, BPF_ANY);
	if (err < 0) {
		printf("failed to store prog_fd in prog_array\n");
		return -1;
	}
	return 0;
}

/* 加载ebpf程序到内核 */
static int load_and_attach(const char *event, struct bpf_insn *prog, int size)
{
    /* 利用elf不同段名分类 */
	bool is_socket = strncmp(event, "socket", 6) == 0;
	bool is_kprobe = strncmp(event, "kprobe/", 7) == 0;
	bool is_kretprobe = strncmp(event, "kretprobe/", 10) == 0;
	bool is_tracepoint = strncmp(event, "tracepoint/", 11) == 0;
	bool is_xdp = strncmp(event, "xdp", 3) == 0;
	bool is_perf_event = strncmp(event, "perf_event", 10) == 0;
	enum bpf_prog_type prog_type;
	char buf[256];
	int fd, efd, err, id;
	struct perf_event_attr attr = {};

	attr.type = PERF_TYPE_TRACEPOINT;
	attr.sample_type = PERF_SAMPLE_RAW;
	attr.sample_period = 1;
	attr.wakeup_events = 1;

    /* 设置ebpf程序类别 */
	if (is_socket) {
		prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
	} else if (is_kprobe || is_kretprobe) {
		prog_type = BPF_PROG_TYPE_KPROBE;
	} else if (is_tracepoint) {
		prog_type = BPF_PROG_TYPE_TRACEPOINT;
	} else if (is_xdp) {
		prog_type = BPF_PROG_TYPE_XDP;
	} else if (is_perf_event) {
		prog_type = BPF_PROG_TYPE_PERF_EVENT;
	} else {
		printf("Unknown event '%s'\n", event);
		return -1;
	}

    /* 加载ebpf，并记录对应的文件描述符 */
	fd = bpf_prog_load(prog_type, prog, size, license, kern_version);
	if (fd < 0) {
		printf("bpf_prog_load() err=%d\n%s", errno, bpf_log_buf);
		return -1;
	}
	prog_fd[prog_cnt++] = fd;

    /* xdp及perf event类型程序，提前返回 */
	if (is_xdp || is_perf_event)
		return 0;

    /* 其他类型ebpf程序，需要设置相关内核参数，启动相关功能 */
	if (is_socket) {                    /* socket相关，ebpf程序数组，参考sockex3_*.c */
		event += 6;
		if (*event != '/')
			return 0;
		event++;
		if (!isdigit(*event)) {
			printf("invalid prog number\n");
			return -1;
		}
		return populate_prog_array(event, fd);
	}

	if (is_kprobe || is_kretprobe) {    /* kprobe */
		if (is_kprobe)
			event += 7;
		else
			event += 10;

		if (*event == 0) {
			printf("event name cannot be empty\n");
			return -1;
		}

		if (isdigit(*event))
			return populate_prog_array(event, fd);

        /* 插入kprobe探针 */
		snprintf(buf, sizeof(buf),
			 "echo '%c:%s %s' >> /sys/kernel/debug/tracing/kprobe_events",
			 is_kprobe ? 'p' : 'r', event, event);
		err = system(buf);
		if (err < 0) {
			printf("failed to create kprobe '%s' error '%s'\n",
			       event, strerror(errno));
			return -1;
		}

		strcpy(buf, DEBUGFS);
		strcat(buf, "events/kprobes/");
		strcat(buf, event);
		strcat(buf, "/id");
	} else if (is_tracepoint) {         /* tracepoint */
		event += 11;

		if (*event == 0) {
			printf("event name cannot be empty\n");
			return -1;
		}
		strcpy(buf, DEBUGFS);
		strcat(buf, "events/");
		strcat(buf, event);
		strcat(buf, "/id");
	}

    /* 获取probe事件ID */
	efd = open(buf, O_RDONLY, 0);
	if (efd < 0) {
		printf("failed to open event %s\n", event);
		return -1;
	}

	err = read(efd, buf, sizeof(buf));
	if (err < 0 || err >= sizeof(buf)) {
		printf("read from '%s' failed '%s'\n", event, strerror(errno));
		return -1;
	}

	close(efd);

	buf[err] = 0;
	id = atoi(buf);
	attr.config = id;

    /* 设置perf消息输出, 并挂接ebpf程序 */
	efd = perf_event_open(&attr, -1/*pid*/, 0/*cpu*/, -1/*group_fd*/, 0);
	if (efd < 0) {
		printf("event %d fd %d err %s\n", id, efd, strerror(errno));
		return -1;
	}
	event_fd[prog_cnt - 1] = efd;
	ioctl(efd, PERF_EVENT_IOC_ENABLE, 0);
	ioctl(efd, PERF_EVENT_IOC_SET_BPF, fd);

	return 0;
}

/* 根据elf的"maps"段section，加载ebpf的共享内存表MAP */
static int load_maps(struct bpf_map_def *maps, int len)
{
	int i;

	for (i = 0; i < len / sizeof(struct bpf_map_def); i++) {

		map_fd[i] = bpf_create_map(maps[i].type,
					   maps[i].key_size,
					   maps[i].value_size,
					   maps[i].max_entries,
					   maps[i].map_flags);
		if (map_fd[i] < 0) {
			printf("failed to create a map: %d %s\n",
			       errno, strerror(errno));
			return 1;
		}

		if (maps[i].type == BPF_MAP_TYPE_PROG_ARRAY)
			prog_array_fd = map_fd[i];
	}
	return 0;
}

/* 获取elf段名、段头及段数据 */
static int get_sec(Elf *elf, int i, GElf_Ehdr *ehdr, char **shname,
		   GElf_Shdr *shdr, Elf_Data **data)
{
	Elf_Scn *scn;

    /* 获取段信息(section descriptor) */
	scn = elf_getscn(elf, i);
	if (!scn)
		return 1;

    /* 获取section header */
	if (gelf_getshdr(scn, shdr) != shdr)
		return 2;

    /* 获取section名；ehdr->e_shstrndx为段名所在段的索引；shdr->sh_name为偏移 */
	*shname = elf_strptr(elf, ehdr->e_shstrndx, shdr->sh_name);
	if (!*shname || !shdr->sh_size)
		return 3;

    /* 获取段数据 */
	*data = elf_getdata(scn, 0);
	if (!*data || elf_getdata(scn, *data) != NULL)
		return 4;

	return 0;
}

static int parse_relo_and_apply(Elf_Data *data, Elf_Data *symbols,
				GElf_Shdr *shdr, struct bpf_insn *insn)
{
	int i, nrels;

	nrels = shdr->sh_size / shdr->sh_entsize;

	for (i = 0; i < nrels; i++) {
		GElf_Sym sym;
		GElf_Rel rel;
		unsigned int insn_idx;

		gelf_getrel(data, i, &rel);

		insn_idx = rel.r_offset / sizeof(struct bpf_insn);

		gelf_getsym(symbols, GELF_R_SYM(rel.r_info), &sym);

		if (insn[insn_idx].code != (BPF_LD | BPF_IMM | BPF_DW)) {
			printf("invalid relo for insn[%d].code 0x%x\n",
			       insn_idx, insn[insn_idx].code);
			return 1;
		}
		insn[insn_idx].src_reg = BPF_PSEUDO_MAP_FD;
		insn[insn_idx].imm = map_fd[sym.st_value / sizeof(struct bpf_map_def)];
	}

	return 0;
}

/* 加载llvm编译的.o文件，这样可以编写c语言版本的ebpf程序; 参考man elf */
int load_bpf_file(char *path)
{
	int fd, i;
	Elf *elf;
	GElf_Ehdr ehdr;
	GElf_Shdr shdr, shdr_prog;
	Elf_Data *data, *data_prog, *symbols = NULL;
	char *shname, *shname_prog;

    /* 协调ELF库和本应用进程版本号，
       coordinate ELF library and application versions */
	if (elf_version(EV_CURRENT) == EV_NONE)
		return 1;

	fd = open(path, O_RDONLY, 0);
	if (fd < 0)
		return 1;

    /* 开始解析传入的elf文件: 检测elf文件内容，分配新的ELF描述结构，并
       准备处理整个ELF文件 */
	elf = elf_begin(fd, ELF_C_READ, NULL);
	if (!elf)
		return 1;

    /* gelf_*是generic, ELF class-independent API for manipulating ELF
       object files； provides a single, common interface for handling 
       32–bit and 64–bit ELF format object files；is translation layer
       between the application and the class-dependent parts of the ELF
       library.   获取elf头 */
	if (gelf_getehdr(elf, &ehdr) != &ehdr)
		return 1;

	/* 清空kprobe事件，clear all kprobes */
	i = system("echo \"\" > /sys/kernel/debug/tracing/kprobe_events");

	/* 提取elf特定段信息，如内核版本、许可证、共享表等
       scan over all elf sections to get license and map info */
	for (i = 1; i < ehdr.e_shnum; i++) {

		if (get_sec(elf, i, &ehdr, &shname, &shdr, &data))
			continue;

		if (0) /* helpful for llvm debugging */
			printf("section %d:%s data %p size %zd link %d flags %d\n",
			       i, shname, data->d_buf, data->d_size,
			       shdr.sh_link, (int) shdr.sh_flags);

		if (strcmp(shname, "license") == 0) {     /* 记录license */
			processed_sec[i] = true;
			memcpy(license, data->d_buf, data->d_size);
		} else if (strcmp(shname, "version") == 0) {
			processed_sec[i] = true;
			if (data->d_size != sizeof(int)) {    /* 记录内核版本 */
				printf("invalid size of version section %zd\n",
				       data->d_size);
				return 1;
			}
			memcpy(&kern_version, data->d_buf, sizeof(int));
		} else if (strcmp(shname, "maps") == 0) { /* 加载共享表 */
			processed_sec[i] = true;
			if (load_maps(data->d_buf, data->d_size))
				return 1;
		} else if (shdr.sh_type == SHT_SYMTAB) {  /* 符号表 */
			symbols = data;
		}
	}

	/* 加载需要重定向的ebpf程序，
       load programs that need map fixup (relocations) */
	for (i = 1; i < ehdr.e_shnum; i++) {

		if (get_sec(elf, i, &ehdr, &shname, &shdr, &data))
			continue;
		if (shdr.sh_type == SHT_REL) {
			struct bpf_insn *insns;

			if (get_sec(elf, shdr.sh_info, &ehdr, &shname_prog,
				    &shdr_prog, &data_prog))
				continue;

			insns = (struct bpf_insn *) data_prog->d_buf;

			processed_sec[shdr.sh_info] = true;
			processed_sec[i] = true;

			if (parse_relo_and_apply(data, symbols, &shdr, insns))
				continue;                         /* 符号重定向 */

			if (memcmp(shname_prog, "kprobe/", 7) == 0 ||
			    memcmp(shname_prog, "kretprobe/", 10) == 0 ||
			    memcmp(shname_prog, "tracepoint/", 11) == 0 ||
			    memcmp(shname_prog, "xdp", 3) == 0 ||
			    memcmp(shname_prog, "perf_event", 10) == 0 ||
			    memcmp(shname_prog, "socket", 6) == 0)
				load_and_attach(shname_prog, insns, data_prog->d_size);
		}                                         /* 加载编译后的ebpf */
	}

	/* 加载不需重定向的程序，load programs that don't use maps */
	for (i = 1; i < ehdr.e_shnum; i++) {

		if (processed_sec[i])
			continue;

		if (get_sec(elf, i, &ehdr, &shname, &shdr, &data))
			continue;

		if (memcmp(shname, "kprobe/", 7) == 0 ||
		    memcmp(shname, "kretprobe/", 10) == 0 ||
		    memcmp(shname, "tracepoint/", 11) == 0 ||
		    memcmp(shname, "xdp", 3) == 0 ||
		    memcmp(shname, "perf_event", 10) == 0 ||
		    memcmp(shname, "socket", 6) == 0)
			load_and_attach(shname, data->d_buf, data->d_size);
	}

	close(fd);
	return 0;
}

void read_trace_pipe(void)
{
	int trace_fd;

	trace_fd = open(DEBUGFS "trace_pipe", O_RDONLY, 0);
	if (trace_fd < 0)
		return;

	while (1) {
		static char buf[4096];
		ssize_t sz;

		sz = read(trace_fd, buf, sizeof(buf));
		if (sz > 0) {
			buf[sz] = 0;
			puts(buf);
		}
	}
}

#define MAX_SYMS 300000
static struct ksym syms[MAX_SYMS];          /* 内核符号表 */
static int sym_cnt;

static int ksym_cmp(const void *p1, const void *p2)
{
	return ((struct ksym *)p1)->addr - ((struct ksym *)p2)->addr;
}

/* 读取/proc/kallsyms，加载内核符号表；格式参考proc_kallsyms_System.map.org */
int load_kallsyms(void)
{
	FILE *f = fopen("/proc/kallsyms", "r");
	char func[256], buf[256];
	char symbol;
	void *addr;
	int i = 0;

	if (!f)
		return -ENOENT;
    /* 逐行解析：指令地址 符号名，保留到全局数组，syms[] */
	while (!feof(f)) {
		if (!fgets(buf, sizeof(buf), f))
			break;
		if (sscanf(buf, "%p %c %s", &addr, &symbol, func) != 3)
			break;
		if (!addr)      /* <TAKECARE!!!>超级权限才能读到值 */
			continue;
		syms[i].addr = (long) addr;
		syms[i].name = strdup(func);
		i++;
	}
    
    /* 按地址排序 */
	sym_cnt = i;
	qsort(syms, sym_cnt, sizeof(struct ksym), ksym_cmp);
	return 0;
}

/* 搜索内核符号表，查找PC指针对应的符号名 */
struct ksym *ksym_search(long key)
{
	int start = 0, end = sym_cnt;
	int result;

	while (start < end) {
		size_t mid = start + (end - start) / 2;

		result = key - syms[mid].addr;
		if (result < 0)
			end = mid;
		else if (result > 0)
			start = mid + 1;
		else
			return &syms[mid];
	}

	if (start >= 1 && syms[start - 1].addr < key &&
	    key < syms[start].addr)
		/* valid ksym */
		return &syms[start - 1];

	/* out of range. return _stext */
	return &syms[0];
}
