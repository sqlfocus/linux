#ifndef _AF_NETLINK_H
#define _AF_NETLINK_H

#include <linux/rhashtable.h>
#include <linux/atomic.h>
#include <net/sock.h>

#define NLGRPSZ(x)	(ALIGN(x, sizeof(unsigned long) * 8) / 8)
#define NLGRPLONGS(x)	(NLGRPSZ(x)/sizeof(unsigned long))

/* netlink的插口信息结构 */
struct netlink_sock {
	/* struct sock has to be the first member of netlink_sock */
	struct sock		sk;
	u32			portid;                /* 监听端口信息 */
	u32			dst_portid;
	u32			dst_group;
	u32			flags;                 /* 特定标识，如 NETLINK_F_KERNEL_SOCKET */
	u32			subscriptions;
	u32			ngroups;
	unsigned long		*groups;       /* 多播位掩码，bind()时分配 */
	unsigned long		state;
	size_t			max_recvmsg_len;
	wait_queue_head_t	wait;
	bool			bound;             /* 是否已经插入nl_table[]表, struct netlink_table */
	bool			cb_running;
	struct netlink_callback	cb;
	struct mutex		*cb_mutex;
	struct mutex		cb_def_mutex;
    
	void			(*netlink_rcv)(struct sk_buff *skb);
	int			(*netlink_bind)(struct net *net, int group);
	void			(*netlink_unbind)(struct net *net, int group);
                                       /* 操控函数指针，如bind/read()等 */
                                       /* netlink_rcv = struct netlink_kernel_cfg->input */
                                       /* netlink_bind = struct netlink_kernel_cfg->bind */
                                       /* netlink_unbind = struct netlink_kernel_cfg->unbind */
	struct module		*module;       /* 实现模块 */

	struct rhash_head	node;          /* 插入到struct netlink_table->hash的节点 */
	struct rcu_head		rcu;
};

static inline struct netlink_sock *nlk_sk(struct sock *sk)
{
	return container_of(sk, struct netlink_sock, sk);
}

/* netlink协议描述结构，如 NETLINK_NETFILTER 等，见include/uapi/linux/netlink.h;
   由模块儿调用 netlink_kernel_create() 注册 */
struct netlink_table {
	struct rhashtable	hash;             /* 支持协议的内核监听插口，用户态插口 */
	struct hlist_head	mc_list;          /* 多播表 */
	struct listeners __rcu	*listeners;   /* 监听的多播位掩码 */
	unsigned int		flags;
	unsigned int		groups;           /* 支持的组播数 */
	struct mutex		*cb_mutex;
	struct module		*module;          /* 实现模块儿 */
	int			(*bind)(struct net *net, int group);
	void			(*unbind)(struct net *net, int group);
	bool			(*compare)(struct net *net, struct sock *sock);
	int			registered;               /* 是否已注册 */
};

extern struct netlink_table *nl_table;
extern rwlock_t nl_table_lock;

#endif
