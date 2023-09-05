
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/bug.h>
#include <linux/socket.h>
#include <linux/lsm_hooks.h>
#include <linux/msg.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/xattr.h>

#include <linux/list.h>
#include <linux/types.h>
#include<linux/slab.h>
#include<linux/mutex.h>

#include <linux/file.h>
#include <linux/namei.h>

#include <net/sock.h>
#include <net/ip.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/skbuff.h>

//Datatypes
typedef int tag_t;

//Tag list for the seclabel, poscaps, negcaps
struct tag_list{
	tag_t t;
	struct list_head list;
};

//List Functions
extern int init_list(struct tag_list** orig_list_address);
extern int init_list2(struct tag_list* orig_list_address);
extern int add_list(struct tag_list* orig_list, tag_t tag);
extern void copy_init_list(struct tag_list* orig_list, struct tag_list** dest_list);
extern int copy_lists(struct tag_list* orig_list, struct tag_list* new_list);
extern int copy_list(struct tag_list* orig_list, struct tag_list* new_list);
extern bool exists_list(struct tag_list* orig_list, tag_t tag);
extern bool exists_list_globalpos(tag_t tag);
extern bool exists_list_globalneg(tag_t tag);
extern int remove_list(struct tag_list* orig_list, tag_t tag);
extern int list_size(struct tag_list* orig_list);
extern int list_print(struct tag_list* orig_list);
extern void union_list(struct tag_list* A, struct tag_list* B, struct tag_list** C);
extern bool dominates_global(struct tag_list* seclabel);
extern bool dominates(struct tag_list* A, struct tag_list* B);
extern bool equals(struct tag_list* A, struct tag_list* B);
extern void allocate_full_process_context(pid_t pid);
//Other Functions
extern int init_process_security_context(pid_t pid, uid_t uid, tag_t* sec, tag_t* pos, tag_t* neg, int secsize, int possize, int negsize);
extern int get_label_size(pid_t pid);
extern tag_t* get_label(pid_t pid);
extern void change_global_cap(tag_t tag, int pos, int add);
extern void change_process_cap(pid_t pid, tag_t tag, int pos, int add);
extern void add_tag_to_label(pid_t pid, tag_t tag);
extern void remove_tag_from_label(pid_t pid, tag_t tag);
extern void add_label_checklist(struct tag_list* s_label,struct tag_list* new_label);
extern void free_tag_list(struct tag_list* del_list);
extern struct security_operations flowros_ops;




enum {
	PROVENANCE_LOCK_PROC,
	PROVENANCE_LOCK_DIR,
	PROVENANCE_LOCK_INODE,
	PROVENANCE_LOCK_MSG,
	PROVENANCE_LOCK_SHM,
	PROVENANCE_LOCK_SOCKET,
	PROVENANCE_LOCK_SOCK
};
struct taglist{
	char *tag;
	struct tag_list *label;
	struct taglist *next;
};
struct checklist{
	struct taglist *head;
	struct taglist *update;
};
struct provenance {
//	union prov_elt msg;
	struct checklist *check;
	struct tag_list *seclabel;
	struct tag_list *poscap;
	struct tag_list *negcap;
	spinlock_t lock;
	struct mutex flowros_lock;
	int service;
	int flag;
	int exit_flag;
	int pid;
	int recv_pid;
};



extern void flowros_free_checklist(struct provenance *tprov);
extern void flowros_task_init(struct provenance *tprov);
extern void handle_checklist(struct provenance *sender_prov, struct provenance *receiver_prov, struct task_struct *receiver);
extern void add_label_checklist(struct tag_list *s_label, struct tag_list *new_label);
extern void flowros_free_task(struct provenance *tprov);
extern int flowros_send(struct provenance *sender_prov, struct provenance *receiver_prov, struct task_struct *receiver);

static inline struct provenance *provenance_cred(const struct cred *cred)
{
	return cred->security;
}

static inline struct provenance *provenance_task(const struct task_struct *task)
{
	struct provenance *prov;
	const struct cred *cred = get_task_cred(task);

	prov = cred->security;
	put_cred(cred); // Release cred.
	return prov;
}

static inline struct provenance *provenance_cred_from_task(
	struct task_struct *task)
{
	struct provenance *prov;
	const struct cred *cred = get_task_cred(task);

	prov = cred->security;
	put_cred(cred); // Release cred.
	return prov;
}

static inline struct provenance *provenance_file(const struct file *file)
{
	return file->f_security;
}

static inline struct provenance *provenance_inode(
	const struct inode *inode)
{
	if (unlikely(!inode->i_security))
		return NULL;
	return inode->i_security;
}

static inline struct provenance *provenance_msg_msg(
	const struct msg_msg *msg_msg)
{
	return msg_msg->security;
}

static inline struct provenance *provenance_ipc(
	const struct kern_ipc_perm *ipc)
{
	return ipc->security;
}


static inline struct provenance *get_file_provenance(struct file *file,
						     bool may_sleep)
{
	struct inode *inode = file_inode(file);

	if (!inode)
		return NULL;
	return provenance_inode(inode);
}


static inline struct provenance *get_socket_inode_provenance(
	struct socket *sock)
{
	struct inode *inode = SOCK_INODE(sock);
	struct provenance *iprov = NULL;

	if (inode)
		iprov = provenance_inode(inode);
	return iprov;
}

static inline struct provenance *get_sk_inode_provenance(struct sock *sk)
{
	struct socket *sock = sk->sk_socket;

	if (!sock)
		return NULL;
	return get_socket_inode_provenance(sock);
}

static inline struct provenance *get_sk_provenance(struct sock *sk)
{
	struct provenance *pprov = sk->sk_provenance;

	return pprov;
}
