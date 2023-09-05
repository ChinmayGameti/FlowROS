#include <linux/slab.h>
#include <linux/lsm_hooks.h>
#include <linux/msg.h>
#include <net/sock.h>
#include <net/af_unix.h>
#include <linux/binfmts.h>
#include <linux/random.h>
#include <linux/xattr.h>
#include <linux/file.h>
#include <linux/ptrace.h>
#include <linux/workqueue.h>
#include <linux/delay.h>
#include "provenance.h"
#include "flowros_netlink.h"



static int provenance_socket_sendmsg(struct socket *sock,
				     struct msghdr *msg,
				     int size)
{
//	struct provenance *tprov = provenance_task(current);
	struct provenance *iprova = get_socket_inode_provenance(sock);
	int rc = 0;

	if (!iprova)
		return -ENOMEM;

	/* Custom code start */
	if(sock->sk->sk_family == AF_INET && (sock->sk->sk_type == SOCK_STREAM ||
				sock->sk->sk_type == SOCK_DGRAM)) {
	//	printk(KERN_INFO"%d ---socket send msg",sock->sk->sk_num);
		//printk(KERN_INFO "socket_sendmsg(): process %s, pid %d\n", current->comm, current->pid);
	}
	if(iprova->pid != current->pid) {
		iprova->recv_pid = 0;
		if(sock->sk->sk_family == AF_INET && (sock->sk->sk_type == SOCK_STREAM ||
					sock->sk->sk_type == SOCK_DGRAM)) {
			//printk(KERN_INFO "socket_sendmsg(): process %s, pid %d - set recv_pid to 0\n", current->comm, current->pid);
		}
	}
	iprova->pid = current->pid;
	/* Custom code end */

	return rc;
}



static int provenance_socket_recvmsg(struct socket *sock,
				     struct msghdr *msg,
				     int size,
				     int flags)
{
	//struct provenance *tprov = provenance_task(current);
	struct provenance *iprov = get_socket_inode_provenance(sock);
	int rc = 0;

	/* Custom code start */
	//iprov->recv_pid = current->pid;
	if(iprov!=NULL)
		iprov->recv_pid = current->tgid;

	if(sock->sk->sk_family == AF_INET && (sock->sk->sk_type == SOCK_STREAM ||
				sock->sk->sk_type == SOCK_DGRAM)) {

	//			printk(KERN_INFO"%d socket recv",sock->sk->sk_num);
		int sender_pid = iprov->pid;
		int receiver_pid = current->pid;
		//printk(KERN_INFO "socket_recvmsg(): process %s, pid %d, sender_pid %d\n", current->comm, current->pid, sender_pid);
		//struct provenance *sender_prov = prov_from_vpid(sender_pid);

		if(sender_pid != receiver_pid && sender_pid != 0 && receiver_pid != 0) {
			struct task_struct *sender = find_task_by_vpid(sender_pid);
			struct task_struct *receiver = current;
			if(sender != NULL && receiver != NULL) {

			}
		}
	}
	/* Custom code end */

	if (!iprov)
		return -ENOMEM;
	return rc;
}



static int provenance_socket_sock_rcv_skb(struct sock *sk, struct sk_buff *skb)
{

	struct provenance *iprov;
	uint16_t family = sk->sk_family;
	//unsigned long irqflags;
	int rc = 0;

	if (family != PF_INET)
		return 0;

	iprov = get_sk_inode_provenance(sk);
	if (!iprov)
		return -ENOMEM;

	/* Custom code start */
	if(skb && skb->secmark)
	{
		if(sk->sk_num==7400 || sk->sk_num==7412 || sk->sk_num==7414 || sk->sk_num==7416 || sk->sk_num==7418)
		{
			
		//	printk(KERN_INFO"skipping for discovery protocol");
			return rc;
		}

		if(sk->sk_family == AF_INET && (sk->sk_type == SOCK_STREAM || sk->sk_type == SOCK_DGRAM))
		{
			int sender_pid = skb->secmark;
			int receiver_pid = iprov->recv_pid;
			if(sender_pid != receiver_pid && sender_pid != 0 && receiver_pid != 0)
			{
				struct task_struct *sender_tmp = find_task_by_vpid(sender_pid);
				struct task_struct *receiver_tmp = find_task_by_vpid(receiver_pid);
				struct task_struct *sender =find_task_by_vpid(sender_tmp->tgid);
				struct task_struct *receiver=find_task_by_vpid(receiver_tmp->tgid);

				if(sender !=NULL && receiver != NULL)
				{
					struct provenance *sender_prov = provenance_task(sender);
					struct provenance *receiver_prov = provenance_task(receiver);
					//  struct provenance *sender_prov_tmp = provenance_cred(__task_cred(sender_tmp));
					//  struct provenance *receiver_prov_tmp = provenance_cred(__task_cred(receiver_tmp));

					if(sender_prov != NULL && receiver_prov != NULL){


						if(sender_prov->seclabel!=NULL){
							if(dominates(receiver_prov->seclabel,sender_prov->seclabel))
							{
								//Flow is allowed because label of receiving process
								//dominates the label of sender.
								udelay(500);
								printk(KERN_INFO"Flow allowed\n");
							}
							else
							{
								//mutex_lock(&flowros->lock);
								//if(receiver_prov->service==0){
									if(dominates_global(sender_prov->seclabel)){
										if(receiver_prov->seclabel==NULL)
											copy_init_list(sender_prov->seclabel,&(receiver_prov->seclabel));
										else
											copy_list(sender_prov->seclabel,receiver_prov->seclabel);
										printk(KERN_INFO"propagating for receiver pid %d\t, recieving port %d and  with label:",sk->sk_num,receiver_pid);
										list_print(receiver_prov->seclabel);
									}	
								//}
								//mutex_unlock(&flowros->lock);
								// Call query hooks for propagate tracking.
								//rc = call_query_hooks(f, t, (prov_entry_t *)&relation);
								// if(rc!=0)
								return -EPERM; //or EACCES;
							}
						}
					}
				}
			}
		}
	}

	/* Custom code end */

	return rc;
}




static int provenance_sk_alloc_security(struct sock *sk,
					int family,
					gfp_t priority)
{
	struct provenance *skprov = provenance_task(current);

	if (!skprov)
		return -ENOMEM;
	sk->sk_provenance = skprov;
	return 0;
}

static int provenance_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
	struct provenance *prov;
	//struct task_struct *t = current;
	struct provenance *tprov;

    if(cred!=NULL){

	if(cred->security==NULL){
	  prov=kzalloc(sizeof(struct provenance),GFP_KERNEL);

	    if (!prov)
		return -ENOMEM;

	cred->security=prov;
	flowros_task_init(prov);
	}
    }

	return 0;
}


static void provenance_cred_free(struct cred *cred)
{
	struct provenance *cprov = provenance_cred(cred);

	if(cprov!=NULL){

	  flowros_free_checklist(cprov);
	  flowros_free_task(cprov);
	  kfree(cprov);
	  cred->security=NULL;

	}


}


static int provenance_cred_prepare(struct cred *new,
				   const struct cred *old,
				   gfp_t gfp)
{
	struct provenance *old_prov = provenance_cred(old);
	int rc=0;
	struct provenance *nprov;
	if(new!=NULL && new->security==NULL)
	{
	  nprov=kzalloc(sizeof(struct provenance),GFP_KERNEL);
	  if (!nprov)
		return -ENOMEM;
	  new->security=nprov;
	flowros_task_init(nprov);
	}
	/*
	if(nprov!=NULL && old_prov!=NULL){
		if(old_prov->flag==1 && old_prov->check!=NULL && old_prov->exit_flag==0){
				copy_init_list(old_prov->seclabel,&(nprov->seclabel));
				nprov->check=old_prov->check;
				old_prov->exit_flag=1;
				old_prov->flag=0;		
		}
	}*/
      return rc;
}

static void provenance_cred_transfer(struct cred *new, const struct cred *old)
{
	struct provenance *nprov;
	struct provenance *old_prov=provenance_cred(old);
	if(new!=NULL)
	{
	  if(new->security==NULL){
	    nprov=kzalloc(sizeof(struct provenance),GFP_KERNEL);
	    if (!nprov)
		return -ENOMEM;
	    new->security=nprov;
	    flowros_task_init(nprov);
	  }
	}
	/*
	if(nprov!=NULL && old_prov!=NULL){
		if(old_prov->flag==1 && old_prov->check!=NULL && old_prov->exit_flag==0){
				copy_init_list(old_prov->seclabel,&(nprov->seclabel));
				nprov->check=old_prov->check;
				old_prov->exit_flag=1;
				old_prov->flag=0;		
		}
	}
	*/
}


/*
static int provenance_task_alloc(struct task_struct *task,
				 unsigned long clone_flags)
{
	//struct provenance *ntprov = provenance_task(task);
	struct task_struct *t = current;
	struct provenance *tprov;
	    if(t!=NULL){
	      if(t->security==NULL){
		  tprov=kzalloc(sizeof(struct provenance),GFP_KERNEL);
	      }
	      else{
		tprov=provenance_task(t);
	      }


	      if(tprov!=NULL)
		 flowros_task_init(tprov);
	    }
	return 0;
}
*/
/*
static void provenance_task_free(struct task_struct *task)
{
    struct provenance *tprov;
    if(task!=NULL){
       tprov=provenance_task(task);

      if(tprov!=NULL){
	flowros_free_checklist(tprov);
	flowros_free_task(tprov);
	kfree(tprov);
	task->security=NULL;
      }

    }
}
*/
static void cred_init_security(void)
{
	struct cred *cred=(struct cred*)current->real_cred;
	struct provenance *tprov;
	tprov=kzalloc(sizeof(struct provenance),GFP_KERNEL);

	if (!tprov)
	  panic("FlowRos:Failed to initialize initial task.\n");

	cred->security=tprov;

}


static int provenance_inode_alloc_security(struct inode *inode)
{
	struct provenance *iprov;
      if(inode!=NULL){
	iprov=kzalloc(sizeof(struct provenance),GFP_KERNEL);

	if (unlikely(!iprov))
		return -ENOMEM;

	inode->i_security=iprov;
	flowros_task_init(iprov);
      }
	return 0;
}


static void provenance_inode_free_security(struct inode *inode)
{
	struct provenance *iprov = provenance_inode(inode);
	if(iprov!=NULL){
	  flowros_free_task(iprov);
	  kfree(iprov);
	  inode->i_security=NULL;
	}
}


/*
static int provenance_inode_create(struct inode *dir,
				   struct dentry *dentry,
				   umode_t mode)
{
	struct provenance *iprov;
	int rc;

	if (!iprov)
		return -ENOMEM;
	return rc;
}*/

static int provenance_sb_alloc_security(struct super_block *sb)
{   /*
	struct provenance *sbprov;
	sbprov= kzalloc(sizeof(struct provenance), GFP_KERNEL);

	if (!sbprov)
		return -ENOMEM;
	sb->s_provenance = sbprov;
	flowros_task_init(sbprov);
    */
	return 0;
}

static void provenance_sb_free_security(struct super_block *sb)
{   /*
	if (sb->s_provenance)
		kfree(sb->s_provenance);
	sb->s_provenance = NULL;
    */
}




/*!
 * @brief Add provenance hooks to security_hook_list.
 */
static struct security_hook_list provenance_hooks[] = {
	/* cred related hooks */
	LSM_HOOK_INIT(cred_free,                provenance_cred_free),
	LSM_HOOK_INIT(cred_alloc_blank,         provenance_cred_alloc_blank),
	LSM_HOOK_INIT(cred_prepare,             provenance_cred_prepare),
	LSM_HOOK_INIT(cred_transfer,            provenance_cred_transfer),

	/* task related hooks */
//	LSM_HOOK_INIT(task_alloc,               provenance_task_alloc),
//	LSM_HOOK_INIT(task_free,                provenance_task_free),
//	LSM_HOOK_INIT(task_fix_setuid,          provenance_task_fix_setuid),
//	LSM_HOOK_INIT(task_setpgid,             provenance_task_setpgid),
//	LSM_HOOK_INIT(task_getpgid,             provenance_task_getpgid),
//	LSM_HOOK_INIT(task_kill,                provenance_task_kill),
//	LSM_HOOK_INIT(ptrace_access_check,      provenance_ptrace_access_check),
//	LSM_HOOK_INIT(ptrace_traceme,           provenance_ptrace_traceme),

	/* inode related hooks */
	LSM_HOOK_INIT(inode_alloc_security,     provenance_inode_alloc_security),
	//LSM_HOOK_INIT(inode_create,             provenance_inode_create),
	LSM_HOOK_INIT(inode_free_security,      provenance_inode_free_security),
//	LSM_HOOK_INIT(inode_permission,         provenance_inode_permission),
//	LSM_HOOK_INIT(inode_link,               provenance_inode_link),
//	LSM_HOOK_INIT(inode_unlink,             provenance_inode_unlink),
//	LSM_HOOK_INIT(inode_symlink,            provenance_inode_symlink),
//	LSM_HOOK_INIT(inode_rename,             provenance_inode_rename),
//	LSM_HOOK_INIT(inode_setattr,            provenance_inode_setattr),
//	LSM_HOOK_INIT(inode_getattr,            provenance_inode_getattr),
//	LSM_HOOK_INIT(inode_readlink,           provenance_inode_readlink),
//	LSM_HOOK_INIT(inode_setxattr,           provenance_inode_setxattr),
//	LSM_HOOK_INIT(inode_post_setxattr,      provenance_inode_post_setxattr),
//	LSM_HOOK_INIT(inode_getxattr,           provenance_inode_getxattr),
//	LSM_HOOK_INIT(inode_listxattr,          provenance_inode_listxattr),
//	LSM_HOOK_INIT(inode_removexattr,        provenance_inode_removexattr),
	/* file related hooks */
//	LSM_HOOK_INIT(file_permission,          provenance_file_permission),
//	LSM_HOOK_INIT(mmap_file,                provenance_mmap_file),
//	LSM_HOOK_INIT(file_ioctl,               provenance_file_ioctl),
//	LSM_HOOK_INIT(file_open,                provenance_file_open),
//	LSM_HOOK_INIT(file_receive,             provenance_file_receive),
//	LSM_HOOK_INIT(file_lock,                provenance_file_lock),
//	LSM_HOOK_INIT(file_send_sigiotask,      provenance_file_send_sigiotask),
//	LSM_HOOK_INIT(kernel_read_file,         provenance_kernel_read_file),

	/* socket related hooks */
	LSM_HOOK_INIT(sk_alloc_security,        provenance_sk_alloc_security),
//	LSM_HOOK_INIT(socket_post_create,       provenance_socket_post_create),
//	LSM_HOOK_INIT(socket_socketpair,        provenance_socket_socketpair),
//	LSM_HOOK_INIT(socket_bind,              provenance_socket_bind),
//	LSM_HOOK_INIT(socket_connect,           provenance_socket_connect),
//	LSM_HOOK_INIT(socket_listen,            provenance_socket_listen),
//	LSM_HOOK_INIT(socket_accept,            provenance_socket_accept),

	LSM_HOOK_INIT(socket_sendmsg,           provenance_socket_sendmsg),
	LSM_HOOK_INIT(socket_recvmsg,           provenance_socket_recvmsg),
    /* CONFIG_SECURITY_FLOW_FRIENDLY */
	LSM_HOOK_INIT(socket_sock_rcv_skb,      provenance_socket_sock_rcv_skb),
//	LSM_HOOK_INIT(unix_stream_connect,      provenance_unix_stream_connect),
//	LSM_HOOK_INIT(unix_may_send,            provenance_unix_may_send),

	/* exec related hooks */
//	LSM_HOOK_INIT(bprm_check_security,      provenance_bprm_check_security),
//	LSM_HOOK_INIT(bprm_set_creds,           provenance_bprm_set_creds),
//	LSM_HOOK_INIT(bprm_committing_creds,    provenance_bprm_committing_creds),

	/* file system related hooks */
	LSM_HOOK_INIT(sb_alloc_security,        provenance_sb_alloc_security),
	LSM_HOOK_INIT(sb_free_security,         provenance_sb_free_security),
//	LSM_HOOK_INIT(sb_kern_mount,            provenance_sb_kern_mount)
};



static int __init provenance_init(void)
{
	pr_info("Provenance: initialization started...");


	cred_init_security();
//	pr_info("Provenance: init propagate query.");
//	init_prov_propagate();
//	pr_info("Provenance: starting in epoch %d.", epoch);
	// Register provenance security hooks.

 //     inode_cache = kmem_cache_create("FlowRos_inode_security",
//	          sizeof(struct inode_security_struct),
//			        0, SLAB_PANIC, NULL);
//      file_security_cache = kmem_cache_create("FlowRos_file_security",
//		    sizeof(struct file_security_struct),
//			          0, SLAB_PANIC, NULL);

	security_add_hooks(provenance_hooks,
			   ARRAY_SIZE(provenance_hooks));
	pr_info("FlowRos: hooks ready.\n");

	return 0;
}

/*Flowros Init*/
security_initcall(provenance_init);
