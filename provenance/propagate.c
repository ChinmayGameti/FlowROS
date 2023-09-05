
#include "include/provenance.h"
#include "linux/errno.h"


#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/pid.h>
#include <linux/pid_namespace.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include "include/flowros_netlink.h"

#define NETLINK_USER 31


/*flowros ioctl interface*/
#include "include/flowros_ioctl.h"
/*Some Util functions*/

#include "include/flowros_lsm.h"

struct tag_list* global_pos;
struct tag_list* global_neg;
int ioctl_count = 0;
int add_tag(struct tag_list* orig_list, tag_t tag){
	int ret = add_list(orig_list, tag);
	return ret;
}
bool exists_tag(struct tag_list* orig_list, tag_t tag){
	bool ret = exists_list(orig_list, tag);
	return ret;
}
bool exists_tag_globalpos(tag_t tag){
	bool ret=exists_list(global_pos,tag);
	return ret;
}
bool exists_tag_globalneg(tag_t tag){
	bool ret=exists_list(global_neg,tag);
	return ret;
}
int remove_tag(struct tag_list* orig_list, tag_t tag){
	int ret = remove_list(orig_list, tag);
	return ret;
}
int copy_lists(struct tag_list* orig_list, struct tag_list* new_list){
	int ret=0;
	if(orig_list==NULL){
	    ret=-1;
	    return ret;
	}
	if(new_list==NULL){
	    ret=init_list(&new_list);
	    if(ret==ENOMEM)
		return ret;
	}
	ret=copy_list(orig_list, new_list);
	return ret;
}

bool dominates_global(struct tag_list* seclabel){
 
	if(dominates(global_pos,seclabel))
		 return true;
	 else 
	 	 return false;
}

/***********************Util End****************/

/*Some FlowRos provenance related functions used by ioctl interface*/

void add_tag_to_label(pid_t pid,tag_t tag){

  struct task_struct *task=find_task_by_vpid(pid);

  if(task!=NULL){

    struct provenance *task_prov=provenance_task(task);

    mutex_lock(&task_prov->flowros_lock);
   //
    if(task_prov->seclabel==NULL){

	task_prov->seclabel = (struct tag_list*)kzalloc(sizeof(struct tag_list), GFP_KERNEL);
	init_list2(task_prov->seclabel);

    }


    int ret=add_list(task_prov->seclabel, tag);

    if(ret==-1)printk(KERN_INFO"Error adding tag to label\n");
      //list_print(task_prov->seclabel);

    mutex_unlock(&task_prov->flowros_lock);
   //
   //
  }
}

void remove_tag_from_label(pid_t pid, tag_t tag)
{

  struct task_struct *task=find_task_by_vpid(pid);

  if(task!=NULL){

      struct provenance *task_prov=provenance_task(task);
      mutex_lock(&task_prov->flowros_lock);

      if(task_prov->seclabel!=NULL && list_size(task_prov->seclabel)>0)
      {

       int ret=remove_list(task_prov->seclabel,tag);
       if(ret==-1)printk(KERN_INFO"Error removing tag from label\n");
       //list_print(task_prov->seclabel);

      }

      mutex_unlock(&task_prov->flowros_lock);

  }
}

void change_process_cap(pid_t pid, tag_t tag, int pos, int add){

  struct task_struct *task=find_task_by_vpid(pid);

  if(task!=NULL){

    struct provenance *task_prov=provenance_task(task);
    mutex_lock(&task_prov->flowros_lock);
    //
    if(add==1){
	if(pos==1){
	   if(task_prov->poscap==NULL){

	     init_list(&task_prov->poscap);

	   }

	   add_list(task_prov->poscap,tag);

	}
      else if(pos==-1){
	if(task_prov->negcap==NULL){

	  init_list(&task_prov->negcap);

	}
	add_list(task_prov->negcap,tag);

      }

    }
   else if(add==-1){

      if(pos==1){
	 if(task_prov->poscap!=NULL){

	   remove_list(task_prov->poscap,tag);

	 }
      }
      else if(pos==-1){
	  if(task_prov->negcap!=NULL){
	    remove_list(task_prov->negcap,tag);
	  }
      }
    }

     mutex_unlock(&task_prov->flowros_lock);

  }
}

void change_global_cap(tag_t tag,int pos,int add){
    if(add==1){
      if(pos==1){
	if(global_pos==NULL){

	    init_list(&global_pos);
	}

	  add_list(global_pos,tag);
      }
    else if(pos==-1){
      if(global_neg==NULL){

	init_list(&global_neg);

      }

      add_list(global_neg,tag);

    }

  }
  else if(add==-1){

      if(pos==1){
	if(global_pos!=NULL){

	  remove_list(global_pos,tag);

	}
      }
      else if(pos==-1){
	if(global_neg!=NULL){

	  remove_list(global_neg,tag);

	}
      }
  }
}

void allocate_full_process_context(pid_t pid){

}


void add_label_checklist(struct tag_list *s_label, struct tag_list *new_label){
  struct list_head *pos;
  struct tag_list *tmp;

  list_for_each(pos,&(s_label->list)){

    tmp=list_entry(pos, struct tag_list,list);
    add_tag(new_label,tmp->t);

  }
}

/*
 *handle checklist function has parameters 1) sender process's provenance. 2) receiver process's provenance
 3) task_struct of receiver process
 if required FlowRos creates new instance of a receiving process for it to receive sensitive information.

 * */
void handle_checklist(struct provenance *sender_prov, struct provenance *receiver_prov, struct task_struct *receiver){
	struct mm_struct *mm=receiver->mm;
	int ret=0;
			if(mm!=NULL)
			{
			  if((receiver_prov->check)==NULL)
			  { printk(KERN_INFO"Initialization point 0\n");
			    struct checklist *new_check=(struct checklist *)kmalloc(sizeof(struct checklist),GFP_KERNEL);
			   if(!new_check)printk(KERN_INFO"Could not allocate memory for checklist\n");
			   else
			   { receiver_prov->check=new_check;
			      receiver_prov->check->head=NULL;
			      receiver_prov->check->update=NULL;
			      ret=flowros_send(sender_prov,receiver_prov,receiver);
			      if(ret==-1)printk(KERN_INFO"failed call to flowros_send\n");
			    }
			  }
			  else
			  { //spin_lock(&(receiver_prov->check->lock));
			    struct taglist *tmp;
			    tmp=receiver_prov->check->head;
			    bool call_send=true;
			    while (tmp!=NULL)
			    {
			      if(equals(sender_prov->seclabel,tmp->label))
			      {
				call_send=false;
				break;
			      }
			      tmp=tmp->next;
			    }
			      if(call_send){
				ret=flowros_send(sender_prov,receiver_prov,receiver);
				if(ret==-1)printk(KERN_INFO"faile call to flowros_send\n");
			      }
			  }
			}

}


void flowros_task_init(struct provenance *tprov){
	/***FlowRos Initialization***/
	if(tprov!=NULL){
	mutex_init(&tprov->flowros_lock);
	mutex_lock(&tprov->flowros_lock);

	tprov->check=NULL;
	tprov->seclabel=NULL;
	tprov->poscap=NULL;
	tprov->negcap=NULL;
	tprov->service=0;
	tprov->flag=0;
	tprov->exit_flag=0;
	mutex_unlock(&tprov->flowros_lock);
	}
}

void flowros_free_checklist(struct provenance *tprov){

      if(tprov!=NULL &&  tprov->check!=NULL && tprov->exit_flag==0){
	struct taglist *tmp;
	struct taglist *tmp_p;
	printk(KERN_INFO"FLOWROS:freeing the Checklist on task exit\n");
	if(tprov->check->head!=NULL)
	{
	  tmp=tprov->check->head;
	  tmp_p=tprov->check->head;

	  if((tprov->check->update)==(tprov->check->head) && equals(tmp->label,tprov->seclabel))
	  {
	       free_tag_list(tmp->label);
	       kfree(tmp);
	       tprov->check->head=NULL;
	       tprov->check->update=NULL;
	       kfree(tprov->check);
	      printk(KERN_INFO"tags freed\n");
	  }
	  else
	    {
		while(tmp!=NULL)
		{
		  if(equals(tmp->label,tprov->seclabel))
		  {
		    printk(KERN_INFO"tags matched and freed\n");
		    free_tag_list(tmp->label);
		    tmp_p->next=tmp->next;
		    kfree(tmp);
		    break;
		  }
		    tmp_p=tmp;
		    tmp=tmp->next;
		    if(tprov->check->head==NULL){
		      kfree(tprov->check);
		    }
		}
	    }
	}
	else
	{
	  kfree(tprov->check);
	  tprov->check=NULL;
	}
      }
}

void free_tag_list(struct tag_list *del_list){

	  if(list_size(del_list)>0){
	    struct list_head *pos,*q;
	    struct tag_list *tmp;
	    list_for_each_safe(pos,q,&(del_list->list)){
	      tmp=list_entry(pos, struct tag_list, list);
	      list_del(pos);
	      kfree(tmp);
	    }
	  }
}


void flowros_free_task(struct provenance *tprov){
    //free security context of a process
	mutex_lock(&tprov->flowros_lock);
	if(tprov->seclabel!=NULL){
	  printk(KERN_INFO"Clearing Security label for process %d\n",tprov->pid);
	  if(list_size(tprov->seclabel)>0){
	    struct list_head *pos,*q;
	    struct tag_list *tmp;
	    list_for_each_safe(pos,q,&(tprov->seclabel->list)){
	      tmp=list_entry(pos, struct tag_list, list);
	      list_del(pos);
	      kfree(tmp);
	    }
	  }
	  kfree(tprov->seclabel);
	}
	if(tprov->poscap!=NULL){
	  if(list_size(tprov->poscap)>0){
	    struct list_head *pos,*q;
	    struct tag_list *tmp;
	    list_for_each_safe(pos,q,&(tprov->poscap->list)){
	      tmp=list_entry(pos, struct tag_list, list);
	      list_del(pos);
	      kfree(tmp);
	    }
	  }
	  kfree(tprov->poscap);
	}
	if(tprov->negcap!=NULL){

	  if(list_size(tprov->negcap)>0){
	    struct list_head *pos,*q;
	    struct tag_list *tmp;
	    list_for_each_safe(pos,q,&(tprov->negcap->list)){
	      tmp=list_entry(pos, struct tag_list, list);
	      list_del(pos);
	      kfree(tmp);
	    }
	  }
	  kfree(tprov->negcap);
	}
	mutex_unlock(&tprov->flowros_lock);
}

int flowros_send(struct provenance *sender_prov,struct provenance *receiver_prov,struct task_struct *receiver)
{
	//struct provenance *sender_prov = provenance_cred(__task_cred(sender));
	//struct provenance *receiver_prov = provenance_cred(__task_cred(receiver));
	struct mm_struct *mm=receiver->mm;
	struct taglist *new_tag=(struct taglist *)kmalloc(sizeof(struct taglist),GFP_KERNEL);

	if(new_tag!=NULL){
	  new_tag->label=(struct tag_list *)kmalloc(sizeof(struct tag_list),GFP_KERNEL);
	  init_list2(new_tag->label);
	}

	if(new_tag==NULL){
	  return -1;
	}
	else
	{
	   add_label_checklist(sender_prov->seclabel,new_tag->label);
	   new_tag->next=NULL;
	  if((receiver_prov->check->head)==NULL)
	  {
	    receiver_prov->check->head=new_tag;
	    receiver_prov->check->update=new_tag;
	  }
	  else
	  {
	    receiver_prov->check->update->next=new_tag;
	    receiver_prov->check->update=new_tag;
	  }
		struct file *exe_file;
		char *pathname,*path;
		pathname=kmalloc(PATH_MAX, GFP_KERNEL);
		exe_file =get_mm_exe_file(mm);
		path_get(&exe_file->f_path);
		path=d_path(&mm->exe_file->f_path,pathname,PATH_MAX);
  //printk(KERN_INFO" -sock---task->comm: %s , task pid %d, path : %s\n",receiver->comm, receiver_prov->msg.task_info.pid, path);
  //printk(KERN_INFO"tgid of the receiving process is %d\n",receiver->tgid);
		char s1[PATH_MAX];
		char delimeter[2]=":";
		char pid_char[32];
		char end[2]="x";
		long int pid_s=receiver->pid;
		sprintf(pid_char,"%ld",pid_s);

		strcpy(s1,path);
		strcat(s1,delimeter);
		strcat(s1,pid_char);
		strcat(s1,delimeter);
		struct list_head *pos;
		struct tag_list *tmp;

	      list_for_each(pos,&(sender_prov->seclabel->list)){
		tmp=list_entry(pos, struct tag_list,list);

		char tmp_string[10];
		sprintf(tmp_string,"%d",tmp->t);
		strcat(s1,tmp_string);
		strcat(s1,delimeter);
	      }
	      strcat(s1,end);

		send_to_daemon(&s1[0]);
   // printk(KERN_INFO" -sock---task->comm: %s , task pid %d, path : %s\n",receiver->comm, receiver_prov->msg.task_info.pid, &s1[0]);
		kfree(pathname);
		return 0;
	}
}


/*****flowros ioctls end**************/

static long flow_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{

	int ret = 0;
	size_t size = _IOC_SIZE(cmd);
	void __user *ubuf = (void __user *)arg;
	struct hello *hello_msg=NULL;
	struct add_tag_process *add_tag_tmp=NULL;
	struct change_global_cap *g_cap=NULL;
	struct change_process_cap *c_cap=NULL;
	struct daemon_sec *d_sec=NULL;
	ioctl_count++;	
      switch(cmd){
	case FLOW_HELLO:
		hello_msg = (struct hello*)kmalloc(sizeof(struct hello), GFP_KERNEL);
		ret=copy_from_user(hello_msg,ubuf,size);
		if(ret==-1)printk("Error copying param from user to kernel\n");

		if(hello_msg!=NULL){

	printk(KERN_INFO"Version 0.1.3 --In Flow Hello received msg %s and size %ld\n",hello_msg->hellomsg,hello_msg->hellolen);
		  kfree(hello_msg);
		}
		break;

	case FLOW_PROC_LABEL:
		break;

	case FLOW_TAG_TO_LABEL:

		add_tag_tmp=(struct add_tag_process*)kmalloc(sizeof(struct add_tag_process),GFP_KERNEL);
		if(add_tag_tmp!=NULL){

		  ret=copy_from_user(add_tag_tmp,ubuf,sizeof(struct add_tag_process));

		  if(ret==-1){
		    printk("Error copy from user while adding tag to process\n");
		    kfree(add_tag_tmp);
		    break;
		  }



		  if(add_tag_tmp->add==1){
		    

	//printk(KERN_INFO"tag %d, to process %d, with add value %d\n",add_tag_tmp->tag,add_tag_tmp->pid,add_tag_tmp->add);
			  add_tag_to_label(add_tag_tmp->pid,add_tag_tmp->tag);
		  }

		  else if(add_tag_tmp->add==-1){
		  remove_tag_from_label(add_tag_tmp->pid, add_tag_tmp->tag);
	//printk(KERN_INFO"tag %d, to process %d, with add value %d\n",add_tag_tmp->tag,add_tag_tmp->pid,add_tag_tmp->add);
		  }
		  else if(add_tag_tmp->add==0){
		  		printk("ioctls count:%d\n",ioctl_count);
				ioctl_count=0;
		  }

		  kfree(add_tag_tmp);
		}

		break;

	case FLOW_GLOBAL_CAP:
		
		g_cap=(struct change_global_cap*)kmalloc(sizeof(struct change_global_cap),GFP_KERNEL);
		ret=copy_from_user(g_cap,ubuf,size);

		if(ret==-1 || g_cap==NULL){
		  kfree(g_cap);
		  break;
		}
		change_global_cap(g_cap->tag,g_cap->pos,g_cap->add);
		kfree(g_cap);
		break;

	case FLOW_PROC_CAP:
		
		c_cap=(struct change_process_cap*)kmalloc(sizeof(struct change_process_cap),GFP_KERNEL);
		ret=copy_from_user(c_cap,ubuf,size);

		if(ret==-1 || c_cap==NULL){
		  kfree(c_cap);
		  break;
		}

		change_process_cap(c_cap->pid,c_cap->tag,c_cap->pos,c_cap->add);
		kfree(c_cap);
		break;

	case FLOW_INIT_PROC_SEC_CONTEXT:
		break;
	
	case FLOW_DAEMON:
		
		d_sec =(struct daemon_sec*)kmalloc(sizeof(struct daemon_sec),GFP_KERNEL);
		
		ret=copy_from_user(d_sec,ubuf,sizeof(struct daemon_sec));

		
		printk("received checklist copy request from daemon with current_pid:%d from_pid:%d and Tag:%d\n",d_sec->current_pid,d_sec->from_pid,d_sec->tag);
		
		struct task_struct *current_task=find_task_by_vpid(d_sec->current_pid);
		struct task_struct *from_task = find_task_by_vpid(d_sec->from_pid);
		//struct provenance *tprov=get_task_provenance(true);
	
		struct provenance *tprov=provenance_task(current_task);
		struct provenance *fprov=provenance_task(from_task);
		//struct provenance *cprov=provenance_cred(__task_cred(current_task));
	
		if(current_task!=NULL && from_task!=NULL){
	
	  		if(tprov!=NULL && fprov!=NULL && fprov->check!=NULL){
	    		printk(KERN_INFO"IMP---check is not null for a receiving process who sent clone request\n");
		
				if(tprov->seclabel==NULL){

		  				tprov->seclabel = (struct tag_list*)kzalloc(sizeof(struct tag_list), GFP_KERNEL);
		  				init_list2(tprov->seclabel);
					}
	      		int ret=add_list(tprov->seclabel,d_sec->tag);

	      		if(ret==-1){
				printk(KERN_INFO"Error adding tag to label\n");
		  		return ret;
				}
	      		list_print(tprov->seclabel);
		
				tprov->check=fprov->check;
				tprov->flag=1;			
	  		}

		}	
		
		break;

	default:
		printk(KERN_INFO"This Command does'nt exist\n");
		ret = -1;
		break;
	}
	return ret;
}

static struct file_operations flow_fops = {
	.unlocked_ioctl = flow_ioctl,
};

static struct miscdevice flow_miscdev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "flowros",
	.fops = &flow_fops,
};

static int __init flow_init(void)
{
	int ret;
	ret = misc_register(&flow_miscdev);
	if(ret<0) {
		printk("Initializing flowros....... %d\n", ret);
	}
	else {
		printk("flowros ioctl device registered....!!\n");
	}

	return ret;
}
device_initcall(flow_init);

/*ioctl end*/


int daemon_pid=0;
struct sock *nl_sk = NULL;

/*
Netlink Kernel implementation
*/


 void send_to_daemon(char *path)
{
	if(daemon_pid!=0)
	{
		struct nlmsghdr *nlh;
		struct sk_buff *skb_out;
		int path_size;
		int res;

		printk(KERN_INFO"Sending msg to daemon\n");

		path_size=strlen(path);

		skb_out = nlmsg_new(path_size,0);

	if(!skb_out)
	{
			printk(KERN_ERR "Failed to allocate new skb\n");
	return;
	}

		nlh=nlmsg_put(skb_out,0,0,NLMSG_DONE,path_size,0);

		NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */

		strncpy(nlmsg_data(nlh),path,path_size);

		res=nlmsg_unicast(nl_sk,skb_out,daemon_pid);


	if(res<0)
		printk(KERN_INFO "Error sending path to Daemon\n");

	}

}




static void flowros_nl_recv_msg(struct sk_buff *skb) {

	struct nlmsghdr *nlh;
	int pid;
	struct sk_buff *skb_out;
	int msg_size;
	char *msg="Hello from kernel----2.2.2";
	int res;

	printk(KERN_INFO "Entering: %s\n", __FUNCTION__);

	msg_size=strlen(msg);

	nlh=(struct nlmsghdr*)skb->data;

	printk(KERN_INFO "Netlink received msg payload:%s\n",(char*)nlmsg_data(nlh));
	pid = nlh->nlmsg_pid; /*pid of The trusted daemon process */

	daemon_pid=pid;

	skb_out = nlmsg_new(msg_size,0);

	if(!skb_out)
	{

    printk(KERN_ERR "Failed to allocate new skb\n");
    return;

	}
	nlh=nlmsg_put(skb_out,0,0,NLMSG_DONE,msg_size,0);
	NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */
	strncpy(nlmsg_data(nlh),msg,msg_size);

	res=nlmsg_unicast(nl_sk,skb_out,pid);

	if(res<0)
	printk(KERN_INFO "Error sending path to Daemon\n");
	}

static int __init flowros_init(void) {

	printk("Entering: %s\n",__FUNCTION__);
	//This is for 3.6 kernels and above.
	struct netlink_kernel_cfg cfg = {
    .input = flowros_nl_recv_msg,
	};

	nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
	if(!nl_sk)
	{

	printk(KERN_ALERT "Error creating kernel netlink socket.\n");
	return -10;

	}

	return 0;
}


//INIT
int init_list(struct tag_list** list_pointer_address){
	*list_pointer_address = (struct tag_list*)kmalloc(sizeof(struct tag_list), GFP_KERNEL);
	if (!(*list_pointer_address)){
		return ENOMEM;
	}
	INIT_LIST_HEAD(&((*list_pointer_address)->list));
	return 0;
}
//INIT
int init_list2(struct tag_list* list_pointer_address){
	INIT_LIST_HEAD(&(list_pointer_address->list));
	return 0;
}

//COPY_INIT: Inits the destination and copies
void copy_init_list(struct tag_list* orig_list, struct tag_list** dest_list){
	init_list(dest_list);
	copy_list(orig_list, *dest_list);
}

//COPY
int copy_list(struct tag_list* orig_list, struct tag_list* new_list){
	struct list_head* pos;
	struct tag_list* tmp;
	if(orig_list==NULL || new_list==NULL){
	    return -1;
	}

	//Iterate to check if "value" exists in the list
	list_for_each(pos, &(orig_list->list)){
		tmp=list_entry(pos, struct tag_list, list);
		if(!exists_list(new_list, tmp->t)){
		    add_list(new_list, tmp->t);
		    //list_add(&(tmp->list), &(new_list->list));
		}
	}
	return 0;
}

//ADD
int add_list(struct tag_list* orig_list, tag_t value){
	struct tag_list *to_add;
	if(orig_list==NULL){

	    return -1;
	}

	if(exists_list(orig_list, value)){
	    return -1;
	}

	to_add = (struct tag_list*)kmalloc(sizeof(struct tag_list), GFP_KERNEL);
	if (to_add==NULL){
		return ENOMEM;
	}
	to_add->t = value;

	list_add(&(to_add->list), &(orig_list->list));

	return 0;
}

//EXISTS
bool exists_list(struct tag_list* orig_list, tag_t value){
	struct list_head* pos;
	struct tag_list* tmp;

	if(orig_list==NULL){
		return false;
	}

	//Iterate to check if "value" exists in the list
	list_for_each(pos, &(orig_list->list)){
		tmp=list_entry(pos, struct tag_list, list);
		//Return true if found
		if(tmp->t == value){
			return true;
		}
	}

	return false;
}

//REMOVE
int remove_list(struct tag_list* orig_list, tag_t value){
	struct list_head *pos, *q;
	struct tag_list* tmp;

	if(orig_list==NULL){
		return -1;
	}

	//Iterate to check if "value" exists in the list
	list_for_each_safe(pos, q, &(orig_list->list)){
		tmp=list_entry(pos, struct tag_list, list);
		//Remove if found
		if(tmp->t == value){
			list_del(pos);
			kfree(tmp);
			return 0;
		}
	}

	return 0;
}

//SIZE
int list_size(struct tag_list* orig_list){
	struct list_head* pos;
	int size=0;
	if(orig_list==NULL){
		return -1;
	}

	//printk("WEIR:list_size orig_list not NULL.\n");
	//Iterate to check if "value" exists in the list
	list_for_each(pos, &(orig_list->list)){
	    //printk("WEIR:list_size in list_for_each, size_counter=%d.\n", size);
	    size++;
	}

	return size;
}

//PRINT
int list_print(struct tag_list* orig_list){
	struct list_head* pos;
	struct tag_list* tmp;
	if(orig_list==NULL){
		printk("{}\n");
		return -1;
	}

	printk("{");
	//Iterate
	list_for_each(pos, &(orig_list->list)){
	    tmp=list_entry(pos, struct tag_list, list);
	    printk("%d, ",tmp->t);
	}
	printk("}\n");

	return 0;
}

//EMPTY
bool is_empty(struct tag_list* orig_list){
	if(list_size(orig_list)==0){
		return true;
	}
	return false;
}

// DOMINATES (i.e., a>=b)
bool dominates(struct tag_list* A, struct tag_list* B){
    struct list_head* pos;
	struct tag_list* tmp;

	//Everything dominates the lowest label.
	if(B==NULL || is_empty(B)){
		return true;
	}

	//If A is empty or NULL, it can dominate iff B is empty or null
	if(A==NULL || is_empty(A)){
		if(B==NULL || is_empty(B)){
			return true;
		} else {
			return false;
		}
	}

	list_for_each(pos, &(B->list)){
		tmp=list_entry(pos, struct tag_list, list);
		//If A does not contain the item in tmp, A does not dominate
		if(!exists_list(A, tmp->t)){
			return false;
		}
	}

	//A clearly dominates B at this point.
	return true;
}

// DOMINATES (i.e., a>=b)
bool equals(struct tag_list* A, struct tag_list* B){
    if(dominates(A,B) && dominates(B,A)) {
	return true;
    }
    return false;
}

//UNION
void union_list(struct tag_list* A, struct tag_list* B, struct tag_list** C) {
	//If both the sets empty, so is the union
	if((A==NULL || is_empty(A)) && (B==NULL || is_empty(B))){
		*C = NULL;
		return;
	}

	//If only A is empty, make a copy of B and return.
	if(A==NULL || is_empty(A)){
		copy_init_list(B, C);
		return;
	}

	//If only B is empty, make a copy of A and return.
	if(B==NULL || is_empty(B)){
		copy_init_list(A, C);
		return;
	}

	//Since both are not null, then we copy both one by one, but init only once.
	copy_init_list(A, C);
	copy_list(B, *C);
	return;
}



static void __exit flowros_exit(void) {

printk(KERN_INFO "exiting flowros netlink and lsm util module\n");
netlink_kernel_release(nl_sk);
}

module_init(flowros_init);
module_exit(flowros_exit);

MODULE_LICENSE("GPL");
