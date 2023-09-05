#include <linux/list.h>
#include <linux/ioctl.h>
#include <linux/xattr.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/mutex.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include<linux/slab.h>
#include<linux/miscdevice.h>

#define FLOWIO 'w'

struct hello
{
	char* hellomsg;
	long hellolen;
};
/*
typedef struct ioctl_inc_s{
  char* msg;
  int msgleb;
}ioctl_int_t;

typedef struct union ioctl_param_u{
  ioctl_int_t set;
}ioctl_param_union;
*/
struct label_process{
	pid_t pid;
	tag_t *sec;
	int *secsize;
	int add;
};

struct change_global_cap{
	tag_t tag;
	int pos; //pos=1 changing positive global capability and pos=-1 changing negative global capability
	int add; //similarly add=1 and add=-1
};

struct change_process_cap{
	pid_t pid;
	tag_t tag;
	int pos; //pos=1 changing positive capability and pos=-1 negative capability
	int add; //similary 1 for adding and -1 for removing
};

struct add_tag_process{
	pid_t pid;
	tag_t tag;
	int add;  //add=1 for adding and add=-1 for removing tag.
};
struct process_sec_context{
	pid_t pid;
	uid_t uid;
	tag_t* sec;
	tag_t* pos;
	tag_t* neg;
	int secsize;
	int possize;
	int negsize;
};
/*This structure is used by kernel on behalf of daemon to handle checklist*/
struct daemon_sec{
int current_pid;
int from_pid;
tag_t tag;
};

enum FLOWIfaceProtocol {
	FLOW_HELLO = _IOWR(FLOWIO, 0, struct hello),
	FLOW_PROC_LABEL = _IOWR(FLOWIO, 1, struct label_process),
	FLOW_GLOBAL_CAP = _IOWR(FLOWIO, 2, struct change_global_cap),
	FLOW_INIT_PROC_SEC_CONTEXT = _IOWR(FLOWIO, 3, struct process_sec_context),
	FLOW_TAG_TO_LABEL = _IOWR(FLOWIO, 4, struct add_tag_process),
	FLOW_PROC_CAP = _IOWR(FLOWIO, 5, struct change_process_cap),
	FLOW_DAEMON = _IOWR(FLOWIO, 6, struct daemon_sec),
};
