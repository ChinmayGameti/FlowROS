#include <linux/wait.h>
#include <linux/time.h>
#include <linux/mutex.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/netlink.h>
#include <linux/net_namespace.h>
#include <linux/skbuff.h>

extern void send_to_daemon(char *path);
extern void show_daemon_id(pid_t id);
