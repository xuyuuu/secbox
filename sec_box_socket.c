#include <linux/netlink.h>
#include <net/net_namespace.h>
#include <net/sock.h>
#include <linux/skbuff.h>
#include <linux/module.h>
#include <linux/pid.h>
#include <linux/string.h>
#include <linux/list.h>

#include "sec_box_socket.h"
#include "sec_box_md5sum.h"
#include "sec_box_blacklist.h"
#include "sec_box_accesslist.h"

static struct sock *sec_box_sock;
struct sec_box_socket sec_box_socket;

static int sec_box_socket_inside_access_ctl(struct sk_buff *skb)
{
	struct sec_box_accesslist_node *node = NULL;
	sec_box_socket_ctl_t *ctl;
	struct nlmsghdr *nlh;	
	nlh = (struct nlmsghdr *)skb->data;
	if (!NLMSG_OK(nlh, skb->len))
	{
		printk("sec_box_socket_receive has error. \n");
		goto out;	
	}
	
	ctl = (sec_box_socket_ctl_t *)NLMSG_DATA(nlh);
	if (strlen(ctl->file) >= SEC_BOX_SOCKET_FILE_SIZE)
		goto out;

	node = kmalloc(sizeof(struct sec_box_accesslist_node), GFP_KERNEL);
	if(!node)
	{
		printk("sec_box_socket_inside_process_ctl has error .\n");	
		goto out;
	}
	memset(node, 0x0, sizeof(*node));
	strncpy(node->path, ctl->file, sizeof(node->path) - 1);
	node->degree = ctl->degree;

	if (ctl->action == ADD_ACTION)
	{
		if( sec_box_accesslist_error == sec_box_accesslist.search(node))
		{
			sec_box_accesslist.add(node);
		}
		else
			kfree(node);
	}
	else if(ctl->action == DEL_ACTION)
	{
		sec_box_accesslist.remove(node);
		kfree(node);
	}
out:
	return 0;
}

static int sec_box_socket_inside_process_ctl(struct sk_buff *skb)
{
	struct sec_box_blacklist_node *node = NULL;
	sec_box_socket_ctl_t *ctl;
	struct nlmsghdr *nlh;	
	nlh = (struct nlmsghdr *)skb->data;
	if (!NLMSG_OK(nlh, skb->len))
	{
		printk("sec_box_socket_receive has error. \n");
		goto out;	
	}

	ctl = (sec_box_socket_ctl_t *)NLMSG_DATA(nlh);
	if (strlen(ctl->file) >= SEC_BOX_SOCKET_FILE_SIZE)
		goto out;

	/* degree or action error  */
	if ((ctl->action != ADD_ACTION && ctl->action != DEL_ACTION) ||
			(ctl->degree != 0 && ctl->degree != 1))
		goto out;

	node = kmalloc(sizeof(struct sec_box_blacklist_node), GFP_KERNEL);
	if(!node)
	{
		printk("sec_box_socket_inside_process_ctl has error .\n");	
		goto out;
	}
	memset(node, 0x0, sizeof(*node));
	strncpy(node->file, ctl->file, sizeof(node->file) - 1);
	node->degree = ctl->degree;
	if(!sec_box_md5sum.handler(ctl->file, node->md5num))
	{
		if (ctl->action == ADD_ACTION)
		{
			if( sec_box_blacklist_error == sec_box_blacklist.search(node))
			{
				sec_box_blacklist.add(node);
			}
			else
				kfree(node);
		}
		else if(ctl->action == DEL_ACTION)
		{
			sec_box_blacklist.remove(node);
			kfree(node);
		}
	}

	/*push node into list*/

#if 0 
	printk("== %s ===%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x=\n", ctl->file,
			node->md5num[0],node->md5num[1],node->md5num[2],node->md5num[3],
			node->md5num[4],node->md5num[5],node->md5num[6],node->md5num[7],
			node->md5num[8],node->md5num[9],node->md5num[10],node->md5num[11],
			node->md5num[12],node->md5num[13],node->md5num[14],node->md5num[15]);
#endif
out:
	return 0;
}



static void sec_box_socket_receive(struct sk_buff *skb)
{
	struct nlmsghdr *nlh;

	nlh = nlmsg_hdr(skb);
	if (nlh->nlmsg_len < sizeof(*nlh) ||
			skb->len < nlh->nlmsg_len)
	{
		goto out;
	}

	if (!NLMSG_OK(nlh, skb->len))
	{
		printk("sec_box_socket_receive has error. \n");
		goto out;	
	}

	switch(nlh->nlmsg_type)
	{
		case PROCESS_CTL:
			printk("receive a process_ctl message .\n");
			sec_box_socket_inside_process_ctl(skb);
			break;
		case ACCESS_CTL:
			printk("receive a access_ctl message .\n");
			sec_box_socket_inside_access_ctl(skb);
			break;
		case LOG_CTL:
			printk("receive a log_ctl message .\n");
			sec_box_blacklist.dump();
			sec_box_accesslist.dump();
			break;
		default:
			printk("from pid:[%d] process, message type error. \n", NETLINK_CREDS(skb)->pid);
			break;
	}
out:
	return;
}

static int sec_box_socket_send(char *data, int data_len, u16 msg_type,
		u16 msg_flags, pid_t pid)
{
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	char *msg;

	size_t payload_len = 0;
	int rtn;

	if(!sec_box_sock || !sec_box_sock->sk_socket)
	{
		printk("sec_box_socket_send have a error. \n");
		goto out;
	}
	
	payload_len = ((data && data_len)? data_len: 0);
	if(!(skb = alloc_skb(NLMSG_SPACE(payload_len), GFP_KERNEL)))
	{
		printk("sec_box_socket_send allock_skb error. \n");	
		goto out;
	}

	nlh = NLMSG_PUT(skb, pid, 0, msg_type, payload_len);
	nlh->nlmsg_flags = msg_flags;
	nlh->nlmsg_pid = 0;
	if (payload_len)
	{
		msg = (char *)NLMSG_DATA(nlh);
		memcpy(msg, data, data_len);
	}
	rtn = netlink_unicast(sec_box_sock, skb, pid, 0);
	if (rtn < 0)
		printk("sec_box_socket_send netlink_unicast error. \n");	
nlmsg_failure:
	kfree_skb(skb);
out:
	return 0;
}

static int sec_box_socket_handler(void)
{
	sec_box_sock = netlink_kernel_create(&init_net, SEC_BOX_SOCK_AF,
			0, sec_box_socket_receive, NULL, THIS_MODULE);

	return 0;
}


static int sec_box_socket_destroy(void)
{
	netlink_kernel_release(sec_box_sock);
	return 0;
}



__attribute((constructor))
int sec_box_socket_module_init(void)
{
	sec_box_socket.handler	= sec_box_socket_handler;
	sec_box_socket.destroy	= sec_box_socket_destroy;

	return 0;
}

