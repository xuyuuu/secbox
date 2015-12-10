#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <dirent.h>
#include <pthread.h>
#include <time.h>

#include <asm/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>

#include <linux/netlink.h>
#include <linux/socket.h>

#include "sec_box_socket.h"
#include "sec_box_ring.h"
#include "sec_box_common_list.h"

#define SEC_BOX_TCP_STATE_MAP_SIZE (1 << 16)
#define SEC_BOX_TCP_STATE_MAP_MASK (SEC_BOX_TCP_STATE_MAP_SIZE - 1)

#define PATH_PROC_STATE "/proc/net/tcp"
#define PRG_SOCKET_PFX "socket:["
#define PRG_SOCKET_PFXL (strlen(PRG_SOCKET_PFX))
#define SEC_BOX_INT_MAX (1 << 31)

#define TCP_PACK_DETAILS(file, proc)\
FILE *fp;\
fp = fopen((file), "r");\
if(fp == NULL)\
	rc = -1;\
do\
{\
	if(fgets(buff, sizeof(buff), fp))\
		(proc)(lnr++, buff);\
}while(!feof(fp));\
fclose(fp);\

#define TCP_PACK(file, proc)\
char buff[8192];\
int rc = 0;\
int lnr = 0;\
TCP_PACK_DETAILS(file, proc)\
return rc;\

static struct sockaddr_nl sec_box_saddr, sec_box_daddr;
static struct sec_box_ring *sec_box_ring;

enum
{
	TCP_ESTABLISHED = 1,
	TCP_SYN_SENT,
	TCP_SYN_RECV,
	TCP_FIN_WAIT1,
	TCP_FIN_WAIT2,
	TCP_TIME_WAIT,
	TCP_CLOSE,
	TCP_CLOSE_WAIT,
	TCP_LAST_ACK,
	TCP_LISTEN,
	TCP_CLOSING			/* now a valid state */
};

struct hnode
{
	struct list_head node;

	uint8_t state;
	uint64_t inode;

	uint64_t update;
	uint64_t staycount;
	uint8_t mark; /*send netlink flag*/
};

static struct list_head sec_box_tcp_state_map[SEC_BOX_TCP_STATE_MAP_SIZE];
static pthread_rwlock_t sec_box_tcp_state_lock[SEC_BOX_TCP_STATE_MAP_SIZE];

static void tcp_state_read(int lnr, char *buff)
{
	unsigned long rxq, txq, time_len, retr, inode;
	int num, local_port, rem_port, d, state, uid, timer_run, timeout, found, hnum;
	char rem_addr[128], local_addr[128], timers[64], buffer[1024], more[512];
	struct hnode *item;

	if (lnr == 0)
		return;

	num = sscanf(buff,
			"%d: %64[0-9A-Fa-f]:%X %64[0-9A-Fa-f]:%X %X %lX:%lX %X:%lX %lX %d %d %ld %512s\n",
			&d, local_addr, &local_port, rem_addr, &rem_port, &state,
			&txq, &rxq, &timer_run, &time_len, &retr, &uid, &timeout, &inode, more);
	if(0 != num)
	{
		found = 0;
		item = NULL;

		hnum = state & SEC_BOX_TCP_STATE_MAP_MASK;
		pthread_rwlock_rdlock(&sec_box_tcp_state_lock[hnum]);
		list_for_each_entry(item, &sec_box_tcp_state_map[hnum], node)
		{
			if(item->inode == inode)	
			{
				found = 1;	
				break;
			}
		}
		pthread_rwlock_unlock(&sec_box_tcp_state_lock[hnum]);

		if(found)
		{
			if(item->state == state)		
			{
				item->update = time(NULL);	
				item->staycount++;
				if(!item->mark && item->staycount >= 1200 && item->state == TCP_CLOSE_WAIT)
				{
					item->mark = 1;
					uint64_t *pnode  = (uint64_t *)malloc(sizeof(uint64_t) * 1);
					if(pnode)
					{
						*pnode = inode;
						sec_box_ring_module.enqueue(sec_box_ring, (void *)pnode);
					}
				}
			}
			else
			{
				item->staycount = 0;
				item->state = state;	
				item->update = time(NULL);
			}
		}
		else
		{
			struct hnode *node = (struct hnode *)malloc(sizeof(struct hnode) * 1);			
			if(node)
			{
				node->inode = inode;
				node->state = state;
				node->update = time(NULL);
				node->staycount = 0;
				node->mark = 0;
				pthread_rwlock_wrlock(&sec_box_tcp_state_lock[hnum]);
				list_add_tail(&node->node, &sec_box_tcp_state_map[hnum]);
				pthread_rwlock_unlock(&sec_box_tcp_state_lock[hnum]);
			}

		}

	}
}

static int map_pack()
{
	TCP_PACK(PATH_PROC_STATE, tcp_state_read);
}

static void map_update(void)
{
	;
}

static void * netstat_task(void *arg)
{
	pthread_detach(pthread_self());

	while(1)
	{
		map_pack();		
		usleep(100 * 1000);
	}

	return 0;
}

static void usage(void)
{
	printf("--usage--:\n-d [run background]\n");
}

static void talk_to_kernel(int sockfd, ulong i_node, struct sockaddr_nl *pdaddr)
{
	struct nlmsghdr *nlh = NULL;
	struct iovec iov;
	struct msghdr msg;
	sec_box_socket_clean_t node;

	nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(sizeof(sec_box_socket_clean_t)));
	if(!nlh)
	{
		printf("malloc nlmsghdr error!\n");
		return;
	}
	memset(&msg,0,sizeof(msg));
	nlh->nlmsg_len = NLMSG_SPACE(sizeof(sec_box_socket_clean_t));
	nlh->nlmsg_pid = getpid();
	nlh->nlmsg_flags = 0;
	nlh->nlmsg_type = NET_CLEAN;
	memset(&node, 0x0, sizeof(sec_box_socket_clean_t));
	node.action = CLEAN_ACTION;
	node.inode = i_node;
	memcpy(NLMSG_DATA(nlh), &node, sizeof(sec_box_socket_clean_t));

	iov.iov_base = (void *)nlh;
	iov.iov_len = NLMSG_SPACE(sizeof(sec_box_socket_clean_t));

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = (void *)pdaddr;
	msg.msg_namelen = sizeof(*pdaddr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	sendmsg(sockfd, &msg, 0);
	free(nlh);

	return;
}

static int init_sock(int *sockfd)
{
	*sockfd = socket(AF_NETLINK, SOCK_RAW, SEC_BOX_SOCK_AF);
	if(*sockfd == -1)
	{
		printf("socket has error .\n");
		return -1;
	}

	memset(&sec_box_saddr, 0, sizeof(sec_box_saddr));
	sec_box_saddr.nl_family = AF_NETLINK;
	sec_box_saddr.nl_pid = getpid(); 
	sec_box_saddr.nl_groups = 0; 

	memset(&sec_box_daddr,0,sizeof(sec_box_daddr));
	sec_box_daddr.nl_family = AF_NETLINK;
	sec_box_daddr.nl_pid = 0;
	sec_box_daddr.nl_groups = 0;

	int retval;
	retval = bind(*sockfd, (struct sockaddr*)&sec_box_saddr, sizeof(sec_box_saddr));
	if(retval < 0)
	{
		printf("bind failed: %s", strerror(errno));
		return -1;
	}

	return 0;
}

int main(int argc, char* argv[])
{
	int sockfd, opt, backnd = 0;

	while(-1 != (opt = getopt(argc, argv, "d")))
	{
		switch (opt)	
		{
		case 'd':
			backnd = 1;
			break;
		case 0:
			usage();
			return 0;
		default:
			usage();
			return 0;
		}
	}

	if(backnd)
		daemon(1, 1);

	/*init socket*/
	if(init_sock(&sockfd))
		goto err;

	/*init ring*/
	sec_box_ring = sec_box_ring_module.create(10240);
	if(!sec_box_ring)
		goto err;
	
	/*init rwlock and hashmap*/
	int i;
	for(i = 0; i < SEC_BOX_TCP_STATE_MAP_SIZE; i++)
	{
		pthread_rwlock_init(&sec_box_tcp_state_lock[i], NULL);
		INIT_LIST_HEAD(&sec_box_tcp_state_map[i]);
	}

	/*search task*/
	pthread_t tid;
	pthread_create(&tid, NULL, netstat_task, NULL);

	/*for loop*/
	int ret;
	uint64_t * pnode;
	struct timeval start, current;
	gettimeofday(&start, NULL);
	while(1)
	{
		ret = sec_box_ring_module.dequeue(sec_box_ring, (void **)&pnode);
		if(ret == 0)
		{
			talk_to_kernel(sockfd, *pnode, &sec_box_daddr);
			free(pnode);
		}

		gettimeofday(&current, NULL);
		if(current.tv_sec - start.tv_sec > 30)
		{
			start.tv_sec = current.tv_sec;	
			start.tv_usec = current.tv_usec;
			map_update();
		}
		usleep(20 * 1000);
	}

err:
	if (sockfd > 0)
		close(sockfd);

	return 0;
}
