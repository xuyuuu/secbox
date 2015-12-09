#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <dirent.h>
#include <pthread.h>

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

#define PATH_PROC_INODE "/proc/%d/fd/"
#define PATH_PROC_STATE "/proc/net/tcp"
#define PRG_SOCKET_PFX "socket:["
#define PRG_SOCKET_PFXL (strlen(PRG_SOCKET_PFX))
#define SEC_BOX_INT_MAX (1 << 31)

static struct sockaddr_nl sec_box_saddr, sec_box_daddr;
static struct sec_box_ring *sec_box_ring;

struct hnode
{
	struct list_head node;

	uint8_t state;
	uint64_t inode;
};

static struct list_head sec_box_tcp_state_map[SEC_BOX_TCP_STATE_MAP_SIZE];
static pthread_rwlock_t sec_box_tcp_state_lock[SEC_BOX_TCP_STATE_MAP_SIZE];

static void map_inode_pack(const char lname[], uint64_t *inode)
{
	if(strlen(lname) < PRG_SOCKET_PFXL + 3)
		*inode = -1;
	else if(memcmp(lname, PRG_SOCKET_PFX, PRG_SOCKET_PFXL))
		*inode = -1;
	else if(lname[strlen(lname)-1] != ']')
		*inode = -1;
	else
	{
		char inode_str[strlen(lname + 1)];
		const int inode_str_len = strlen(lname) - PRG_SOCKET_PFXL - 1;
		char *serr;

		strncpy(inode_str, lname+PRG_SOCKET_PFXL, inode_str_len);
		inode_str[inode_str_len] = '\0';
		*inode = strtol(inode_str, &serr, 0);
		if ((!serr) || (*serr) || (*inode < 0) || (*inode >= SEC_BOX_INT_MAX))
			*inode = -1;
	}
}

void map_pack(const char *file)
{
	DIR *dirfd = NULL;
	struct dirent *direfd;
	char line[4096] = {0};
	char lname[30] = {0};
	int offset = 0, lnamelen = 0;
	uint64_t inode;

	offset = strlen(file);
	strncpy(line, file, offset);

	dirfd = opendir(file);
	if(!dirfd)
	{
		printf("opendir %s error !\n", file);	
		exit(-1);
	}
	while(NULL != (direfd = readdir(dirfd)))
	{
		if(direfd->d_type != DT_LNK)	
			continue;
		
		strncpy(line + offset, direfd->d_name, strlen(direfd->d_name));
		line[offset + strlen(direfd->d_name)] = '\0';
		lnamelen = readlink(line, lname, sizeof(lname) - 1);
		lname[lnamelen]  = '\0';
		map_inode_pack(lname, &inode);
	}
}

void map_update(void)
{
	;
}

void * netstat_task(void *arg)
{
	int pid = *((int *)arg);

	char file[512] = {0};
	sprintf(file, PATH_PROC_INODE, pid);

	pthread_detach(pthread_self());
	while(1)
	{
		map_pack(file);		
		usleep(300 * 1000);
	}

	return 0;
}

void usage(void)
{
	printf("--usage--:\n-p [pid]\n");
}

void talk_to_kernel(int sockfd, ulong i_node, struct sockaddr_nl *pdaddr)
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

	sendmsg(sockfd,&msg,0);
	free(nlh);

	return;
}

int init_sock(int *sockfd)
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

	int pid = 0, tmp = 0, sockfd, opt=0;
	char *endptr = NULL;

	while((opt = getopt(argc, argv, "p:")) != -1)
	{
		switch(opt)
		{
		case 'p':
			tmp = (int)strtod(optarg, &endptr);
			if(isalnum(tmp))
				pid = tmp;
			break;
		case 0:
			usage();
			return 0;
		default:
			usage();
			return 0;
		}
	}

	if (!pid)
	{
		printf("pid input error .\n");	
		goto err;
	}

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
	pthread_create(&tid, NULL, netstat_task, (void *)&pid);

	/*for loop*/
	int ret;
	struct sec_box_socket_clean_s *node;
	struct timeval start, current;
	gettimeofday(&start, NULL);
	while(1)
	{
		ret = sec_box_ring_module.dequeue(sec_box_ring, (void **)&node);
		if(ret == 0)
		{
			talk_to_kernel(sockfd, node->inode, &sec_box_daddr);
			free(node);
		}

		gettimeofday(&current, NULL);
		if(current.tv_sec - start.tv_sec > 2)
		{
			start.tv_sec = current.tv_sec;	
			start.tv_usec = current.tv_usec;
			map_update();
		}

		usleep(300 * 1000);
	}

err:
	if (sockfd > 0)
		close(sockfd);

	return 0;
}
