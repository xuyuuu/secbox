#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <string.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/socket.h>
#include <errno.h>

#include "sec_box_socket.h"

void usage(void)
{
	printf("--usage--:\n\
-t [process/access/log]\n\
-f controled file or folder\n\
-d degree[0/1/2] (0 means black, 1 means gray, 2 means protect)\n\
-m actoin[0/1] (0 means add, 1 means del)\n");
}

int main(int argc, char* argv[])
{
	char file[SEC_BOX_SOCKET_FILE_SIZE] = {0};
	struct iovec iov;
	struct msghdr msg;
	sec_box_socket_ctl_t node;
	struct nlmsghdr *nlh = NULL;
	struct sockaddr_nl saddr, daddr;
	int state, opt, type = -1, degree = -1, mode = -1,\
		sockfd = 0, retval, state_smg = 0, length;

	while((opt = getopt(argc, argv, "t:f:d:hm:")) != -1)
	{
		switch(opt)
		{
		case 't':
			type = !strncasecmp(optarg, "access", strlen(optarg)) ?ACCESS_CTL :\
			       (!strncasecmp(optarg, "process", strlen(optarg))? PROCESS_CTL:\
				(!strncasecmp(optarg, "log", strlen(optarg))? LOG_CTL : -1));
			break;
		case 'd':
			degree = atoi(optarg);
			break;
		case 'm':
			mode = atoi(optarg);
			break;
		case 'f':
			strncpy(file, optarg, sizeof(file) - 1);
			break;
		case 'h':
			usage();
			return 0;
		case 0:
			usage();
			return 0;
		default:
			usage();
			return 0;
		}
	}

	if ((type != LOG_CTL && (degree == -1 || mode == -1)) || type == -1)
	{
		printf("argument input error .\n");	
		goto err;
	}

	sockfd = socket(AF_NETLINK, SOCK_RAW, SEC_BOX_SOCK_AF);
	if(sockfd == -1)
	{
		printf("socket has error .\n");
		goto err;
	}

	memset(&saddr, 0, sizeof(saddr));
	saddr.nl_family = AF_NETLINK;
	saddr.nl_pid = getpid(); 
	saddr.nl_groups = 0; 


	retval = bind(sockfd, (struct sockaddr*)&saddr, sizeof(saddr));
	if(retval < 0)
	{
		printf("bind failed: %s", strerror(errno));
		goto err;
	}

	nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(sizeof(sec_box_socket_ctl_t)));
	if(!nlh)
	{
		printf("malloc nlmsghdr error!\n");
		goto err;
	}

	memset(&daddr,0,sizeof(daddr));
	daddr.nl_family = AF_NETLINK;
	daddr.nl_pid = 0;
	daddr.nl_groups = 0;

	memset(&msg,0,sizeof(msg));
	nlh->nlmsg_len = NLMSG_SPACE(sizeof(sec_box_socket_ctl_t));
	nlh->nlmsg_pid = getpid();
	nlh->nlmsg_flags = 0;
	nlh->nlmsg_type = type;
	memset(&node, 0x0, sizeof(sec_box_socket_ctl_t));
	node.degree = degree;
	node.action = mode;
	strncpy(node.file, file, sizeof(file) - 1);
	memcpy(NLMSG_DATA(nlh), &node, sizeof(sec_box_socket_ctl_t));

	iov.iov_base = (void *)nlh;
	iov.iov_len = NLMSG_SPACE(sizeof(sec_box_socket_ctl_t));

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = (void *)&daddr;
	msg.msg_namelen = sizeof(daddr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	printf("send message to kernel .\n");
	state_smg = sendmsg(sockfd,&msg,0);
	if(state_smg == -1)
	{
		printf("send message to kernel failed .\n");
		goto err;
	}
	printf("send message to kernel success .\n");

err:
	if (sockfd > 0)
	{
		close(sockfd);
	}

	return 0;
}
