#ifndef __sec_box_socket_h__
#define __sec_box_socket_h__

#define SEC_BOX_SOCK_AF 24

#define SEC_BOX_SOCKET_FILE_SIZE 512

enum SEC_BOX_SOCK_ACTION
{
	ADD_ACTION = 0,
	DEL_ACTION
};

enum SEC_BOX_SOCK_TYPE
{
	PROCESS_CTL = 0,
	ACCESS_CTL,
	LOG_CTL
};

typedef struct sec_box_socket_ctl_s sec_box_socket_ctl_t;
struct sec_box_socket_ctl_s
{
	char action;
	char degree;
	u_char file[SEC_BOX_SOCKET_FILE_SIZE];
}__attribute__((packed));


struct sec_box_socket
{
	int (* handler)(void);
	int (* send)(void);
	int (* destroy)(void);
};

extern struct sec_box_socket sec_box_socket;

#endif
