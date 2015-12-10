#ifndef __sec_box_tcpstat_h__
#define __sec_box_tcpstat_h__

#define SEC_BOX_TCPSTAT_LOG_FILE "/var/log/sec_box_tcpstat.log"

#define SEC_BOX_TCPSTAT_HASHTABLE_SIZE (1 << 12)
#define SEC_BOX_TCPSTAT_HASHTABLE_MASK (SEC_BOX_TCPSTAT_HASHTABLE_SIZE - 1)

enum sec_box_tcpstat_rtn{sec_box_tcpstat_ok = 0, sec_box_tcpstat_error};

struct sec_box_tcpstat_node
{
	struct list_head head;

	struct inode *i_node;
	struct socket *socket;
};

struct sec_box_tcpstat
{
	int (* init)(void);
	int (* add)(struct sec_box_tcpstat_node *node);
	int (* remove)(struct inode *i_node);
	int (* search)(struct inode *i_node);
	void (* release)(ulong inode);
	int (* destroy)(void);
	int (* dump)(void);
};

extern struct sec_box_tcpstat sec_box_tcpstat;

#endif
