#ifndef __sec_box_tcpstat_h__
#define __sec_box_tcpstat_h__

#define SEC_BOX_TCPSTAT_LOG_FILE "/var/log/sec_box_tcpstat.log"

#define SEC_BOX_TCPSTAT_HASHTABLE_SIZE (1 << 16)
#define SEC_BOX_TCPSTAT_HASHTABLE_MASK (SEC_BOX_TCPSTAT_HASHTABLE_SIZE - 1)

enum sec_box_tcpstat_rtn{sec_box_tcpstat_ok = 0, sec_box_tcpstat_error};

struct sec_box_tcpstat_node
{
	struct list_head head;

	ulong *i_node;
	struct socket *socket;
};

struct sec_box_tcpstat
{
	int (* init)(void);
	int (* add)(struct sec_box_tcpstat_node *node);
	int (* remove)(ulong *i_node);
	int (* search)(ulong *i_node);
	int (* destroy)(void);
	int (* dump)(void);
};

extern struct sec_box_tcpstat sec_box_tcpstat;

#endif
