#ifndef __sec_box_blacklist_h__
#define __sec_box_blacklist_h__

#define SEC_BOX_BLACKLIST_LOG_FILE "/var/log/sec_box_blacklist.log"

#define SEC_BOX_BLACKLIST_DEGREE_SERIOUS 0
#define SEC_BOX_BLACKLIST_DEGREE_SLIGHT 1
#define SEC_BOX_BLACKLIST_PROTECT 2

#define SEC_BOX_BLACKLIST_HASHTABLE_SIZE (1 << 16)
#define SEC_BOX_BLACKLIST_HASHTABLE_MASK (SEC_BOX_BLACKLIST_HASHTABLE_SIZE - 1)

enum sec_box_blacklist_rtn{sec_box_blacklist_ok = 0, sec_box_blacklist_error};

struct sec_box_blacklist_node
{
	struct list_head head;

	u_char md5num[16];
	char file[512];
	char degree;
};

struct sec_box_blacklist
{
	int (* init)(void);
	int (* add)(struct sec_box_blacklist_node *node);
	int (* remove)(struct sec_box_blacklist_node *node);
	int (* search)(struct sec_box_blacklist_node *node);
	int (* destroy)(void);
	int (* dump)(void);
};

extern struct sec_box_blacklist sec_box_blacklist;

#endif
