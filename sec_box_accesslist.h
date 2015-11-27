#ifndef __sec_box_accesslist_h__
#define __sec_box_accesslist_h__

#define SEC_BOX_ACCESSLIST_LOG_FILE "/var/log/sec_box_accesslist.log"

#define SEC_BOX_ACCESSLIST_DEGREE_SERIOUS 0
#define SEC_BOX_ACCESSLIST_DEGREE_SLIGHT 1

#define SEC_BOX_ACCESSLIST_HASHTABLE_SIZE 65525
#define SEC_BOX_ACCESSLIST_HASHTABLE_MASK (SEC_BOX_ACCESSLIST_HASHTABLE_SIZE - 1)

enum sec_box_accesslist_rtn{sec_box_accesslist_ok = 0, sec_box_accesslist_error};

struct sec_box_accesslist_node
{
	struct list_head head;

	char path[512];
	char degree;
};

struct sec_box_accesslist
{
	int (* init)(void);
	int (* add)(struct sec_box_accesslist_node *node);
	int (* remove)(struct sec_box_accesslist_node *node);
	int (* search)(struct sec_box_accesslist_node *node);
	int (* destroy)(void);
	int (* dump)(void);
};

extern struct sec_box_accesslist sec_box_accesslist;

#endif
