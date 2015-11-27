#include <linux/list.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/string.h>

#include "sec_box_accesslist.h"

struct sec_box_accesslist sec_box_accesslist;
static struct list_head sec_box_accesslist_head[SEC_BOX_ACCESSLIST_HASHTABLE_SIZE];

static int sec_box_accesslist_timer33(char * path, int len)
{
	int i;
        size_t hash = 0;
        for (i = 0; i < len; i++)
                hash = ((hash << 5) + hash) + (size_t)path[i];
	
	return hash % SEC_BOX_ACCESSLIST_HASHTABLE_MASK;
}

static int sec_box_accesslist_init(void)
{
	int i;
	for (i = 0; i < SEC_BOX_ACCESSLIST_HASHTABLE_SIZE; i++)
	{
		INIT_LIST_HEAD(&sec_box_accesslist_head[i]);
	}

	return 0;
}

static int sec_box_accesslist_add(struct sec_box_accesslist_node *node)
{
	int h = sec_box_accesslist_timer33(node->path, strlen(node->path));
	list_add_tail(&node->head, &sec_box_accesslist_head[h]);

	return 0;
}


static int sec_box_accesslist_remove(struct sec_box_accesslist_node *node)
{
	int rtn = sec_box_accesslist_ok;
	struct sec_box_accesslist_node *item, *nxt;
	int h = sec_box_accesslist_timer33(node->path, strlen(node->path));	

	list_for_each_entry_safe(item, nxt, &sec_box_accesslist_head[h], head)
	{
		if (!strncasecmp(item->path, node->path, strlen(node->path)))	
		{
			list_del(&item->head);
			kfree(item);
			goto out;
		}
	}
	rtn = sec_box_accesslist_error;
out:
	return rtn;
}

static int sec_box_accesslist_search(struct sec_box_accesslist_node *node)
{
	int rtn = sec_box_accesslist_ok;
	struct sec_box_accesslist_node *item;
	int h = sec_box_accesslist_timer33(node->path, strlen(node->path));

	list_for_each_entry(item, &sec_box_accesslist_head[h], head)
	{
		if (!strncasecmp(item->path, \
			node->path, strlen(node->path)) && (item->degree == node->degree))	
			goto out;
	}
	rtn = sec_box_accesslist_error;

out:
	return rtn;
}

static int sec_box_accesslist_destroy(void)
{
	int i;
	struct sec_box_accesslist_node *item, *nxt;
	for (i = 0; i < SEC_BOX_ACCESSLIST_HASHTABLE_SIZE; i++)
	{
		list_for_each_entry_safe(item, nxt, &sec_box_accesslist_head[i], head)
		{
			list_del(&item->head);	
			kfree(item);
		}
	}

	return 0;
}

static int sec_box_accesslist_dump(void)
{
	int i;
	mm_segment_t oldfs;
	loff_t oldpos;
	struct sec_box_accesslist_node *item = NULL;
	struct file *tmpf = NULL;
	char kern_buff[1024], *point;

	tmpf = filp_open(SEC_BOX_ACCESSLIST_LOG_FILE, O_RDWR | O_CREAT | O_TRUNC, 0);
	if(IS_ERR(tmpf))
	{
		tmpf = NULL;
		printk("sec_box_accesslist_dump has error in filp_open .\n");	
		goto out;
	}
	oldfs = get_fs();
	set_fs(KERNEL_DS);
	oldpos = tmpf->f_pos;
	tmpf->f_pos = 0;

	for (i = 0; i < SEC_BOX_ACCESSLIST_HASHTABLE_SIZE; i++)
	{
		if (list_empty(&sec_box_accesslist_head[i]))
			continue;
		list_for_each_entry(item, &sec_box_accesslist_head[i], head)
		{
			memset(kern_buff, 0, sizeof(kern_buff));
			strncpy(kern_buff, item->path, strlen(item->path));

			point = kern_buff;
			point += strlen(kern_buff);
			*point++ = '\t';
			*point++ = item->degree + '0';
			*point = '\n';
			tmpf->f_op->write(tmpf, kern_buff, strlen(kern_buff),&tmpf->f_pos);
		}
	}

	tmpf->f_pos = oldpos;
	set_fs(oldfs);

out:
	if (tmpf)
		filp_close(tmpf, 0);

	return 0;
}

__attribute__((constructor))
int sec_box_accesslist_module_init(void)
{
	sec_box_accesslist.init		= sec_box_accesslist_init;	
	sec_box_accesslist.add		= sec_box_accesslist_add;
	sec_box_accesslist.remove	= sec_box_accesslist_remove;
	sec_box_accesslist.search	= sec_box_accesslist_search;
	sec_box_accesslist.destroy	= sec_box_accesslist_destroy;
	sec_box_accesslist.dump		= sec_box_accesslist_dump;

	return 0;
}

/* can`t init in kernel module
struct sec_box_accesslist sec_box_accesslist
{
	.init		= sec_box_accesslist_init,
	.add		= sec_box_accesslist_add,
	.remove		= sec_box_accesslist_remove,
	.search		= sec_box_accesslist_search,
	.destroy	= sec_box_accesslist_destroy,
};
*/

