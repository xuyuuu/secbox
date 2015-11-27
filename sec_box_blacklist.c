#include <linux/list.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <asm/uaccess.h>

#include "sec_box_blacklist.h"

struct sec_box_blacklist sec_box_blacklist;
static struct list_head sec_box_blacklist_head[SEC_BOX_BLACKLIST_HASHTABLE_SIZE];

static int sec_box_blacklist_simhash(u_char * md5num)
{
	u_int *p_md5num;
	p_md5num = (u_int *)md5num;
	
	return (*p_md5num) % SEC_BOX_BLACKLIST_HASHTABLE_MASK;
}

static int sec_box_blacklist_init(void)
{
	int i;
	for (i = 0; i < SEC_BOX_BLACKLIST_HASHTABLE_SIZE; i++)
	{
		INIT_LIST_HEAD(&sec_box_blacklist_head[i]);
	}

	return 0;
}

static int sec_box_blacklist_add(struct sec_box_blacklist_node *node)
{
	int h = sec_box_blacklist_simhash(node->md5num);
	list_add_tail(&node->head, &sec_box_blacklist_head[h]);

	return 0;
}

static int sec_box_blacklist_inside_compare(u_char *pattern1, u_char *pattern2, int len)
{
	int i, rtn;
	for(i = 0; i < len; i++)
	{
		if (pattern1[i] == pattern2[i])	
			continue;
		else if(pattern1[i] > pattern2[i])
		{
			rtn = 1;
			goto err;
		}
		else
		{
			rtn = -1;		
			goto err;
		}
	}
	rtn = 0;
err:
	return rtn;
}

static int sec_box_blacklist_remove(struct sec_box_blacklist_node *node)
{
	int rtn = sec_box_blacklist_ok;
	struct sec_box_blacklist_node *item, *nxt;
	int h = sec_box_blacklist_simhash(node->md5num);	

	list_for_each_entry_safe(item, nxt, &sec_box_blacklist_head[h], head)
	{
		if (!sec_box_blacklist_inside_compare(item->md5num, node->md5num, 16))	
		{
			list_del(&item->head);
			kfree(item);
			goto out;
		}
	}
	rtn = sec_box_blacklist_error;
out:
	return rtn;
}

static int sec_box_blacklist_search(struct sec_box_blacklist_node *node)
{
	int rtn = sec_box_blacklist_ok;
	struct sec_box_blacklist_node *item;
	int h = sec_box_blacklist_simhash(node->md5num);

	list_for_each_entry(item, &sec_box_blacklist_head[h], head)
	{
		if (!sec_box_blacklist_inside_compare(item->md5num, \
			node->md5num, 16) && (item->degree == node->degree))	
			goto out;
	}
	rtn = sec_box_blacklist_error;

out:
	return rtn;
}

static int sec_box_blacklist_destroy(void)
{
	int i;
	struct sec_box_blacklist_node *item, *nxt;
	for (i = 0; i < SEC_BOX_BLACKLIST_HASHTABLE_SIZE; i++)
	{
		list_for_each_entry_safe(item, nxt, &sec_box_blacklist_head[i], head)
		{
			list_del(&item->head);	
			kfree(item);
		}
	}

	return 0;
}

static int sec_box_blacklist_dump(void)
{
	int i;
	mm_segment_t oldfs;
	loff_t oldpos;
	struct sec_box_blacklist_node *item = NULL;
	struct file *tmpf = NULL;
	char kern_buff[1024], *point;

	tmpf = filp_open(SEC_BOX_BLACKLIST_LOG_FILE, O_RDWR | O_CREAT | O_TRUNC, 0);
	if(IS_ERR(tmpf))
	{
		tmpf = NULL;
		printk("sec_box_blacklist_dump has error in filp_open .\n");	
		goto out;
	}
	oldfs = get_fs();
	set_fs(KERNEL_DS);
	oldpos = tmpf->f_pos;
	tmpf->f_pos = 0;

	for (i = 0; i < SEC_BOX_BLACKLIST_HASHTABLE_SIZE; i++)
	{
		if (list_empty(&sec_box_blacklist_head[i]))
			continue;
		list_for_each_entry(item, &sec_box_blacklist_head[i], head)
		{
			memset(kern_buff, 0, sizeof(kern_buff));
			strncpy(kern_buff, item->file, strlen(item->file));

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
int sec_box_blacklist_module_init(void)
{
	sec_box_blacklist.init		= sec_box_blacklist_init;	
	sec_box_blacklist.add		= sec_box_blacklist_add;
	sec_box_blacklist.remove	= sec_box_blacklist_remove;
	sec_box_blacklist.search	= sec_box_blacklist_search;
	sec_box_blacklist.destroy	= sec_box_blacklist_destroy;
	sec_box_blacklist.dump		= sec_box_blacklist_dump;

	return 0;
}

/* can`t init in kernel module
struct sec_box_blacklist sec_box_blacklist
{
	.init		= sec_box_blacklist_init,
	.add		= sec_box_blacklist_add,
	.remove		= sec_box_blacklist_remove,
	.search		= sec_box_blacklist_search,
	.destroy	= sec_box_blacklist_destroy,
};
*/

