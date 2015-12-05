#include <linux/list.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <asm/uaccess.h>

#include "sec_box_tcpstat.h"

struct sec_box_tcpstat sec_box_tcpstat;
static struct list_head sec_box_tcpstat_head[SEC_BOX_TCPSTAT_HASHTABLE_SIZE];

static int sec_box_tcpstat_simhash(ulong i_node)
{
	return i_node % SEC_BOX_TCPSTAT_HASHTABLE_MASK;
}

static int sec_box_tcpstat_init(void)
{
	int i;
	for (i = 0; i < SEC_BOX_TCPSTAT_HASHTABLE_SIZE; i++)
	{
		INIT_LIST_HEAD(&sec_box_tcpstat_head[i]);
	}

	return 0;
}

static int sec_box_tcpstat_add(struct sec_box_tcpstat_node *node)
{
	int h = sec_box_tcpstat_simhash((ulong)node->i_node);
	list_add_tail(&node->head, &sec_box_tcpstat_head[h]);

	return 0;
}


static int sec_box_tcpstat_remove(ulong *i_node)
{
	int rtn = sec_box_tcpstat_ok;
	struct sec_box_tcpstat_node *item, *nxt;
	int h = sec_box_tcpstat_simhash((ulong)i_node);	

	list_for_each_entry_safe(item, nxt, &sec_box_tcpstat_head[h], head)
	{
		if (*(item->i_node) == *i_node)	
		{
			list_del(&item->head);
			kfree(item);
			goto out;
		}
	}
	rtn = sec_box_tcpstat_error;
out:
	return rtn;
}

static int sec_box_tcpstat_search(ulong *i_node)
{
	int rtn = sec_box_tcpstat_ok;
	struct sec_box_tcpstat_node *item;
	int h = sec_box_tcpstat_simhash((ulong)i_node);

	list_for_each_entry(item, &sec_box_tcpstat_head[h], head)
	{
		if(*(item->i_node) == *i_node)
			goto out;
	}
	rtn = sec_box_tcpstat_error;

out:
	return rtn;
}

static int sec_box_tcpstat_destroy(void)
{
	int i;
	struct sec_box_tcpstat_node *item, *nxt;
	for (i = 0; i < SEC_BOX_TCPSTAT_HASHTABLE_SIZE; i++)
	{
		list_for_each_entry_safe(item, nxt, &sec_box_tcpstat_head[i], head)
		{
			list_del(&item->head);	
			kfree(item);
		}
	}

	return 0;
}

static int sec_box_tcpstat_intostr(ulong i_node, char *str)
{
	int i = 0, j = 0, sz = 0;
	while((sz = i_node / 10) > 0)
	{   
		str[i++] = i_node % 10 + '0'; 
		i_node /= 10; 
	}   
	str[i] = i_node + '0';
	sz = i + 1;

	while(str[i] && i >= j)
	{   
		str[i] = str[i] ^ str[j];
		str[j] = str[i] ^ str[j];
		str[i] = str[i] ^ str[j];
		i--;
		j++;
	}

	return sz;
}

static int sec_box_tcpstat_dump(void)
{
	int i;
	mm_segment_t oldfs;
	loff_t oldpos;
	struct sec_box_tcpstat_node *item = NULL;
	struct file *tmpf = NULL;
	char kern_buff[1024], *point;

	tmpf = filp_open(SEC_BOX_TCPSTAT_LOG_FILE, O_RDWR | O_CREAT | O_TRUNC, 0);
	if(IS_ERR(tmpf))
	{
		tmpf = NULL;
		printk("sec_box_tcpstat_dump has error in filp_open .\n");	
		goto out;
	}
	oldfs = get_fs();
	set_fs(KERNEL_DS);
	oldpos = tmpf->f_pos;
	tmpf->f_pos = 0;

	for (i = 0; i < SEC_BOX_TCPSTAT_HASHTABLE_SIZE; i++)
	{
		if (list_empty(&sec_box_tcpstat_head[i]))
			continue;
		list_for_each_entry(item, &sec_box_tcpstat_head[i], head)
		{
			memset(kern_buff, 0, sizeof(kern_buff));
			sec_box_tcpstat_intostr(*(item->i_node), kern_buff);

			point = kern_buff;
			point += strlen(kern_buff);
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
int sec_box_tcpstat_module_init(void)
{
	sec_box_tcpstat.init		= sec_box_tcpstat_init;	
	sec_box_tcpstat.add		= sec_box_tcpstat_add;
	sec_box_tcpstat.remove		= sec_box_tcpstat_remove;
	sec_box_tcpstat.search		= sec_box_tcpstat_search;
	sec_box_tcpstat.destroy		= sec_box_tcpstat_destroy;
	sec_box_tcpstat.dump		= sec_box_tcpstat_dump;

	return 0;
}
