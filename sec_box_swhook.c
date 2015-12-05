#include <linux/types.h>
#include <linux/fs.h>
#include <linux/security.h>
#include <linux/mount.h>
#include <linux/list.h>
#include <linux/fs_struct.h>
#include <linux/sched.h>
#include <linux/net.h>
#include <asm/current.h>
#include <asm/signal.h>
#include <linux/dcache.h>
#include <linux/fs_struct.h>
#include <linux/stat.h>
//#include <net/inet_common.h>
#include <net/sock.h>

#include "sec_box_swhook.h"
#include "sec_box_blacklist.h"
#include "sec_box_accesslist.h"
#include "sec_box_tcpstat.h"
#include "sec_box_md5sum.h"

struct sec_box_hook sec_box_hook;

/* old hook function point */
static int (* old_bprm_check_security)(struct linux_binprm *bprm);
static int ( *old_file_permission)(struct file *file, int mask);
static int (*old_bprm_set_creds) (struct linux_binprm *bprm);
static int (*old_task_kill) (struct task_struct *p, struct siginfo *info, int sig, u32 secid);
int (*old_inode_create) (struct inode *dir, struct dentry *dentry, int mode);
void (*old_inode_delete) (struct inode *inode);
int (*old_inode_mknod) (struct inode *dir, struct dentry *dentry, int mode, dev_t dev);
int (*old_inode_alloc_security) (struct inode *inode);
void (*old_inode_free_security) (struct inode *inode);


static void (* sec_box_hook_set_fs_root)(struct fs_struct *, struct path *);
typedef void (* pfunc)(struct fs_struct *, struct path *);

/*inside function*/
static int sec_box_hook_inside_inode_alloc_security(struct inode *inode)
{
	struct socket *d_sock = NULL;
	struct sec_box_tcpstat_node *node = NULL;

	if(!inode || IS_ERR(inode))
		goto next;

	if(!S_ISSOCK(inode->i_mode))
		goto next;

	d_sock = SOCKET_I(inode);
	if(IS_ERR(d_sock) || !d_sock)
		goto next;

	node = kmalloc(sizeof(struct sec_box_tcpstat_node), GFP_KERNEL);
	if(!node)
		goto next;

	node->i_node = &inode->i_ino;
	node->socket = d_sock;
	sec_box_tcpstat.add(node);

next:
	return 0;
}

static int sec_box_hook_inside_inode_mknod(struct inode *dir, struct dentry *dentry, int mode, dev_t dev)
{
	return 0;
}

static int sec_box_hook_inside_inode_create(struct inode *dir, struct dentry *dentry, int mode)
{
	return 0;
}

static void sec_box_hook_inside_inode_delete(struct inode *inode)
{
	;
}

static void sec_box_hook_inside_inode_free_security(struct inode *inode)
{
	int ret;
	if(IS_ERR(inode) || !inode)
		goto next;

	if(!S_ISSOCK(inode->i_mode))
		goto next;

	ret = sec_box_tcpstat.search(&inode->i_ino);
	if(sec_box_tcpstat_ok == ret)
	{
		sec_box_tcpstat.remove(&inode->i_ino);
		//printk("------remove sockid : %lu -----\n", inode->i_ino);
	}
next:
	return;
}

static int sec_box_hook_inside_inside_get_fullname(struct path *path, char *d_file, int size)
{
	char tmp_buff[512] = {0}, *p = NULL;
	int rtn = 0;

	if (IS_ERR(path) || !path)
	{
		rtn = -1;	
		goto out;
	}
	
	p = d_path(path, tmp_buff, sizeof(tmp_buff));
	if (IS_ERR(p) || !p)
	{
		rtn = -1;
		goto out;
	}

	strncpy(d_file, p, strlen(p));

out:
	return rtn;
}
static int sec_box_hook_inside_inside_check_permission(struct path *path, int mask)
{
	int rtn = 0;
	struct sec_box_accesslist_node node;
	memset(&node, 0x0, sizeof(node));

	if(sec_box_hook_inside_inside_get_fullname(path, node.path, sizeof(node.path)))
		goto out;

	/* search black  */
	node.degree = 0;
	if(sec_box_accesslist_ok == sec_box_accesslist.search(&node))
	{
		/* disable */
		printk("find blacklist function, permission reject .\n");
		rtn = -1;
		goto out;
	}

out:
	return rtn;
}

static int sec_box_hook_inside_system_chroot(struct fs_struct *fs)
{
#define SEC_BOX_HOOK_INSIDE_SYSTEM_SANDBOX_PATH "/home/xuyong/secbox/sandbox"
	struct file *fp = filp_open(SEC_BOX_HOOK_INSIDE_SYSTEM_SANDBOX_PATH, O_RDONLY, 0);
	if(IS_ERR(fp) || !fp)
	{
		printk("sec_box_hook_inside_system_chroot error0 .\n");
		fp = NULL;	
		goto out;
	}
	if(IS_ERR(fp->f_path.mnt) || !fp->f_path.mnt ||
		IS_ERR(fp->f_path.dentry) || !fp->f_path.dentry)
	{
		printk("sec_box_hook_inside_system_chroot error1 .\n");	
		goto out;
	}
	/*set root */
	//set_fs_root(fs, &fp->f_path);
	sec_box_hook_set_fs_root(fs, &fp->f_path);
out:
	if(fp)
		filp_close(fp, 0);

	return 0;
}

static int sec_box_hook_inside_disable_capability(struct task_struct *task)
{
	int cap, ret;
	rcu_read_lock();
	cap = 0;
	ret = cap_raised(__task_cred(task)->cap_effective, cap);
	rcu_read_unlock();

	return ret;
}

static int sec_box_hook_inside_run_into_sanbox(struct linux_binprm *bprm)
{
	struct task_struct * task = NULL;
	task = current;
	/* chroot */
	sec_box_hook_inside_system_chroot(task->fs);
	/* disable capability */
	sec_box_hook_inside_disable_capability(task);
	return 0;
}


/* new hook function definetion */
static int sec_box_hook_inside_bprm_set_creds(struct linux_binprm *bprm)
{
	//printk("------------run set_creds-------\n");
	return 0;
}

static int sec_box_hook_task_kill(struct task_struct *p, struct siginfo *info, int sig, u32 secid)
{
	struct mm_struct *mm = NULL;
	struct vm_area_struct * mmap = NULL;
	struct file *file = NULL;

	struct sec_box_blacklist_node node;
	memset(&node, 0x0, sizeof(node));
	/*check signal*/
	if(info->si_signo != SIGTERM && info->si_signo != SIGINT &&\
			info->si_signo != SIGKILL && info->si_signo != SIGQUIT)
	{
		/* ignor normal signal */
		goto out;
	}

	mm = p->mm;
	if(IS_ERR(mm) || !mm)
	{
		goto out;
	}
	mmap = mm->mmap;
	if(IS_ERR(mmap) || !mmap)
	{
		goto out;
	}
	file = mmap->vm_file;
	if(IS_ERR(file) || !file)
	{
		goto out;	
	}

	if(sec_box_hook_inside_inside_get_fullname(&file->f_path, node.file, sizeof(node.file)))
	{
		goto out;
	}

	memset(node.md5num, 0x0, sizeof(node.md5num));
	if(sec_box_md5sum.handler(node.file, node.md5num))
	{
		goto out;
	}

	/* search while */
	node.degree = 2;
	if(sec_box_blacklist_ok == sec_box_blacklist.search(&node))
	{
		printk("find protect function, permission don`t allow .\n");	
		return -1;
	}
out:

	return 0;
}

static int sec_box_hook_inside_file_permission(struct file *file, int mask)
{
	int rtn = 0;
	if (!mask || (mask & MAY_EXEC))
		goto out;

	rtn = sec_box_hook_inside_inside_check_permission(&file->f_path, mask);

out:
	return rtn;
}

static int sec_box_hook_inside_bprm_check_security(struct linux_binprm *bprm)
{
	struct file *file = bprm->file;
	struct dentry * tmp_dentry = file->f_path.dentry;

	struct sec_box_blacklist_node node;
	memset(&node, 0x0, sizeof(node));

	if (IS_ERR(tmp_dentry) || !(tmp_dentry))
		goto out;

	if(sec_box_hook_inside_inside_get_fullname(&file->f_path, node.file, sizeof(node.file)))
	{
		goto out;
	}

	memset(node.md5num, 0x0, sizeof(node.md5num));
	if(sec_box_md5sum.handler(node.file, node.md5num))
	{
		goto out;
	}

	/* search black  */
	node.degree = 0;
	if(sec_box_blacklist_ok == sec_box_blacklist.search(&node))
	{
		/* disable */
		printk("find blacklist function, permission reject .\n");
		return -1;
	}

	/* search gray */
	node.degree = 1;
	if(sec_box_blacklist_ok == sec_box_blacklist.search(&node))
	{
		printk("find graylist function, permission allow .\n");
		/* run in sanbox */
		sec_box_hook_inside_run_into_sanbox(bprm);
	}


out:
	return 0;
}

static ulong sec_box_hook_clear_mask(void)
{
	ulong cr0 = 0;	
	ulong ret;
#ifdef __32bit__
	asm volatile("movl %%cr0, %%eax":"=r"(cr0));
#else
	asm volatile("movq %%cr0, %%rax":"=r"(cr0));
#endif
	ret = cr0;
	cr0 &= 0xfffeffff;
#ifdef __32bit__
	asm volatile("movl %%eax, %%cr0"::"r"(cr0));
#else
	asm volatile("movq %%rax, %%cr0"::"r"(cr0));
#endif

	return ret;
}

static void sec_box_hook_recover_mask(ulong val)
{
#ifdef __32bit__
	asm volatile ("movl %%eax, %%cr0"::"a"(val));	
#else
	asm volatile ("movq %%rax, %%cr0"::"a"(val));	
#endif
}

static int sec_box_hook_set_newhook(struct security_operations *security_point)
{
	old_bprm_check_security = security_point->bprm_check_security;
	old_file_permission	= security_point->file_permission;
	old_bprm_set_creds	= security_point->bprm_set_creds;
	old_task_kill		= security_point->task_kill;
	old_inode_create	= security_point->inode_create;
	old_inode_mknod		= security_point->inode_mknod;
	old_inode_alloc_security= security_point->inode_alloc_security;
	old_inode_delete	= security_point->inode_delete;
	old_inode_free_security = security_point->inode_free_security;

	security_point->bprm_check_security = sec_box_hook_inside_bprm_check_security;
	security_point->file_permission     = sec_box_hook_inside_file_permission;
	security_point->bprm_set_creds	    = sec_box_hook_inside_bprm_set_creds;
	security_point->task_kill	    = sec_box_hook_task_kill;
	security_point->inode_create	    = sec_box_hook_inside_inode_create;
	security_point->inode_mknod	    = sec_box_hook_inside_inode_mknod;
	security_point->inode_delete	    = sec_box_hook_inside_inode_delete;
	security_point->inode_alloc_security= sec_box_hook_inside_inode_alloc_security;
	security_point->inode_free_security = sec_box_hook_inside_inode_free_security;

	/*other function point*/
	sec_box_hook_set_fs_root = (pfunc)0xffffffff811bbfe0;

	return 0;
}

static int sec_box_hook_set_oldhook(struct security_operations *security_point)
{
	security_point->bprm_check_security = old_bprm_check_security;
	security_point->file_permission     = old_file_permission;
	security_point->bprm_set_creds	    = old_bprm_set_creds;
	security_point->task_kill	    = old_task_kill;
	security_point->inode_create	    = old_inode_create;
	security_point->inode_mknod	    = old_inode_mknod;
	security_point->inode_alloc_security= old_inode_alloc_security;
	security_point->inode_delete	    = old_inode_delete;
	security_point->inode_free_security = old_inode_free_security;

	return 0;
}

__attribute__((constructor))
int sec_box_hook_module_init(void)
{
	sec_box_hook.clear	= sec_box_hook_clear_mask;	
	sec_box_hook.recover	= sec_box_hook_recover_mask;
	sec_box_hook.sethook	= sec_box_hook_set_newhook;
	sec_box_hook.resethook	= sec_box_hook_set_oldhook;

	return 0;
}

