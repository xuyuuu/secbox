#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/security.h>
#include <linux/delay.h>
#include <linux/jiffies.h>
#include <linux/types.h>
#include <linux/list.h>

#include "sec_box_socket.h"
#include "sec_box_blacklist.h"
#include "sec_box_accesslist.h"
#include "sec_box_swhook.h"

struct security_operations * security_point;

u_long sec_box_module_timestamp;

#ifdef __32bit__
static u_int sec_hook_address= 0xffffffff;
module_param(sec_hook_address, u_int, 0644);
MODULE_PARM_DESC(sec_hook_address, "u_int security_ops address");
#endif

#ifdef __64bit__
static u_long sec_hook_address = 0xffffffffffffffff;
module_param(sec_hook_address, ulong, 0644);
MODULE_PARM_DESC(sec_hook_address, "u_long security_ops address");
#endif

static void show_install_message(void)
{
	printk("sec box version is [%s]. \n", SEC_BOX_VERSION);
}


static int __init sec_box_init(void)
{
#ifdef __64bit__
	u_long * sec_hook_address_point;
#else
	u_int * sec_hook_address_point;
#endif
	ulong cr0;
	sec_box_module_timestamp = jiffies;

	show_install_message();

#ifdef __64bit__
	sec_hook_address_point = NULL;
	if (sec_hook_address == 0xffffffffffffffff || sec_hook_address == 0x0)
	{
		printk("insmod argument error.\n");	
		return -1;
	}
	sec_hook_address_point = (u_long *)sec_hook_address;
#else
	sec_hook_address_point = NULL;
	if (sec_hook_address == 0xffffffff || sec_hook_address == 0x0)
	{
		printk("insmod argument error. \n");	
		return -1;
	}
	sec_hook_address_point = (u_int *)sec_hook_address;
#endif

	security_point = (struct security_operations *)sec_hook_address_point;
	printk("security_point : %p\n", security_point);

	/*open save switch*/
	cr0 = sec_box_hook.clear();
	/* set hook */
	sec_box_hook.sethook(security_point);
	sec_box_hook.recover(cr0);

	sec_box_accesslist.init();
	sec_box_blacklist.init();
	sec_box_socket.handler();

	return 0;
}

static void __exit sec_box_exit(void)
{
	ulong cr0;
	cr0 = sec_box_hook.clear();
	sec_box_hook.resethook(security_point);
	sec_box_hook.recover(cr0);

	sec_box_socket.destroy();
	printk("release socket source success.\n");
	sec_box_blacklist.destroy();
	printk("release blacklist source success. \n");
	sec_box_accesslist.destroy();
	printk("release accesslist source success. \n");
}



/* initiation module */
module_init(sec_box_init);
/* exit module */
module_exit(sec_box_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Linux Security Module");
