#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/security.h>
#include <linux/delay.h>
#include <linux/types.h>
#include <linux/list.h>

#include "sec_box_socket.h"
#include "sec_box_blacklist.h"
#include "sec_box_accesslist.h"
#include "sec_box_swhook.h"

struct security_operations * security_point;


static u_long sec_hook_address = 0xffffffffffffffff;
module_param(sec_hook_address, ulong, 0644);
MODULE_PARM_DESC(sec_hook_address, "u_long security_ops address");

static void show_install_message(void)
{
	printk("sec box version is [%s]. \n", SEC_BOX_VERSION);
}


static int __init sec_box_init(void)
{
	u_long * sec_hook_address_point;

	show_install_message();

	sec_hook_address_point = NULL;
	if (sec_hook_address == 0xffffffffffffffff || sec_hook_address == 0x0)
	{
		printk("insmod argument error.\n");	
		return -1;
	}
	sec_hook_address_point = (u_long *)sec_hook_address;

	security_point = (struct security_operations *)sec_hook_address_point;
	printk("security_point : %p\n", security_point);

	write_cr0(read_cr0() & (~ 0x10000));
	/* set hook */
	sec_box_hook.sethook(security_point);

	write_cr0(read_cr0() | 0x10000);

	sec_box_accesslist.init();
	sec_box_blacklist.init();
	sec_box_socket.handler();

	return 0;
}

static void __exit sec_box_exit(void)
{
	write_cr0(read_cr0() & (~ 0x10000));

	sec_box_hook.resethook(security_point);

	write_cr0(read_cr0() | 0x10000);

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
