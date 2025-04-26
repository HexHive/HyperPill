#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");

static int init(void)
{
	printk(KERN_INFO, "dummy_hvc init\n");

	asm volatile("mov x0, 0xdead\n");
	asm volatile("mov x1, 0xbeef\n");
	asm volatile("lsl x0, x0, 16\n");
	asm volatile("orr x0, x0, x1\n");
	asm volatile("hvc #0\n");

	return 0;
}

static void exit(void)
{
	printk(KERN_INFO, "dummy_hvc exit\n");
}

module_init(init);
module_exit(exit);
