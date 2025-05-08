#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>

#define PROC_FILENAME "dummy_hvc"

MODULE_LICENSE("GPL");

static struct proc_dir_entry *proc_file;

static ssize_t proc_write(struct file *file, const char __user *buffer,
			  size_t count, loff_t *pos) {
	char buf[16] = { 0 };

	if (count > sizeof(buf) - 1)
		count = sizeof(buf) - 1;

	if (copy_from_user(buf, buffer, count))
		return -EFAULT;

	buf[count] = '\0';

	if (buf[0] == '1') {
		asm volatile("mov x0, 0xdead\n");
		asm volatile("mov x1, 0xbeef\n");
		asm volatile("lsl x0, x0, 16\n");
		asm volatile("orr x0, x0, x1\n");
		asm volatile("hvc #0\n");
	}

	return count;
}

static const struct proc_ops proc_fops = {
    .proc_write = proc_write,
};

static int __init my_module_init(void) {
	proc_file = proc_create(PROC_FILENAME, 0666, NULL, &proc_fops);
	if (!proc_file) {
		pr_err("Failed to create /proc/%s\n", PROC_FILENAME);
		return -ENOMEM;
	}
	pr_info("dummy_hcv init at /proc/%s\n", PROC_FILENAME);
	return 0;
}

static void __exit my_module_exit(void) {
	proc_remove(proc_file);
	pr_info("dummy_hvc exit\n");
}

module_init(my_module_init);
module_exit(my_module_exit);
