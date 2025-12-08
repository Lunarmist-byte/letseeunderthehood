//LKM to probe rdmsr/wrsmr and ioread/iowrite only for linux
#include<linux/module.h>
#include<linux/kernel.h>
#include<linux/kprobes.h>
#include<linux/ktime.h>
#include<linux/sched.h>
#include<linux/uaccess.h>
#include<linux/proc_fs.h>
#include<seq_file.h>
#include<linux/spinlock.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Lunarmist-byte")
MODULE_DESCRIPTION("log MSR and IO/MMIO accesses via kprobes")
#define LOG_ENTRIES 4096
struct reg_event{
    ktime_t ts;
    pid_t pid;
    char comm[TASK_COMM_LEN];
    int cpu;
    char type;//"M for MSR I FOR IO, R FOR READ, W FOR WRITE"
    unsigned long addr;//index/port/addr
    unsigned long long val_ho;
    unsigned long long val_hi;

};
static struct reg_event *ring;
static unsigned int ring_head;
static spinlock_t ring_lock;

