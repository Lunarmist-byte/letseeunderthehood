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
static struct proc_dir_entry *proc_ent;

static void ring_push(const struct reg_event *ev)
{
    unsigned long flags;
    spin_lock_irqsave(&ring_lock,flags);
    ring[ring_head]=*ev;
    ring_head=(ring_head+1)&(LOG_ENTRIES-1);
    spin_unlock_irqestore(&ring_lock,flags);
}
static int regwatch_proc_show(struct seq_file *m,void *v)
{
    unsigned int i;
    unsigned long flags;
    spin_lock_irqsave(&ring_lock,flags);
    for(i=0;i<LOG_ENTRIES;++i){
        struct reg_event *e=&ring[i];
        if(e->ts==0)
            continue;
        seq_printf(m,"%llu.%09llu pid=%d comm=%s cpu=%d type=%c addr=0x%lx "
            "val_lo=0x%llx val_hi=0x%llx\n",(unsigned long long)ktime_to_ns(e->ts)/1000000000ULL,
            (unsigned long long)ktime_to_ns(e->ts) % 1000000000ULL,
            e->pid, e->comm, e->cpu, e->type, e->addr,
            (unsigned long long)e->val_lo,
            (unsigned long long)e->val_hi);
    }
    spin_unlock_irqrestore(&ring_lock,flags);
    return 0;
    }
    
}
