//LKM to probe rdmsr/wrsmr and ioread/iowrite only for linux
#include<linux/module.h>
#include<linux/kernel.h>
#include<linux/kprobes.h>
#include<linux/kretprobe.h>
#include<linux/ktime.h>
#include<linux/sched.h>
#include<linux/uaccess.h>
#include<linux/proc_fs.h>
#include<seq_file.h>
#include<linux/seq_file.h>
#include<linux/slab.h>
#include<linux/netlink.h>
#include<linux/sock.h>
#include<linux/cred.h>
#include<linux/uidgid.h>
#include<linux/vmalloc.h>
#include<asm/processor.h>
#include<linux/spinlock.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Lunarmist-byte")
MODULE_DESCRIPTION("log MSR and IO/MMIO accesses via kprobes")

#define RING_SIZE 8192
#define MAX_MSG_LEN 512
#define NETLINK_REGWATCH 31 /*change as needed arbitiary free protocol no:*/
struct reg_event{
    ktime_t ts;
    pid_t pid;
    pid_t tgid;
    kuid_t uid;
    char comm[TASK_COMM_LEN];
    int cpu;
    char type;//'M' MSR, 'P' Port IO, 'Q' PCI config, 'R' MMIO read, 'W' MMIO write, 'S' snapshot, 'C' syscall, 'F' fault "
    unsigned long addr;//index/port/addr
    unsigned long long val_ho;
    unsigned long long val_hi;
    unsigned long regs_rip,regs_rax,regs_rbx,regs_rcx,regs_rdx,regs_rsp,regs_rbp;

};
static struct reg_event *ring; //ring buffer
static unsigned int ring_head;
static spinlock_t ring_lock;

static struct proc_dir_entry *proc_ent; //proc entry

static struct sock *nl_sk=NULL; //netlink

struct kp_node{ //dynamic kprobe
    struct list_head list;
    struct kprobe kp; //prehandler
};
static LIST_HEAD(kp_list);

static struct kretprobe msr_read_ret_kret; //kretprobe 
static struct kretprobe msr_write_ret_kret;

static void push_event_notify(struct reg_event *e) //for netlink push
{
    unsigned long flags;
    char msg[MAX_MSG_LEN];
    int len;
    spin_lock_irqsave(&ring_lock,flags);
    ring[ring_head]=*e;
    ring_head=(ring_head+1)&(RING_SIZE-1);
    spin_unlock_irqrestore(&ring_lock,flags);

len=snprintf(msg,sizeof(msg),"{\"t\":%llu,\"pid\":%d,\"tgid\":%d,\"uid\":%u,\"comm\":\"%s\",\"cpu\":%d,\"type\":\"%c\",\"addr\":\"0x%lx\",\"vlo\":\"0x%llx\",\"vhi\":\"0x%llx\",\"rip\":\"0x%lx\"}",
(unsigned long long)ktime_to_ns(e->ts),//json o/p
e->pid,e->tgid,__kuid_val(e->uid),e->comm,e->cpu,e->type,e->addr,
(unsigned long long)e->val_lo,(unsigned long long)e->val_hi,e->regs_rip);

if()

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
