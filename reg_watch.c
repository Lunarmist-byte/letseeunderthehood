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

if(nl_sk){
    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    int dst_pid=0; //*broadcast to all or single if pid known*
    skb=nlmsg_new(len,GFP_ATOMIC);
    if(skb){
        nlh=nlmsg_put(skb,0,0,NLMSG_DONE,len,0);
        if(!nlh){
            kfree_skb(skb);
        }else{
            memcpy(nlmsg_data(nlh),msg,len);
            /* send to userspace: multicast to groups 0 (no groups) - use nlmsg_unicast for simplicity if dst_pid known.*/
            /* Here we do a simple netlink_broadcast so any listening processes get it if they joined the group (group 0 won't be listed).*/
        rtnl_lock();
        netlink_broadcast(nl_sk,skb,0,0,GFP_ATOMIC);
        rtnl_unlock();
        }
    }

}
}

static int proc_show(struct seq_file *m,void *v)
{
    unsigned int i;
    unsigned long flags;
    spin_lock_irqsave(&ring_lock,flags);
    for(i=0;i<RING_SIZE;++i){
        struct reg_event *e=&ring[i];
        if(e->ts==0) continue;
        seq_printf(m, "%llu pid=%d tgid=%d uid=%u comm=%s cpu=%d type=%c addr=0x%lx vlo=0x%llx vhi=0x%llx rip=0x%lx rax=0x%lx rbp=0x%lx rsp=0x%lx\n",
                   (unsigned long long)ktime_to_ns(e->ts),
                   e->pid, e->tgid, __kuid_val(e->uid), e->comm, e->cpu, e->type, e->addr,
                   (unsigned long long)e->val_lo, (unsigned long long)e->val_hi, e->regs_rip, e->regs_rax, e->regs_rbp, e->regs_rsp);
    }
    spin_unlock_irqrestore(&ring_lock,flags);
    return 0;
}
static int proc_open(struct inode *inode,struct file *file){
    return single_open(file,proc_show,NULL);
}
static const struct proc_ops proc_ops={
    .proc_open=proc_open,
    .proc_read=seq_read,
    .proc_lseek=seq_lseek,
    .proc_release=single_release,
};

static void fill_regs_snapshot(struct reg_event *ev,struct pt_regs *regs){/*capture basic snapshot*/
    #if defined(CONFIG_X86_64) || defined(CONFIG_X86)
        if(regs){
    #if defined(CONFIG_X86_64)
        ev->regs_rip=regs->ip;
        ev->regs_rax=regs->ax;
        ev->regs_rbx=regs->bx;
        ev->regs_rcx=regs->cx;
        ev->regs_rdx=regs->dx;
        ev->regs_rsp=regs->sp;
        ev->regs_rbp=regs->bp;
#else
        ev->regs_rip=regs->ip;
        ev->regs_rax=regs->ax;
        ev->regs_rbx=regs->bx;
        ev->regs_rcx=regs->cx;
        ev->regs_rdx=regs->dx;
        ev->regs_rsp=regs->sp;
        ev->regs_rbp=regs->bp;
#endif
    } else {
        ev->regs_rip=0;
        ev->regs_rax=0;
        ev->regs_rbx=0;
        ev->regs_rcx=0;
        ev->regs_rdx=0;
        ev->regs_rsp=0;
        ev->regs_rbp=0;
    }
#else
    /* Not supported arch so all are 0 out */
    ev->regs_rip=ev->regs_rax=ev->regs_rbx=ev->regs_rcx=ev->regs_rdx=ev->regs_rsp=ev->regs_rbp=0;
#endif
}
//Probe handlers with set of possible MSR helper names
static const char *msr_read_symbols[]={
    "do_rdmsr",
    "rdmsr_safe",
    "native_read_msr",
    "do_read_msr"//common ones
};
static const char *msr_write_symbols[]={
    "do_wrmsr",
    "wrmsr_safe",
    "native_write_msr",
    "do_write_msr"
};
//kprobes for input pre-handling and kretprobes for capturing o/p
static int generic_pre_msr(struct kprobe *p,struct pt_regs *regs){//probes where i/p args 
    struct reg_event ev;
    memset(&ev,0,sizeof(ev));
    ev.ts=ktime_get();
    ev.pid=current->pid;
    ev.tgid=current->tgid;
    ev.uid=current_uid();
    get_task_comm(ev.comm,current);
    ev.cpu=smp_processor_id();
    ev.type='M';
#if defined(CONFIG_X86_64) || defined(CONFIG_X86)
    ev.addr=(unsigned long)regs->cx;//msr index in ecx
    ev.val_ho=(unsigned long long)regs->ax;
    ev.val_hi=(unsigned long long)regs->dx;
#endif
    fill_regs_snapshot(&ev,regs);
    push_event_and_notify(&ev);
    return 0;
}
static int msr_write_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct reg_event ev;
    memset(&ev,0,sizeof(ev));
    
}

}

    
