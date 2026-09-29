/*
 * dawgfilter - netfilter firewall living below iptables.
 *
 * Hooks register between conntrack and iptables so a red team that flushes or
 * rewrites iptables rules cannot bypass this filter. Packets that pass are
 * delivered manually (dst_output()/state->okfn()) and the hook returns
 * NF_STOLEN, so the remaining (possibly tampered-with) hooks are skipped.
 *
 * Two modes, chosen at compile time (see config.h and the Makefile):
 *
 *   make                -> port-based filtering (classic)
 *   make PROC_MODE=1    -> process-based filtering (defines DAWG_PROC_FILTER)
 *
 * Process mode keeps a table of every socket on the host and the binary that
 * created it. The table is maintained with return probes on sock_alloc_file()
 * (that function runs for socket(2) AND for accept(2)/accept4(2), so accepted
 * server children are attributed to the server binary, not to whoever they
 * were forked from) plus removal probes on sock_close() (userspace close of a
 * socket fd). On insmod, sockets that already exist are seeded by walking
 * every process's fd table, so existing connections survive module load.
 *
 * A packet in LOCAL_OUT/LOCAL_IN does not carry the pid of its sender (the
 * creating process may have exec'd or exited by the time traffic flows), so
 * every socket's creator is recorded at creation time and keyed by the socket
 * inode number (sk->sk_ino), which netfilter can read straight off the skb.
 * Two enforcement flavors:
 *
 *   strict (default): the recorded creator must still exist (start_boottime
 *     guards against pid reuse) and must STILL be running the same binary -
 *     identity is compared as (vfsmount, dentry) of mm->exe_file, so renames,
 *     hardlinks and delete-and-replace are caught. A service that execs into
 *     something else (compromise) loses network access.
 *
 *   loose (insmod ... loose=1): the binary is checked once when the socket is
 *     created and cached; traffic flows even if that process died/restarted
 *     (useful for frequently-restarting services at the cost of not noticing
 *     later identity changes).
 *
 * Notes / limitations:
 *   - Only TCP/UDP over IPv4 is considered; everything else gets DEFAULT_RULE.
 *   - Kernel sockets (created via kern_sendmsg/__sock_create without a struct
 *     file, e.g. in-kernel NFS) are not attributed and get DEFAULT_RULE.
 *   - Only init_net is hooked (same as before).
 *   - get_mm_exe_file()/get_task_exe_file() are not exported to modules, so
 *     the exe lookup below is open-coded: get_task_mm() + get_file_rcu() on
 *     mm->exe_file + mmput_async() (all exported), per kernel/fork.c.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/skbuff.h>
#include <net/route.h>
#include <net/ip.h>
#include "config.h"

#ifdef DAWG_PROC_FILTER

#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/net.h>
#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/cred.h>
#include <linux/namei.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/pid.h>
#include <linux/fdtable.h>
#include <linux/inetdevice.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <net/inet_hashtables.h>
#include <net/udp.h>
#include <net/tcp.h>

/* how often strict mode re-verifies a socket owner (jiffies) */
#define DAWG_RECHECK (HZ)

static bool loose;
module_param(loose, bool, 0600);
MODULE_PARM_DESC(loose,
	"1 = trust the binary that created the socket even if that process died or changed; 0 (default) = require the creator to still be alive and still running the allowed binary");

/* ------------------------------------------------------------------ */
/*  allowed binaries                                                  */
/* ------------------------------------------------------------------ */

struct allowed_bin {
	const char *path;
	struct path resolved;
	bool ok;
};

static struct allowed_bin *allowed_tbl;
static unsigned int allowed_cnt;

static int resolve_allowed(void)
{
	unsigned int i;

	allowed_cnt = ARRAY_SIZE(ALLOWED_BINS);
	if (allowed_cnt == 0) {
		pr_err("dawgfilter: no allowed binaries configured\n");
		return -EINVAL;
	}

	allowed_tbl = kvzalloc(allowed_cnt * sizeof(*allowed_tbl), GFP_KERNEL);
	if (!allowed_tbl)
		return -ENOMEM;

	for (i = 0; i < allowed_cnt; i++) {
		allowed_tbl[i].path = ALLOWED_BINS[i];
		if (kern_path(ALLOWED_BINS[i], LOOKUP_FOLLOW,
			       &allowed_tbl[i].resolved)) {
			pr_warn("dawgfilter: allowed path '%s' not found - entry inactive\n",
				ALLOWED_BINS[i]);
			continue;
		}
		allowed_tbl[i].ok = true;
		pr_info("dawgfilter: allowing binary '%s'\n", ALLOWED_BINS[i]);
	}
	return 0;
}

static void release_allowed(void)
{
	unsigned int i;

	if (!allowed_tbl)
		return;
	for (i = 0; i < allowed_cnt; i++)
		if (allowed_tbl[i].ok)
			path_put(&allowed_tbl[i].resolved);
	kvfree(allowed_tbl);
	allowed_tbl = NULL;
}

static bool path_is_allowed(const struct path *p)
{
	unsigned int i;

	for (i = 0; i < allowed_cnt; i++)
		if (allowed_tbl[i].ok && path_equal(p, &allowed_tbl[i].resolved))
			return true;
	return false;
}

/* ------------------------------------------------------------------ */
/*  socket -> creator table                                           */
/* ------------------------------------------------------------------ */

struct sock_owner {
	struct hlist_node node;		/* linked into sock_hash */
	struct rcu_head rcu;
	u64 ino;			/* socket inode number */
	pid_t tgid;			/* creating process id (global) */
	u64 start_boottime;		/* detects pid reuse */
	bool verdict_ok;		/* cached allow decision */
	unsigned long verdict_jiffies;	/* when the cache was written */
};

static DEFINE_HASHTABLE(sock_hash, 10);
static DEFINE_SPINLOCK(sock_hash_lock);

static inline u32 sock_ino_key(u64 ino)
{
	return hash_64(ino, 32);
}

/* RCU lookup; caller holds rcu_read_lock. */
static struct sock_owner *sock_owner_find(u64 ino)
{
	struct sock_owner *entry;

	hash_for_each_possible_rcu(sock_hash, entry, node, sock_ino_key(ino))
		if (entry->ino == ino)
			return entry;
	return NULL;
}

/* Record sock's creator = @task, with @creator_ok = whether the caller
 * already determined that @task's binary is in the allow list (computed
 * outside this atomic function: mm->exe_file must not be poked here).
 * Safe in atomic context.
 */
static void sock_owner_add(struct socket *sock, struct task_struct *task,
			   bool creator_ok)
{
	struct inode *inode;
	struct sock_owner *entry;
	unsigned long flags;

	if (!sock || !sock->sk)
		return;
	if (sock->sk->sk_family != AF_INET)
		return;

	inode = SOCK_INODE(sock);

	spin_lock_irqsave(&sock_hash_lock, flags);
	if (sock_owner_find(inode->i_ino)) {
		spin_unlock_irqrestore(&sock_hash_lock, flags);
		return; /* socket inode still tracked - leave creator alone */
	}
	spin_unlock_irqrestore(&sock_hash_lock, flags);

	entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
	if (!entry)
		return;
	entry->ino = inode->i_ino;
	entry->tgid = task_tgid_nr(task);
	entry->start_boottime = task->start_time;
	entry->verdict_ok = creator_ok;
	entry->verdict_jiffies = jiffies;

	spin_lock_irqsave(&sock_hash_lock, flags);
	if (!sock_owner_find(entry->ino))
		hash_add(sock_hash, &entry->node, sock_ino_key(entry->ino));
	spin_unlock_irqrestore(&sock_hash_lock, flags);
}

static void sock_owner_del(u64 ino)
{
	struct sock_owner *entry = NULL;
	struct sock_owner *pos;
	unsigned long flags;

	spin_lock_irqsave(&sock_hash_lock, flags);
	hash_for_each_possible(sock_hash, pos, node, sock_ino_key(ino)) {
		if (pos->ino == ino) {
			hash_del(&pos->node);
			entry = pos;
			break;
		}
	}
	spin_unlock_irqrestore(&sock_hash_lock, flags);

	/* kfree_rcu outside the lock: it may allocate */
	if (entry)
		kfree_rcu(entry, rcu);
}

static void sock_owner_del_all(void)
{
	struct sock_owner *entry;
	struct hlist_node *tmp;
	int bkt;
	unsigned long flags;

	/* kfree_rcu is atomic-safe, OK under the lock */
	spin_lock_irqsave(&sock_hash_lock, flags);
	hash_for_each_safe(sock_hash, bkt, tmp, entry, node) {
		hash_del(&entry->node);
		kfree_rcu(entry, rcu);
	}
	spin_unlock_irqrestore(&sock_hash_lock, flags);
}

/*
 * Strict-mode revalidation: the recorded tgids must still exist, still be
 * the same process (start_boottime), and still be running an allowed binary.
 * Open-coded get_task_exe_file(): mm->exe_file is a plain RCU pointer;
 * get_file_rcu() is exported (kernel/fork.c: get_mm_exe_file pattern).
 *
 * Safe from softirq (LOCAL_IN) and process (LOCAL_OUT) context: everything
 * here is atomic-safe; the file reference is dropped after rcu_read_unlock
 * with fput() (task_work deferral makes fput softirq-safe).
 */
static bool entry_revalidate(struct sock_owner *entry)
{
	struct task_struct *task;
	struct mm_struct *mm = NULL;
	struct file *exe = NULL;
	bool allowed = false;

	rcu_read_lock();
	task = pid_task(find_pid_ns(entry->tgid, &init_pid_ns), PIDTYPE_TGID);
	if (task && task->start_time == entry->start_boottime &&
    !(task->flags & PF_KTHREAD)) {
		mm = get_task_mm(task);
		if (mm) {
			exe = rcu_dereference(mm->exe_file);
			if (exe) {
				get_file_rcu(exe);
				allowed = path_is_allowed(&exe->f_path);
			}
		}
	}
	rcu_read_unlock();

	if (exe)
		fput(exe);
	if (mm)
		mmput_async(mm);

	if (!allowed)
		pr_info_ratelimited("dawgfilter: socket ino %llu creator pid %d no longer allowed\n",
				    entry->ino, entry->tgid);

	/* cache the verdict (also for the loose-mode proc display) */
	spin_lock(&sock_hash_lock);
	entry->verdict_ok = allowed;
	entry->verdict_jiffies = jiffies;
	spin_unlock(&sock_hash_lock);

	return allowed;
}

/* Decide whether traffic on the socket owning @sk is allowed. */
static bool sock_owner_allowed(struct sock *sk)
{
	struct sock_owner *entry;
	bool allowed;

	rcu_read_lock();
	entry = sock_owner_find(sock_i_ino(sk));
	if (!entry) {
		rcu_read_unlock();
		return false;
	}
	if (loose ||
	    (time_before(jiffies, READ_ONCE(entry->verdict_jiffies) + DAWG_RECHECK) &&
	     READ_ONCE(entry->verdict_jiffies))) {
		allowed = READ_ONCE(entry->verdict_ok);
		rcu_read_unlock();
	} else {
		rcu_read_unlock();
		allowed = entry_revalidate(entry);
	}
	return allowed;
}

/* ------------------------------------------------------------------ */
/*  probes: socket create/destroy bookkeeping                         */
/* ------------------------------------------------------------------ */

/* entry: sock_alloc_file(struct socket *sock, int flags, const char *dname)
 * Called for socket(2) AND accept(2)/accept4(2). We stash the socket pointer
 * and add the owner on successful return (a failed alloc must not leave an
 * entry behind for a recycled inode number).
 */
static int alloc_file_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct socket **slot = (struct socket **)ri->data;

	*slot = (struct socket *)regs_get_kernel_argument(regs, 0);
	return 0;
}

/* Is the CURRENT process's binary in the allow list?
 * Atomic-safe: current->mm and mm->exe_file are stable while we run in this
 * task's context (same guarantee kernel exec path relies on), so this is the
 * variant usable from the kretprobe handler. The generic-task variant
 * (task_exe_allowed below) is used from sleepable seed code only.
 */
static bool current_exe_allowed(void)
{
	if (current->flags & PF_KTHREAD)
		return false;
	if (!current->mm || !current->mm->exe_file)
		return false;
	return path_is_allowed(&current->mm->exe_file->f_path);
}

static int alloc_file_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct socket *sock = *(struct socket **)ri->data;
	struct file *file = (struct file *)regs_return_value(regs);

	if (!IS_ERR_OR_NULL(file))
		sock_owner_add(sock, current, current_exe_allowed());
	return 0;
}

/* entry: sock_close(struct inode *inode) - file_operations.release for sockets */
static int sock_close_entry(struct kprobe *p, struct pt_regs *regs)
{
	struct inode *inode = (struct inode *)regs_get_kernel_argument(regs, 0);

	if (inode)
		sock_owner_del(inode->i_ino);
	return 0;
}

static struct kretprobe kp_sock_alloc = {
	.kp = { .symbol_name = "sock_alloc_file" },
	.entry_handler = alloc_file_entry,
	.handler = alloc_file_ret,
	.data_size = sizeof(struct socket *),
	.maxactive = 128,
};

static struct kprobe kp_sock_close = {
	.symbol_name = "sock_close",
	.pre_handler = sock_close_entry,
};

static int register_tracking(void)
{
	int ret;

	ret = register_kretprobe(&kp_sock_alloc);
	if (ret < 0) {
		pr_err("dawgfilter: can't probe sock_alloc_file (%d)\n", ret);
		return ret;
	}
	ret = register_kprobe(&kp_sock_close);
	if (ret < 0) {
		pr_err("dawgfilter: can't probe sock_close (%d)\n", ret);
		unregister_kretprobe(&kp_sock_alloc);
		return ret;
	}
	return 0;
}

static void unregister_tracking(void)
{
	unregister_kprobe(&kp_sock_close);
	unregister_kretprobe(&kp_sock_alloc);
}

/* ------------------------------------------------------------------ */
/*  seed sockets that existed before we loaded                        */
/* ------------------------------------------------------------------ */

struct seed_ctx {
	struct task_struct *task;
	bool allowed;	/* task's binary checked before iterate_fd (we are
			 * atomic inside the callback, so the mm->exe_file
			 * read happens here in sleepable-ish context) */
};

static int seed_file_cb(const void *data, struct file *file, unsigned int fd)
{
	const struct seed_ctx *ctx = data;
	struct socket *sock;
	int err;

	sock = sock_from_file(file, &err);
	if (sock)
		sock_owner_add(sock, ctx->task, ctx->allowed);
	return 0;
}

/* Open-coded get_task_exe_file(): get_task_mm() + get_file_rcu on
 * mm->exe_file. Only called from seed_existing_sockets (sleepable).
 */
static bool task_exe_allowed(struct task_struct *task)
{
	struct mm_struct *mm;
	struct file *exe;
	bool allowed = false;

	if (task->flags & PF_KTHREAD)
		return false;

	mm = get_task_mm(task);
	if (!mm)
		return false;

	rcu_read_lock();
	exe = rcu_dereference(mm->exe_file);
	if (exe)
		get_file_rcu(exe);
	rcu_read_unlock();
	if (exe) {
		allowed = path_is_allowed(&exe->f_path);
		fput(exe); /* atomic-safe: deferred via task_work */
	}
	mmput_async(mm); /* caller holds rcu_read_lock; mmput may sleep */
	return allowed;
}

static void seed_existing_sockets(void)
{
	struct task_struct *p;

	rcu_read_lock();
	for_each_process(p) {
		struct seed_ctx ctx;

		if (!thread_group_leader(p))
			continue; /* threads share the fd table */

		ctx.task = p;
		/* compute the verdict BEFORE task_lock/iterate_fd, which are
		 * atomic; get_task_mm/get_file_rcu themselves are fine in rcu
		 */
		ctx.allowed = task_exe_allowed(p);

		task_lock(p);
		if (p->files)
			/* iterate_fd is atomic-safe (takes file_lock internally) */
			iterate_fd(p->files, 0, seed_file_cb, &ctx);
		task_unlock(p);
	}
	rcu_read_unlock();
	pr_info("dawgfilter: seeded pre-existing sockets\n");
}

/* ------------------------------------------------------------------ */
/*  hooks                                                             */
/* ------------------------------------------------------------------ */

static unsigned int hook_out_proc(void *priv, struct sk_buff *skb,
				  const struct nf_hook_state *state)
{
	struct sock *sk = skb_to_full_sk(skb);

	if (!sk || !sock_owner_allowed(sk))
		return DEFAULT_RULE;

	dst_output(state->net, skb->sk, skb);
	return NF_STOLEN;
}

/*
 * On LOCAL_IN the stack may not have attached the socket to the skb (early
 * demux is per-netns sysctl and skipped for the first packets of a flow), so
 * do the same socket lookup the transport layer would do, then decide on the
 * socket's owner and release our temporary reference.
 */
static struct sock *lookup_inbound_sock(struct sk_buff *skb,
					const struct nf_hook_state *state)
{
	const struct iphdr *iph = ip_hdr(skb);

	switch (iph->protocol) {
	case IPPROTO_TCP: {
		const struct tcphdr *th;

		if (!pskb_may_pull(skb, skb_transport_offset(skb) +
						sizeof(struct tcphdr)))
			return NULL;
		th = tcp_hdr(skb);
		if (th->doff < sizeof(struct tcphdr) / 4)
			return NULL;
		/* refcounted result (inet_lookup() pins listeners for us) */
		return inet_lookup(state->net, &tcp_hashinfo, skb, th->doff * 4,
		                   iph->saddr, th->source,
		                   iph->daddr, th->dest, inet_iif(skb));
	}
	case IPPROTO_UDP: {
		const struct udphdr *uh;

		if (!pskb_may_pull(skb, skb_transport_offset(skb) +
						sizeof(struct udphdr)))
			return NULL;
		uh = udp_hdr(skb);
		return udp4_lib_lookup(state->net, iph->saddr, uh->source,
				       iph->daddr, uh->dest, inet_iif(skb));
	}
	default:
		return NULL;
	}
}

static unsigned int hook_in_proc(void *priv, struct sk_buff *skb,
				 const struct nf_hook_state *state)
{
	const struct iphdr *iph = ip_hdr(skb);
	struct sock *sk;
	bool allowed;

	if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
		return DEFAULT_RULE;

	sk = skb_to_full_sk(skb);
	if (sk && net_eq(sock_net(sk), state->net)) {
		allowed = sock_owner_allowed(sk);
	} else {
		sk = lookup_inbound_sock(skb, state);
		if (!sk)
			return DEFAULT_RULE;
		allowed = sock_owner_allowed(sk);
		sock_gen_put(sk);
	}

	if (!allowed)
		return DEFAULT_RULE;

	state->okfn(state->net, skb->sk, skb);
	return NF_STOLEN;
}

/* ------------------------------------------------------------------ */
/*  /proc/dawgfilter: status + reseed                                 */
/* ------------------------------------------------------------------ */

static int dawg_show(struct seq_file *f, void *v)
{
	struct sock_owner *entry;
	int bkt;
	int n = 0;

	seq_printf(f, "%-12s %-8s %-8s %s\n", "SOCKET-INO", "PID", "STATE", "");
	rcu_read_lock();
	hash_for_each_rcu(sock_hash, bkt, entry, node) {
		n++;
		seq_printf(f, "%-12llu %-8d %-8s\n",
			   entry->ino, entry->tgid,
			   loose ? "loose" :
			   (READ_ONCE(entry->verdict_ok) ? "allowed" : "stale"));
	}
	rcu_read_unlock();
	seq_printf(f, "\nsockets tracked: %d (loose=%d)\n", n, loose);
	seq_printf(f, "missed kretprobes: %lu\n",
		   (unsigned long)kp_sock_alloc.nmissed);
	return 0;
}

static int dawg_open(struct inode *inode, struct file *file)
{
	return single_open(file, dawg_show, NULL);
}

static ssize_t dawg_write(struct file *file, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	char kbuf[16];
	size_t n = min(count, sizeof(kbuf) - 1);

	if (copy_from_user(kbuf, buf, n))
		return -EFAULT;
	kbuf[n] = '\0';

	if (sysfs_streq(kbuf, "reload")) {
		unsigned int i;

		pr_info("dawgfilter: re-resolving allowed paths and re-seeding\n");
		for (i = 0; i < allowed_cnt; i++)
			if (allowed_tbl[i].ok)
				path_put(&allowed_tbl[i].resolved);
		release_allowed();
		if (resolve_allowed())
			return -EIO;
		sock_owner_del_all();
		seed_existing_sockets();
	}
	return count;
}

static const struct file_operations dawg_pops = {
	.open		= dawg_open,
	.read		= seq_read,
	.write		= dawg_write,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static struct proc_dir_entry *proc_entry;

/* ------------------------------------------------------------------ */
/*  init/exit                                                         */
/* ------------------------------------------------------------------ */

static struct nf_hook_ops nfho_in;
static struct nf_hook_ops nfho_out;

static int __init nf_dawg_init(void)
{
	int ret;

	ret = resolve_allowed();
	if (ret)
		return ret;

	ret = register_tracking();
	if (ret)
		goto err_allowed;

	seed_existing_sockets();

	nfho_out.hook = hook_out_proc;
	nfho_out.hooknum = NF_INET_LOCAL_OUT;
	nfho_out.pf = NFPROTO_IPV4;
	/* between conntrack and iptables so flushed iptables can't bypass us */
	nfho_out.priority = NF_IP_PRI_CONNTRACK + 1;
	ret = nf_register_net_hook(&init_net, &nfho_out);
	if (ret)
		goto err_track;

	nfho_in.hook = hook_in_proc;
	nfho_in.hooknum = NF_INET_LOCAL_IN;
	nfho_in.pf = NFPROTO_IPV4;
	nfho_in.priority = NF_IP_PRI_CONNTRACK + 1;
	ret = nf_register_net_hook(&init_net, &nfho_in);
	if (ret)
		goto err_out_hook;

	proc_entry = proc_create("dawgfilter", 0600, NULL, &dawg_pops);

	pr_info("dawgfilter: loaded in PROCESS mode (%s)\n",
		loose ? "loose" : "strict");
	return 0;

err_out_hook:
	nf_unregister_net_hook(&init_net, &nfho_out);
err_track:
	unregister_tracking();
err_allowed:
	release_allowed();
	return ret;
}

static void __exit nf_dawg_exit(void)
{
	if (proc_entry)
		proc_remove(proc_entry);
	nf_unregister_net_hook(&init_net, &nfho_out);
	nf_unregister_net_hook(&init_net, &nfho_in);
	unregister_tracking();
	sock_owner_del_all();
	release_allowed();
	pr_info("dawgfilter: unloaded\n");
}

module_init(nf_dawg_init);
module_exit(nf_dawg_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("netfilter firewall below iptables (process mode)");

#else /* ==================== classic port-based mode ==================== */

//netfilter hooks
static struct nf_hook_ops nfho_in;
static struct nf_hook_ops nfho_out;

//main OUTPUT hook func
static unsigned int hook_out(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
	//tcp/ip headers
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct udphdr *udph;

	iph = ip_hdr(skb);

	//accept if not TCP
	if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP){
		pr_info("Unkown Out: %d\n", iph->protocol);
		return DEFAULT_RULE;
	}

  int src_port_tcp;
  int src_port_udp;
  int dst_port_tcp;
  int dst_port_udp;
  int length_in;
  int length_out;
  int i;
  if(iph->protocol == IPPROTO_TCP){
	  tcph = tcp_hdr(skb);
    src_port_tcp = ntohs(tcph->source);
    dst_port_tcp = ntohs(tcph->dest);
    length_out = sizeof(OUT_PORTS_TCP) / sizeof(OUT_PORTS_TCP[0]);
    length_in = sizeof(IN_PORTS_TCP) / sizeof(IN_PORTS_TCP[0]);
	for(i = 0; i < length_out; i++){
		if(dst_port_tcp == OUT_PORTS_TCP[i]){
			dst_output(state->net, skb->sk, skb);
			return NF_STOLEN;
		}
	}
	for(i = 0; i < length_in; i++){
		if(src_port_tcp == IN_PORTS_TCP[i]){
			dst_output(state->net, skb->sk, skb);
			return NF_STOLEN;
		}
	}
	return DEFAULT_RULE;
  }else if (iph->protocol == IPPROTO_UDP){
    udph = udp_hdr(skb);
    src_port_udp = ntohs(udph->source);
    dst_port_udp = ntohs(udph->dest);
    length_out = sizeof(OUT_PORTS_UDP) / sizeof(OUT_PORTS_UDP[0]);
    length_in = sizeof(IN_PORTS_UDP) / sizeof(IN_PORTS_UDP[0]);

	for(i = 0; i < length_in; i++){
		if(src_port_udp == IN_PORTS_UDP[i]){
			dst_output(state->net, skb->sk, skb);
			return NF_STOLEN;
		}
	}
	for(i = 0; i < length_out; i++){
		if(dst_port_udp == OUT_PORTS_UDP[i]){
			dst_output(state->net, skb->sk, skb);
			return NF_STOLEN;
		}
	}
	return DEFAULT_RULE;
  }

	return DEFAULT_RULE;
}

//main INPUT hook func
static unsigned int hook_in(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
	//tcp/ip headers
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct udphdr *udph;

	iph = ip_hdr(skb);

	//accept if not TCP
	if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP){
		pr_info("Unkown In: %d\n", iph->protocol);
		return DEFAULT_RULE;
	}

  int src_port_tcp;
  int src_port_udp;
  int dst_port_tcp;
  int dst_port_udp;
  int length_in;
  int length_out;
  int i;
  if(iph->protocol == IPPROTO_TCP){
	  tcph = tcp_hdr(skb);
    src_port_tcp = ntohs(tcph->source);
    dst_port_tcp = ntohs(tcph->dest);
    length_in = sizeof(IN_PORTS_TCP) / sizeof(IN_PORTS_TCP[0]);
    length_out = sizeof(OUT_PORTS_TCP) / sizeof(OUT_PORTS_TCP[0]);
	for(i = 0; i < length_in; i++){
		if(dst_port_tcp == IN_PORTS_TCP[i]){
			state->okfn(state->net, skb->sk, skb);
			return NF_STOLEN;
		}
	}
	for(i = 0; i < length_out; i++){
		if(src_port_tcp == OUT_PORTS_TCP[i]){
			state->okfn(state->net, skb->sk, skb);
			return NF_STOLEN;
		}
	}
	return DEFAULT_RULE;

  }else if (iph->protocol == IPPROTO_UDP){
    udph = udp_hdr(skb);
    src_port_udp = ntohs(udph->source);
    dst_port_udp = ntohs(udph->dest);
    length_in = sizeof(IN_PORTS_UDP) / sizeof(IN_PORTS_UDP[0]);
    length_out = sizeof(OUT_PORTS_UDP) / sizeof(OUT_PORTS_UDP[0]);
	for(i = 0; i < length_in; i++){
		if(dst_port_udp == IN_PORTS_UDP[i]){
			state->okfn(state->net, skb->sk, skb);
			return NF_STOLEN;
		}
	}
	for(i = 0; i < length_out; i++){
		if(src_port_udp == OUT_PORTS_UDP[i]){
			state->okfn(state->net, skb->sk, skb);
			return NF_STOLEN;
		}
	}
	return DEFAULT_RULE;

  }

	return DEFAULT_RULE;
}

//set hook prio and chain
static int __init nf_dawg_init(void){
	nfho_out.hook = hook_out;
	nfho_out.hooknum = NF_INET_LOCAL_OUT;
	nfho_out.pf = NFPROTO_IPV4;
	//hook prio has to be between conntrack and iptables for this to work
	nfho_out.priority = NF_IP_PRI_CONNTRACK + 1;
	nf_register_net_hook(&init_net, &nfho_out);

	nfho_in.hook = hook_in;
	nfho_in.hooknum = NF_INET_LOCAL_IN;
	nfho_in.pf = NFPROTO_IPV4;
	//hook prio has to be between conntrack and iptables for this to work
	nfho_in.priority = NF_IP_PRI_CONNTRACK + 1;
	nf_register_net_hook(&init_net, &nfho_in);

	pr_info("dawgfilter: loaded\n");
	return 0;
}

static void __exit nf_dawg_exit(void){
	nf_unregister_net_hook(&init_net, &nfho_out);
	nf_unregister_net_hook(&init_net, &nfho_in);
	pr_info("dawgfilter: unloaded\n");
}

module_init(nf_dawg_init);
module_exit(nf_dawg_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("systemd filterd");

#endif /* DAWG_PROC_FILTER */
