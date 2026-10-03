/*
 * filterd - netfilter firewall living below iptables.
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
 *     mm->exe_file + dawg_mmput_async() (a local mmput_async(), which is not
 *     exported on 4.18), per kernel/fork.c.
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
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/workqueue.h>
#include <linux/err.h>
#include <linux/version.h>

/* ------------------------------------------------------------------ */
/*  compat shims for RHEL/CentOS 8 (4.18) vs newer kernels            */
/* ------------------------------------------------------------------ */

/*
 * regs_get_kernel_argument() only exists since 4.20; RHEL 8's 4.18 lacks it.
 * We only ever need argument 0 (the first integer/pointer argument).
 */
static inline unsigned long dawg_regs_arg0(struct pt_regs *regs)
{
#if defined(__x86_64__)
	return regs->di;		/* SysV AMD64: arg0 in %rdi */
#else
	return regs_get_kernel_argument(regs, 0);
#endif
}

/*
 * path_equal() is not guaranteed to be provided by <linux/path.h> on 4.18,
 * so use our own (same semantics: identical vfsmount and dentry).
 */
static inline bool dawg_path_equal(const struct path *a, const struct path *b)
{
	return a->mnt == b->mnt && a->dentry == b->dentry;
}

/*
 * PIDTYPE_TGID was introduced in 4.19. For a thread-group id, the PIDTYPE_PID
 * lookup returns the group leader, which is equivalent for our purposes and
 * exists on every kernel.
 */
#define DAWG_PIDTYPE_TGID PIDTYPE_PID

/*
 * mmput_async() is not exported to modules on 4.18 (the link only warns, then
 * insmod fails with "Unknown symbol"). mmput() IS exported but may sleep when
 * it drops the last reference, and we call this from atomic context. Same
 * trick the kernel uses: drop the reference directly unless it is the last
 * one, in which case hand the final mmput() to a workqueue via the mm's own
 * async_put_work (nobody else touches it while we hold the last reference).
 */
static void dawg_mmput_work(struct work_struct *work)
{
	mmput(container_of(work, struct mm_struct, async_put_work));
}

static void dawg_mmput_async(struct mm_struct *mm)
{
	if (atomic_add_unless(&mm->mm_users, -1, 1))
		return;		/* not the last reference */

	INIT_WORK(&mm->async_put_work, dawg_mmput_work);
	schedule_work(&mm->async_put_work);
}

/* how often strict mode re-verifies a socket owner (jiffies) */
#define DAWG_RECHECK (HZ)

static bool loose;
module_param(loose, bool, 0600);
MODULE_PARM_DESC(loose,
	"1 = trust the binary that created the socket even if that process died or changed; 0 (default) = require the creator to still be alive and still running the allowed binary");

/* ------------------------------------------------------------------ */
/*  allowed binaries (RCU-protected set, swapped atomically on reload) */
/* ------------------------------------------------------------------ */

struct allowed_bin {
	struct path resolved;
	bool ok;
};

struct allowed_set {
	unsigned int cnt;
	struct allowed_bin bins[];
};

static struct allowed_set __rcu *allowed_cur;

/* serialises module init/exit and "reload" writes to /proc/filterd */
static DEFINE_MUTEX(dawg_admin_lock);

static struct allowed_set *build_allowed(void)
{
	struct allowed_set *set;
	unsigned int i, cnt = ARRAY_SIZE(ALLOWED_BINS);

	if (cnt == 0) {
		return ERR_PTR(-EINVAL);
	}

	set = kvzalloc(sizeof(*set) + cnt * sizeof(set->bins[0]), GFP_KERNEL);
	if (!set)
		return ERR_PTR(-ENOMEM);
	set->cnt = cnt;

	for (i = 0; i < cnt; i++) {
		if (kern_path(ALLOWED_BINS[i], LOOKUP_FOLLOW,
			      &set->bins[i].resolved)) {
			continue;
		}
		set->bins[i].ok = true;
	}
	return set;
}

static void free_allowed(struct allowed_set *set)
{
	unsigned int i;

	if (!set)
		return;
	for (i = 0; i < set->cnt; i++)
		if (set->bins[i].ok)
			path_put(&set->bins[i].resolved);
	kvfree(set);
}

/* Publish @set; the previous set is freed only after all readers are done.
 * Caller holds dawg_admin_lock and is in process context. */
static void install_allowed(struct allowed_set *set)
{
	struct allowed_set *old;

	old = rcu_dereference_protected(allowed_cur,
					lockdep_is_held(&dawg_admin_lock));
	rcu_assign_pointer(allowed_cur, set);
	if (old) {
		synchronize_rcu();
		free_allowed(old);
	}
}

static void drop_allowed(void)
{
	install_allowed(NULL);
}

static bool path_is_allowed(const struct path *p)
{
	struct allowed_set *set;
	unsigned int i;
	bool ret = false;

	rcu_read_lock();
	set = rcu_dereference(allowed_cur);
	if (set)
		for (i = 0; i < set->cnt; i++)
			if (set->bins[i].ok &&
			    dawg_path_equal(p, &set->bins[i].resolved)) {
				ret = true;
				break;
			}
	rcu_read_unlock();
	return ret;
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
	unsigned long verdict_jiffies;	/* when the cache was written (0=never) */
};

static DEFINE_HASHTABLE(sock_hash, 10);
static DEFINE_SPINLOCK(sock_hash_lock);

static inline u32 sock_ino_key(u64 ino)
{
	return hash_64(ino, 32);
}

/* RCU lookup; caller holds rcu_read_lock (or sock_hash_lock). */
static struct sock_owner *sock_owner_find(u64 ino)
{
	struct sock_owner *entry;

	hash_for_each_possible_rcu(sock_hash, entry, node, sock_ino_key(ino))
		if (entry->ino == ino)
			return entry;
	return NULL;
}

/* Record sock's creator = @task, with @creator_ok = whether the caller
 * already determined that @task's binary is in the allow list.
 * Safe in atomic context.
 *
 * NOTE: sock_hash_lock is ALWAYS taken with irqsave. The verdict cache is
 * updated locklessly (WRITE_ONCE), so no lock is ever held while a hook
 * can be re-entered from softirq on the same CPU.
 */
static void sock_owner_add(struct socket *sock, struct task_struct *task,
			   bool creator_ok)
{
	struct inode *inode;
	struct sock_owner *entry;
	unsigned long flags;

	if (!sock || !sock->sk)
		return;
	/* AF_INET6 sockets also carry IPv4 (v4-mapped) traffic, e.g. httpd
	 * listening on [::]:80 */
	if (sock->sk->sk_family != AF_INET && sock->sk->sk_family != AF_INET6)
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
	entry->verdict_jiffies = jiffies ? jiffies : 1;

	spin_lock_irqsave(&sock_hash_lock, flags);
	if (!sock_owner_find(entry->ino)) {
		hash_add_rcu(sock_hash, &entry->node, sock_ino_key(entry->ino));
		entry = NULL;
	}
	spin_unlock_irqrestore(&sock_hash_lock, flags);

	kfree(entry);	/* lost the race: free our duplicate (NULL is fine) */
}

static void sock_owner_del(u64 ino)
{
	struct sock_owner *entry = NULL;
	struct sock_owner *pos;
	unsigned long flags;

	spin_lock_irqsave(&sock_hash_lock, flags);
	hash_for_each_possible(sock_hash, pos, node, sock_ino_key(ino)) {
		if (pos->ino == ino) {
			hash_del_rcu(&pos->node);
			entry = pos;
			break;
		}
	}
	spin_unlock_irqrestore(&sock_hash_lock, flags);

	if (entry)
		kfree_rcu(entry, rcu);
}

static void sock_owner_del_all(void)
{
	struct sock_owner *entry;
	struct hlist_node *tmp;
	int bkt;
	unsigned long flags;

	spin_lock_irqsave(&sock_hash_lock, flags);
	hash_for_each_safe(sock_hash, bkt, tmp, entry, node) {
		hash_del_rcu(&entry->node);
		kfree_rcu(entry, rcu);
	}
	spin_unlock_irqrestore(&sock_hash_lock, flags);
}

/*
 * Take a reference on @task's mm WITHOUT ever spinning on task->alloc_lock.
 *
 * get_task_mm() does task_lock(), a plain spin_lock that is not BH-safe. We
 * run from the LOCAL_IN softirq, which can interrupt the very task that
 * already holds its own alloc_lock (exec, exit, prctl, ...) - a guaranteed
 * self-deadlock when the socket creator is the task we interrupted (httpd
 * handling its own traffic). So only trylock; the caller keeps its cached
 * verdict when we report "busy" and simply retries on a later packet.
 */
static struct mm_struct *dawg_try_get_task_mm(struct task_struct *task,
					      bool *busy)
{
	struct mm_struct *mm = NULL;

	if (!spin_trylock(&task->alloc_lock)) {
		*busy = true;
		return NULL;
	}
	if (!(task->flags & PF_KTHREAD)) {
		mm = task->mm;
		if (mm)
			mmget(mm);
	}
	spin_unlock(&task->alloc_lock);
	return mm;
}

/* Caller holds rcu_read_lock. Returns a referenced file or NULL. */
static struct file *dawg_get_exe_file(struct mm_struct *mm)
{
	struct file *exe = rcu_dereference(mm->exe_file);

	if (exe && !get_file_rcu(exe))	/* refcount already hit zero */
		exe = NULL;
	return exe;
}

/*
 * Strict-mode revalidation: the recorded tgid must still exist, still be the
 * same process (start_boottime), and still be running an allowed binary.
 *
 * Caller holds rcu_read_lock (the entry must not be freed under us).
 * Atomic-safe: no sleeping, no spinning on foreign locks. The verdict cache
 * is updated lock-free.
 */
static bool entry_revalidate(struct sock_owner *entry)
{
	struct task_struct *task;
	struct mm_struct *mm = NULL;
	struct file *exe = NULL;
	bool allowed = false;
	bool busy = false;

	task = pid_task(find_pid_ns(entry->tgid, &init_pid_ns),
			DAWG_PIDTYPE_TGID);
	if (task && task->start_time == entry->start_boottime &&
	    !(task->flags & PF_KTHREAD)) {
		mm = dawg_try_get_task_mm(task, &busy);
		if (mm) {
			exe = dawg_get_exe_file(mm);
			if (exe)
				allowed = path_is_allowed(&exe->f_path);
		}
	}

	/* fput() of a possibly-last reference is safe from softirq: it defers
	 * to task_work/delayed_fput there. */
	if (exe)
		fput(exe);
	if (mm)
		dawg_mmput_async(mm);

	if (busy)		/* could not tell - keep previous verdict */
		return READ_ONCE(entry->verdict_ok);


	WRITE_ONCE(entry->verdict_ok, allowed);
	WRITE_ONCE(entry->verdict_jiffies, jiffies ? jiffies : 1);
	return allowed;
}

/* Decide whether traffic on the socket owning @sk is allowed. */
static bool sock_owner_allowed(struct sock *sk)
{
	struct sock_owner *entry;
	unsigned long ino, stamp;
	bool allowed = false;

	/*
	 * Only full sockets: request socks and TIME_WAIT socks are much
	 * smaller than struct sock, and sock_i_ino() would read (and
	 * read_lock_bh()) memory past the end of them.
	 */
	if (!sk || !sk_fullsock(sk))
		return false;

	ino = sock_i_ino(sk);
	if (!ino)
		return false;

	rcu_read_lock();	/* held across revalidation: entry can't vanish */
	entry = sock_owner_find(ino);
	if (entry) {
		stamp = READ_ONCE(entry->verdict_jiffies);
		if (loose || (stamp && time_before(jiffies, stamp + DAWG_RECHECK)))
			allowed = READ_ONCE(entry->verdict_ok);
		else
			allowed = entry_revalidate(entry);
	}
	rcu_read_unlock();
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

	*slot = (struct socket *)dawg_regs_arg0(regs);
	return 0;
}

/* Is the CURRENT process's binary in the allow list? Atomic-safe. */
static bool current_exe_allowed(void)
{
	struct mm_struct *mm = current->mm;
	struct file *exe;
	bool allowed = false;

	if ((current->flags & PF_KTHREAD) || !mm)
		return false;

	rcu_read_lock();
	exe = rcu_dereference(mm->exe_file);
	if (exe)
		allowed = path_is_allowed(&exe->f_path);
	rcu_read_unlock();
	return allowed;
}

static int alloc_file_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct socket *sock = *(struct socket **)ri->data;
	struct file *file = (struct file *)regs_return_value(regs);

	if (sock && !IS_ERR_OR_NULL(file))
		sock_owner_add(sock, current, current_exe_allowed());
	return 0;
}

/* entry: sock_close(struct inode *inode, struct file *filp) */
static int sock_close_entry(struct kprobe *p, struct pt_regs *regs)
{
	struct inode *inode = (struct inode *)dawg_regs_arg0(regs);

	if (inode)
		sock_owner_del(inode->i_ino);
	return 0;
}

static struct kretprobe kp_sock_alloc = {
	.kp = { .symbol_name = "sock_alloc_file" },
	.entry_handler = alloc_file_entry,
	.handler = alloc_file_ret,
	.data_size = sizeof(struct socket *),
	.maxactive = 1024,	/* sock_alloc_file can sleep: allow many in flight */
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
		return ret;
	}
	ret = register_kprobe(&kp_sock_close);
	if (ret < 0) {
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
	bool allowed;
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

/* Process context only (seed_existing_sockets). */
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
	exe = dawg_get_exe_file(mm);
	rcu_read_unlock();
	if (exe) {
		allowed = path_is_allowed(&exe->f_path);
		fput(exe);
	}
	dawg_mmput_async(mm);
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
		ctx.allowed = task_exe_allowed(p);

		task_lock(p);
		if (p->files)
			iterate_fd(p->files, 0, seed_file_cb, &ctx);
		task_unlock(p);
	}
	rcu_read_unlock();
}

/* ------------------------------------------------------------------ */
/*  hooks                                                             */
/* ------------------------------------------------------------------ */

static unsigned int hook_out_proc(void *priv, struct sk_buff *skb,
				  const struct nf_hook_state *state)
{
	const struct iphdr *iph = ip_hdr(skb);
	struct sock *sk;

	if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
		return DEFAULT_RULE;
	if (!skb_dst(skb))	/* dst_output() would oops */
		return DEFAULT_RULE;

	sk = skb_to_full_sk(skb);
	if (!sk || !sock_owner_allowed(sk))
		return DEFAULT_RULE;

	dst_output(state->net, skb->sk, skb);
	return NF_STOLEN;
}

/*
 * On LOCAL_IN the stack may not have attached the socket to the skb, so do
 * the same socket lookup the transport layer would do. The result is
 * refcounted and may be a request sock or TIME_WAIT sock: callers must map
 * it with sk_to_full_sk() and release it with sock_gen_put().
 */
static struct sock *lookup_inbound_sock(struct sk_buff *skb,
					const struct nf_hook_state *state)
{
	const struct iphdr *iph;

	switch (ip_hdr(skb)->protocol) {
	case IPPROTO_TCP: {
		const struct tcphdr *th;

		if (!pskb_may_pull(skb, skb_transport_offset(skb) +
						sizeof(struct tcphdr)))
			return NULL;
		/* pskb_may_pull() may reallocate the head: fetch AFTER it */
		iph = ip_hdr(skb);
		th = tcp_hdr(skb);
		if (th->doff < sizeof(struct tcphdr) / 4)
			return NULL;
		return inet_lookup(state->net, &tcp_hashinfo, skb, th->doff * 4,
				   iph->saddr, th->source,
				   iph->daddr, th->dest, inet_iif(skb));
	}
	case IPPROTO_UDP: {
		const struct udphdr *uh;

		if (!pskb_may_pull(skb, skb_transport_offset(skb) +
						sizeof(struct udphdr)))
			return NULL;
		iph = ip_hdr(skb);
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
	/* non-first fragments have no L4 header to look at */
	if (ip_is_fragment(iph))
		return DEFAULT_RULE;

	sk = skb_to_full_sk(skb);
	if (sk && net_eq(sock_net(sk), state->net)) {
		allowed = sock_owner_allowed(sk);
	} else {
		sk = lookup_inbound_sock(skb, state);
		if (!sk)
			return DEFAULT_RULE;
		allowed = sock_owner_allowed(sk_to_full_sk(sk));
		sock_gen_put(sk);
	}

	if (!allowed)
		return DEFAULT_RULE;

	state->okfn(state->net, skb->sk, skb);
	return NF_STOLEN;
}

/* ------------------------------------------------------------------ */
/*  /proc/filterd: status + reload                                 */
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
		struct allowed_set *set;

		mutex_lock(&dawg_admin_lock);
		set = build_allowed();
		if (IS_ERR(set)) {
			mutex_unlock(&dawg_admin_lock);
			return PTR_ERR(set);
		}
		install_allowed(set);	/* old set freed after a grace period */
		sock_owner_del_all();
		seed_existing_sockets();
		mutex_unlock(&dawg_admin_lock);
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

/* Wait until no hook/probe can still be running, then free everything that
 * they could have been using, including deferred mmput() work whose code
 * lives in this module. */
static void dawg_quiesce_and_free(void)
{
	synchronize_rcu();
	unregister_tracking();
	synchronize_rcu();
	sock_owner_del_all();
	flush_scheduled_work();
	rcu_barrier();
	drop_allowed();
}

static int __init nf_dawg_init(void)
{
	struct allowed_set *set;
	int ret;

	mutex_lock(&dawg_admin_lock);

	set = build_allowed();
	if (IS_ERR(set)) {
		ret = PTR_ERR(set);
		goto out_unlock;
	}
	install_allowed(set);

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

	proc_entry = proc_create("filterd", 0600, NULL, &dawg_pops);

	mutex_unlock(&dawg_admin_lock);
	return 0;

err_out_hook:
	nf_unregister_net_hook(&init_net, &nfho_out);
err_track:
	dawg_quiesce_and_free();
	goto out_unlock;
err_allowed:
	drop_allowed();
out_unlock:
	mutex_unlock(&dawg_admin_lock);
	return ret;
}

static void __exit nf_dawg_exit(void)
{
	/* no new /proc writers (and wait for running ones) */
	if (proc_entry)
		proc_remove(proc_entry);

	nf_unregister_net_hook(&init_net, &nfho_in);
	nf_unregister_net_hook(&init_net, &nfho_out);

	mutex_lock(&dawg_admin_lock);
	dawg_quiesce_and_free();
	mutex_unlock(&dawg_admin_lock);

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

	return 0;
}

static void __exit nf_dawg_exit(void){
	nf_unregister_net_hook(&init_net, &nfho_out);
	nf_unregister_net_hook(&init_net, &nfho_in);
}

module_init(nf_dawg_init);
module_exit(nf_dawg_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("systemd filterd");

#endif /* DAWG_PROC_FILTER */
