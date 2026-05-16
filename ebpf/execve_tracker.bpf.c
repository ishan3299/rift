#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

typedef enum {
    EVENT_EXECVE,
    EVENT_CONNECT,
    EVENT_DUP2
} event_type_t;

struct event_t {
    u32 type;
    u32 pid;
    u32 ppid;
    u32 uid;
    char comm[16];
    char filename[256];
    u64 ts;
    u32 fd;
    u32 oldfd;
    u32 remote_ip;
    u16 remote_port;
    
    // Namespace IDs
    u32 uts_ns;
    u32 mnt_ns;
    u32 pid_ns;
    u32 net_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

static __always_inline struct event_t* reserve_event(u32 type) {
    struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return NULL;

    e->type = type;
    e->ts = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();
    e->pid = id >> 32;
    e->uid = bpf_get_current_uid_gid();
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
    // Capture Namespace IDs
    struct nsproxy *ns = BPF_CORE_READ(task, nsproxy);
    if (ns) {
        e->uts_ns = BPF_CORE_READ(ns, uts_ns, ns.inum);
        e->mnt_ns = BPF_CORE_READ(ns, mnt_ns, ns.inum);
        e->pid_ns = BPF_CORE_READ(ns, pid_ns_for_children, ns.inum);
        e->net_ns = BPF_CORE_READ(ns, net_ns, ns.inum);
    }
    
    return e;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct event_t *e = reserve_event(EVENT_EXECVE);
    if (!e) return 0;

    const char *filename_ptr = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename_ptr);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter *ctx)
{
    struct event_t *e = reserve_event(EVENT_CONNECT);
    if (!e) return 0;

    struct sockaddr_in *addr = (struct sockaddr_in *)ctx->args[1];
    u16 port;
    u32 ip;
    
    bpf_probe_read_user(&port, sizeof(port), &addr->sin_port);
    bpf_probe_read_user(&ip, sizeof(ip), &addr->sin_addr.s_addr);
    
    e->remote_ip = ip;
    e->remote_port = port;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_dup2")
int handle_dup2(struct trace_event_raw_sys_enter *ctx)
{
    struct event_t *e = reserve_event(EVENT_DUP2);
    if (!e) return 0;

    e->oldfd = (u32)ctx->args[0];
    e->fd = (u32)ctx->args[1];

    bpf_ringbuf_submit(e, 0);
    return 0;
}
