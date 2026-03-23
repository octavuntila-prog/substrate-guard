// substrate-guard eBPF programs for AI agent observation
// Compiled and loaded by BCC (BPF Compiler Collection)
// Requires: Linux kernel 5.4+, CONFIG_BPF=y, CAP_SYS_ADMIN or CAP_BPF

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <net/sock.h>

// ============================================
// Event structures passed to userspace via perf
// ============================================

struct execve_event {
    u32 pid;
    u32 tid;
    u32 uid;
    u32 ppid;
    char comm[16];
    char filename[256];
    int ret;
};

struct openat_event {
    u32 pid;
    u32 tid;
    u32 uid;
    char comm[16];
    char filename[256];
    int flags;
    int ret;
};

struct connect_event {
    u32 pid;
    u32 tid;
    u32 uid;
    char comm[16];
    u32 daddr;     // IPv4 destination
    u16 dport;     // destination port
    u16 family;    // AF_INET / AF_INET6
    int ret;
};

struct tls_event {
    u32 pid;
    u32 tid;
    u32 uid;
    char comm[16];
    u32 len;
    char buf[256]; // first 256 bytes of payload
    u8 is_write;   // 0=read, 1=write
};

// ============================================
// Perf output buffers
// ============================================

BPF_PERF_OUTPUT(execve_events);
BPF_PERF_OUTPUT(openat_events);
BPF_PERF_OUTPUT(connect_events);
BPF_PERF_OUTPUT(tls_events);

// ============================================
// PID filter — only trace target agent processes
// key: pid, value: agent_id index
// ============================================

BPF_HASH(traced_pids, u32, u32);

static inline int should_trace() {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 *found = traced_pids.lookup(&pid);
    return found != NULL;
}

// ============================================
// Probe 1: execve — every command execution
// tracepoint/syscalls/sys_enter_execve
// ============================================

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    if (!should_trace()) return 0;
    
    struct execve_event event = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid >> 32;
    event.tid = pid_tgid;
    event.uid = bpf_get_current_uid_gid();
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event.ppid = task->real_parent->tgid;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename), args->filename);
    
    execve_events.perf_submit(args, &event, sizeof(event));
    return 0;
}

// ============================================
// Probe 2: openat — every file open
// tracepoint/syscalls/sys_enter_openat
// ============================================

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    if (!should_trace()) return 0;
    
    struct openat_event event = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid >> 32;
    event.tid = pid_tgid;
    event.uid = bpf_get_current_uid_gid();
    event.flags = args->flags;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename), args->filename);
    
    openat_events.perf_submit(args, &event, sizeof(event));
    return 0;
}

// ============================================
// Probe 3: connect — every network connection
// tracepoint/syscalls/sys_enter_connect
// ============================================

TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    if (!should_trace()) return 0;
    
    struct connect_event event = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid >> 32;
    event.tid = pid_tgid;
    event.uid = bpf_get_current_uid_gid();
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // Read sockaddr to get destination IP/port
    struct sockaddr_in sa = {};
    bpf_probe_read_user(&sa, sizeof(sa), args->uservaddr);
    event.family = sa.sin_family;
    event.dport = __builtin_bswap16(sa.sin_port);
    event.daddr = sa.sin_addr.s_addr;
    
    connect_events.perf_submit(args, &event, sizeof(event));
    return 0;
}

// ============================================
// Probe 4: TLS — decrypt in-flight (uprobe on SSL_read/SSL_write)
// Attach via: attach_uprobe(name="ssl", sym="SSL_read")
// ============================================

int probe_ssl_read_enter(struct pt_regs *ctx) {
    if (!should_trace()) return 0;
    // Store buffer pointer for return probe
    u64 pid_tgid = bpf_get_current_pid_tgid();
    // (buffer tracking via BPF_HASH omitted for brevity — see AgentSight pattern)
    return 0;
}

int probe_ssl_read_return(struct pt_regs *ctx) {
    if (!should_trace()) return 0;
    
    struct tls_event event = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid >> 32;
    event.tid = pid_tgid;
    event.uid = bpf_get_current_uid_gid();
    event.is_write = 0;
    
    int ret = PT_REGS_RC(ctx);
    if (ret <= 0) return 0;
    
    event.len = ret;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    // Read first 256 bytes of decrypted payload
    // (requires buffer pointer from enter probe)
    
    tls_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
