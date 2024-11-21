
// clang-format off
//go:build ignore
// clang-format on

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

/*
# cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/format

name: sys_enter_execve
ID: 822
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:int __syscall_nr; offset:8;       size:4; signed:1;
        field:const char * filename;    offset:16;      size:8; signed:0;
        field:const char *const * argv; offset:24;      size:8; signed:0;
        field:const char *const * envp; offset:32;      size:8; signed:0;

print fmt: "filename: 0x%08lx, argv: 0x%08lx, envp: 0x%08lx", ((unsigned long)(REC->filename)), ((unsigned long)(REC->argv)), ((unsigned long)(REC->envp))
*/
struct sys_enter_execve_format
{
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    const char *filename;
    const char *const *argv;
    const char *const *envp;
};

/*
# cat /sys/kernel/debug/tracing/events/syscalls/sys_exit_execve/format

name: sys_exit_execve
ID: 821
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:int __syscall_nr; offset:8;       size:4; signed:1;
        field:long ret; offset:16;      size:8; signed:1;

print fmt: "0x%lx", REC->ret
*/
struct sys_exit_execve_format
{
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    long ret;
};

#define MAX_ARGS 8
#define MAX_ARG_LEN 50
#define MAX_ENVS 8
#define MAX_ENV_LEN 50

struct event
{
    int pid;            // 4 bytes
    int ppid;           // 4 bytes
    int uid;            // 4 bytes
    char filename[500]; // 500 bytes
    char envp[MAX_ENVS][MAX_ENV_LEN];
    char argv[MAX_ARGS][MAX_ARG_LEN];
};
// This event ring buffer is read by userspace program
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, int);
    __type(value, bool);
    __uint(max_entries, 1024);   
} cgroups_to_monitor SEC(".maps");


SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint_syscalls_sys_enter_execve(struct sys_enter_execve_format *ctx)
{
    // u64 cgroup_id = bpf_get_current_cgroup_id();
    // int *val = bpf_map_lookup_elem(&cgroups_to_monitor, &cgroup_id);
    // if (val == NULL || *val != true)
    // {
    //     return 0;
    // }

    u64 id;
    pid_t pid, tgid, ppid;
    struct task_struct *task;
    uid_t uid = (u32)bpf_get_current_uid_gid();
    id = bpf_get_current_pid_tgid();
    tgid = id >> 32;
    task = (struct task_struct *)bpf_get_current_task();
    ppid = BPF_CORE_READ(task, real_parent, tgid);

    struct event *event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!event)
    {
        return 0;
    }

    event->pid = tgid;
    event->uid = uid;
    event->ppid = ppid;
    bpf_probe_read_user_str(&event->filename, sizeof(event->filename), ctx->filename);
    int i;
    char *tmp;
    for (i = 0; i < sizeof(ctx->argv); i++)
    {
        if (i > MAX_ARGS)
        {
            break;
        }
        bpf_probe_read(&tmp, sizeof(tmp), &ctx->argv[i]);
        if (tmp == NULL)
        {
            break;
        }
        bpf_probe_read_str(&event->argv[i], sizeof(event->argv[i]), tmp);
    }
    if (i < MAX_ARGS)
    {
        event->argv[i][0] = '\0';
    }
    for (i = 0; i < sizeof(ctx->envp); i++)
    {
        if (i > MAX_ENVS)
        {
            break;
        }
        bpf_probe_read(&tmp, sizeof(tmp), &ctx->envp[i]);
        if (tmp == NULL)
        {
            break;
        }
        bpf_probe_read_str(&event->envp[i], sizeof(event->envp[i]), tmp);
    }
    if (i < MAX_ENVS)
    {
        event->envp[i][0] = '\0';
    }
    bpf_ringbuf_submit(event, 0);

    return 0;
}

// SEC("tracepoint/syscalls/sys_exit_execve")
// int tracepoint_syscalls_sys_exit_execve(struct sys_exit_execve_format *ctx)
// {
//     return 0;
// }

char LICENSE[] SEC("license") = "Dual MIT/GPL";
