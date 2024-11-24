
// clang-format off
//go:build ignore
// clang-format on

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define DENTRY_CRAWL_LIMIT 100

struct
{
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 16 * 256 * 1024);
} event_ringbuf SEC(".maps");

#define PATH_MAX 4096
struct event_value
{
  u64 pid;
  char filename[PATH_MAX];
};

SEC("fentry/security_file_open")
int BPF_PROG(prog, struct file *file, int ret)
{
  pid_t pid;
  u64 pid_tgid = bpf_get_current_pid_tgid();
  pid = pid_tgid >> 32;

  struct task_struct *task = (struct task_struct *)bpf_get_current_task();

  struct event_value *event = bpf_ringbuf_reserve(&event_ringbuf, sizeof(struct event_value), 0);
  if (!event)
  {
    return 0;
  }

  event->pid = pid;
  uint filename_len = 0;

  bpf_d_path(&file->f_path, event->filename, PATH_MAX);
 
  bpf_ringbuf_submit(event, 0);
  return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
