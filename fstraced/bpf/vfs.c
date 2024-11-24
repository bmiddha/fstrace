
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

SEC("fentry/do_unlinkat")
int BPF_PROG(prog, int dfd, struct filename *name)
{
  
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
