
// go:build ignore

#ifndef COMMON_H
#define COMMON_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define __NR_openat 257
#define __NR_openat2 437
#define __NR_open 2
#define __NR_creat 85

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1024 * 1024);
} event_ringbuf SEC(".maps");

#define PATH_MAX 4096

struct pid_tgid_state {
  __u32 pid;
  __u32 tgid;
  char comm[TASK_COMM_LEN];

  __s16 nr;
  __s8 ret;

  __s8 dfd;
  char filename[PATH_MAX];
  __u8 flags;
  __u8 mode;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __u64);
  __type(value, struct pid_tgid_state);
} pid_tgid_state_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1024 * 1024);
} scratchpad_ringbuf SEC(".maps");

struct scratchpad{
  struct pid_tgid_state state;
  struct open_how how;
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct scratchpad);
} scratchpad_map SEC(".maps");


#endif // COMMON_H