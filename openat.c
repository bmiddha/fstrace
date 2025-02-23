
// clang-format off
//go:build ignore
// clang-format on

#include "common.h"

volatile const __u64 NS_DEV;
volatile const __u64 NS_INO;

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint_syscalls_sys_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
  __u64 pid_tgid;
  __u32 pid, tgid;
  pid_tgid = bpf_get_current_pid_tgid();
  tgid = pid_tgid >> 32;
  pid = pid_tgid;

  __u32 scratchpad_map_key = 0;
  struct scratchpad *scratch = bpf_map_lookup_elem(&scratchpad_map, &scratchpad_map_key);
  if (!scratch)
  {
    bpf_printk("failed to lookup scratchpad_map\n");
    return 0;
  }
  struct pid_tgid_state *state = &scratch->state;

  state->pid = pid;
  state->tgid = tgid;
  char comm[TASK_COMM_LEN];
  bpf_get_current_comm(state->comm, TASK_COMM_LEN);
  state->nr = ctx->id;
  state->dfd = ctx->args[0];
  const void *filename_ptr = ctx->args[1];
  bpf_probe_read_user_str(state->filename, sizeof(state->filename), filename_ptr);
  state->flags = ctx->args[2];
  state->mode = ctx->args[3];

  if (bpf_map_update_elem(&pid_tgid_state_map, &pid_tgid, state, 0))
  {
    bpf_printk("failed to update pid_tgid_state_map\n");
    return 0;
  }
  return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int tracepoint_syscalls_sys_exit_openat(struct trace_event_raw_sys_exit *ctx)
{
  __u64 pid_tgid;
  __u32 pid, tgid;
  pid_tgid = bpf_get_current_pid_tgid();
  tgid = pid_tgid >> 32;
  pid = pid_tgid;

  struct pid_tgid_state *state;
  state = bpf_map_lookup_elem(&pid_tgid_state_map, &pid_tgid);
  if (!state)
  {
    bpf_printk("failed to lookup pid_tgid_state_map\n");
    return 0;
  }

  state->ret = ctx->ret;

  bpf_ringbuf_output(&event_ringbuf, state, sizeof(struct pid_tgid_state), 0);

  bpf_map_delete_elem(&pid_tgid_state_map, &pid_tgid);
  return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int tracepoint_syscalls_sys_enter_openat2(struct trace_event_raw_sys_enter *ctx)
{
  __u64 pid_tgid;
  __u32 pid, tgid;
  pid_tgid = bpf_get_current_pid_tgid();
  tgid = pid_tgid >> 32;
  pid = pid_tgid;

  __u32 scratchpad_map_key = 0;
  struct scratchpad *scratch = bpf_map_lookup_elem(&scratchpad_map, &scratchpad_map_key);
  if (!scratch)
  {
    bpf_printk("failed to lookup scratchpad_map\n");
    return 0;
  }
  struct pid_tgid_state *state = &scratch->state;
  struct open_how *how = &scratch->how;


  state->pid = pid;
  state->tgid = tgid;
  char comm[TASK_COMM_LEN];
  bpf_get_current_comm(state->comm, TASK_COMM_LEN);
  state->nr = ctx->id;
  state->dfd = ctx->args[0];
  const void *filename_ptr = ctx->args[1];
  bpf_probe_read_user_str(state->filename, sizeof(state->filename), filename_ptr);
  bpf_probe_read_user(how, sizeof(struct open_how), ctx->args[2]);
  state->flags = how->flags;
  state->mode = how->mode;

  bpf_map_update_elem(&pid_tgid_state_map, &pid_tgid, state, 0);
  return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat2")
int tracepoint_syscalls_sys_exit_openat2(struct trace_event_raw_sys_exit *ctx)
{
  __u64 pid_tgid;
  __u32 pid, tgid;
  pid_tgid = bpf_get_current_pid_tgid();
  tgid = pid_tgid >> 32;
  pid = pid_tgid;

  struct pid_tgid_state *state;
  state = bpf_map_lookup_elem(&pid_tgid_state_map, &pid_tgid);
  if (!state)
  {
    bpf_printk("failed to lookup pid_tgid_state_map\n");
    return 0;
  }

  state->ret = ctx->ret;

  bpf_ringbuf_output(&event_ringbuf, state, sizeof(struct pid_tgid_state), 0);

  bpf_map_delete_elem(&pid_tgid_state_map, &pid_tgid);
  return 0;
}

SEC("tracepoint/syscalls/sys_enter_open")
int tracepoint_syscalls_sys_enter_open(struct trace_event_raw_sys_enter *ctx)
{
  __u64 pid_tgid;
  __u32 pid, tgid;
  pid_tgid = bpf_get_current_pid_tgid();
  tgid = pid_tgid >> 32;
  pid = pid_tgid;

  __u32 scratchpad_map_key = 0;
  struct scratchpad *scratch = bpf_map_lookup_elem(&scratchpad_map, &scratchpad_map_key);
  if (!scratch)
  {
    bpf_printk("failed to lookup scratchpad_map\n");
    return 0;
  }
  struct pid_tgid_state *state = &scratch->state;

  state->pid = pid;
  state->tgid = tgid;
  bpf_get_current_comm(state->comm, TASK_COMM_LEN);
  state->dfd = -1;
  state->nr = ctx->id;
  const void *filename_ptr = ctx->args[0];
  bpf_probe_read_user_str(state->filename, sizeof(state->filename), filename_ptr);
  state->flags = ctx->args[1];
  state->mode = ctx->args[2];

  bpf_map_update_elem(&pid_tgid_state_map, &pid_tgid, state, 0);

  return 0;
}

SEC("tracepoint/syscalls/sys_exit_open")
int tracepoint_syscalls_sys_exit_open(struct trace_event_raw_sys_exit *ctx)
{
  __u64 pid_tgid;
  __u32 pid, tgid;
  pid_tgid = bpf_get_current_pid_tgid();
  tgid = pid_tgid >> 32;
  pid = pid_tgid;

  struct pid_tgid_state *state;
  state = bpf_map_lookup_elem(&pid_tgid_state_map, &pid_tgid);
  if (!state)
  {
    bpf_printk("failed to lookup pid_tgid_state_map\n");
    return 0;
  }

  state->ret = ctx->ret;

  bpf_ringbuf_output(&event_ringbuf, state, sizeof(struct pid_tgid_state), 0);

  bpf_map_delete_elem(&pid_tgid_state_map, &pid_tgid);
  return 0;
}

SEC("tracepoint/syscalls/sys_enter_creat")
int tracepoint_syscalls_sys_enter_creat(struct trace_event_raw_sys_enter *ctx)
{
  __u64 pid_tgid;
  __u32 pid, tgid;
  pid_tgid = bpf_get_current_pid_tgid();
  tgid = pid_tgid >> 32;
  pid = pid_tgid;

  __u32 scratchpad_map_key = 0;
  struct scratchpad *scratch = bpf_map_lookup_elem(&scratchpad_map, &scratchpad_map_key);
  if (!scratch)
  {
    bpf_printk("failed to lookup scratchpad_map\n");
    return 0;
  }
  struct pid_tgid_state *state = &scratch->state;

  state->pid = pid;
  state->tgid = tgid;
  bpf_get_current_comm(state->comm, TASK_COMM_LEN);
  state->dfd = -1;
  state->nr = ctx->id;
  const void *filename_ptr = ctx->args[0];
  bpf_probe_read_user_str(state->filename, sizeof(state->filename), filename_ptr);
  state->mode = ctx->args[1];

  bpf_map_update_elem(&pid_tgid_state_map, &pid_tgid, state, 0);

  return 0;
}

SEC("tracepoint/syscalls/sys_exit_creat")
int tracepoint_syscalls_sys_exit_creat(struct trace_event_raw_sys_exit *ctx)
{
  __u64 pid_tgid;
  __u32 pid, tgid;
  pid_tgid = bpf_get_current_pid_tgid();
  tgid = pid_tgid >> 32;
  pid = pid_tgid;

  struct pid_tgid_state *state;
  state = bpf_map_lookup_elem(&pid_tgid_state_map, &pid_tgid);
  if (!state)
  {
    bpf_printk("failed to lookup pid_tgid_state_map\n");
    return 0;
  }

  state->ret = ctx->ret;

  bpf_ringbuf_output(&event_ringbuf, state, sizeof(struct pid_tgid_state), 0);

  bpf_map_delete_elem(&pid_tgid_state_map, &pid_tgid);
  return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
