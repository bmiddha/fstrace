
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

static __always_inline u32 get_ns_pid(struct task_struct *task)
{
  unsigned int level = 0;
  struct pid *pid = NULL;

  pid = BPF_CORE_READ(task, thread_pid);
  level = BPF_CORE_READ(pid, level);
  return BPF_CORE_READ(pid, numbers[level].nr);
}

static __always_inline u32 get_ns_pid_tgid(struct task_struct *task, struct bpf_pidns_info *pidns)
{
  struct task_struct *group_leader = BPF_CORE_READ(task, group_leader);
  pidns->pid = get_ns_pid(task);
  pidns->tgid = get_ns_pid(group_leader);
  return 0;
}

/**
 * * my_bpf_d_path - get the path of a dentry
 * Returns the index of the first character of the path in the buffer
 */
static __always_inline size_t my_bpf_d_path(struct path *path, char *buf, int buflen)
{
  char slash = '/';
  char zero = '\0';

  struct dentry *dentry;
  BPF_CORE_READ_INTO(&dentry, path, dentry);
  struct vfsmount *vfsmnt;
  BPF_CORE_READ_INTO(&vfsmnt, path, mnt);
  struct mount *mnt_p = container_of(vfsmnt, struct mount, mnt);
  struct mount *mnt_parent_p;
  bpf_core_read(&mnt_parent_p, sizeof(struct mount *), &mnt_p->mnt_parent);

  struct dentry *d_parent;
  struct dentry *mnt_root;

  u32 buf_off = (buflen >> 1);
  struct qstr d_name;
  const unsigned char *name;
  u32 len, off;
  int sz = 0;

  if (BPF_CORE_READ(dentry, d_flags) & DCACHE_DISCONNECTED)
  {
    bpf_probe_read_kernel_str(&(buf[0]), PATH_MAX, "<disconnected>");
    return 0;
  }

#pragma unroll
  for (int i = 0; i < PATH_COMPONENTS_MAX; i++)
  {
    mnt_root = BPF_CORE_READ(vfsmnt, mnt_root);
    d_parent = BPF_CORE_READ(dentry, d_parent);
    if (dentry == mnt_root || dentry == d_parent)
    {
      if (dentry != mnt_root)
      {
        break;
      }
      if (mnt_p != mnt_parent_p)
      {
        // traverse up the mount tree
        bpf_core_read(&dentry, sizeof(struct dentry *), &mnt_p->mnt_mountpoint);
        bpf_core_read(&mnt_p, sizeof(struct mount *), &mnt_p->mnt_parent);
        bpf_core_read(&mnt_parent_p, sizeof(struct mount *), &mnt_p->mnt_parent);
        vfsmnt = &mnt_p->mnt;
        continue;
      }
      // done traversing the path
      break;
    }
    // Add this dentry name to path
    d_name = BPF_CORE_READ(dentry, d_name);
    len = (d_name.len + 1) & ((buflen >> 1) - 1);
    off = buf_off - len;
    // Is string buffer big enough for dentry name?
    sz = 0;
    if (off <= buf_off)
    { // verify no wrap occurred
      len = len & ((buflen >> 1) - 1);
      void *dst = &(buf[off & ((buflen >> 1) - 1)]);
      // sz = bpf_probe_read_kernel_str(dst, len, (void *)d_name.name);
    }
    else
    {
      break;
    }
    if (sz > 1)
    {
      buf_off -= 1; // remove null byte termination with slash sign
      // bpf_probe_read_kernel(&(buf[buf_off & (buflen - 1)]), 1, &slash);
      buf_off -= sz - 1;
    }
    else
    {
      // If sz is 0 or 1 we have an error (path can't be null nor an empty string)
      break;
    }
    dentry = d_parent;
  }

  if (buf_off == (buflen >> 1))
  {
    // memfd files have no path in the filesystem -> extract their name
    buf_off = 0;
    BPF_CORE_READ(dentry, d_name);
    bpf_probe_read_kernel_str(&(buf[0]), PATH_MAX, (void *)d_name.name);
  }
  else
  {
    // Add leading slash
    buf_off -= 1;
    bpf_probe_read_kernel(&(buf[buf_off & (buflen - 1)]), 1, &slash);
    // Null terminate the path string
    bpf_probe_read_kernel(&(buf[(buflen >> 1) - 1]), 1, &zero);
  }
  return buf_off;
}

static __always_inline u32 get_task_pwd(struct task_struct *task, struct pid_tgid_state *state, struct scratchpad *scratch)
{
  struct path *pwd_path;
  BPF_CORE_READ_INTO(&pwd_path, task, fs, pwd);
  if (pwd_path == NULL)
  {
    bpf_printk("pwd_path is NULL\n");
    return 0;
  }
  size_t offset = my_bpf_d_path(pwd_path, scratch->pwd_buf, sizeof(scratch->pwd_buf));

  bpf_probe_read_kernel_str(state->pwd, sizeof(state->pwd), &(scratch->pwd_buf[offset]));
}

SEC("tracepoint/syscalls/sys_exit_openat")
int tracepoint_syscalls_sys_exit_openat(struct trace_event_raw_sys_exit *ctx)
{
  __u64 pid_tgid;
  __u32 pid, tgid;
  pid_tgid = bpf_get_current_pid_tgid();

  struct pid_tgid_state *state;
  state = bpf_map_lookup_elem(&pid_tgid_state_map, &pid_tgid);
  if (!state)
  {
    bpf_printk("failed to lookup pid_tgid_state_map\n");
    return 0;
  }

  __u32 scratchpad_map_key = 0;
  struct scratchpad *scratch = bpf_map_lookup_elem(&scratchpad_map, &scratchpad_map_key);
  if (!scratch)
  {
    bpf_printk("failed to lookup scratchpad_map\n");
    return 0;
  }
  struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
  struct bpf_pidns_info *pidns = &scratch->pidns;
  int ret = get_ns_pid_tgid(task, pidns);
  __u32 ns_pid = pidns->pid;
  __u32 ns_tgid = pidns->tgid;

  state->ns_pid = ns_pid;
  state->ns_tgid = ns_tgid;

  state->ret = ctx->ret;

  get_task_pwd(task, state, scratch);

  bpf_ringbuf_output(&event_ringbuf, state, sizeof(struct pid_tgid_state), 0);

  bpf_map_delete_elem(&pid_tgid_state_map, &pid_tgid);

  // int i;
  // struct dentry *dentry = task->fs->pwd.dentry;
  // for (i = 0; i < PATH_COMPONENTS_MAX; i++)
  // {
  //   bpf_probe_read_kernel(scratch->pwd_path_path_segments[i], sizeof(scratch->pwd_path_path_segments[i]), (void *)dentry->d_name.name);
  //   if (dentry == dentry->d_parent)
  //   { // root directory
  //     break;
  //   }

  //   dentry = dentry->d_parent;
  // }
  // scratch->pwd_path_segments_num = i;

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
