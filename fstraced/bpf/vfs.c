// clang-format off
//go:build ignore
// clang-format on

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define __NR_openat          257
#define PATH_MAX             4096
#define MAX_STRING_SIZE      4096
#define MAX_PATH_COMPONENTS  20

#define STRING_BUF_IDX 0

#define EVENT_TYPE_ENTER 1
#define EVENT_TYPE_EXIT  2

#define MAX_PERCPU_BUFSIZE (1 << 15)


struct event_t {
  u32 type;
  u32 pid;
  u64 cgid;
  char str[PATH_MAX];
};

struct simple_buf {
    u8 buf[MAX_PERCPU_BUFSIZE];
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct event_t);
} tmp_storage_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 3);
  __type(key, u32);
  __type(value, struct simple_buf);
} tmp_buf_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 3);
  __type(key, u32);
  __type(value, u32);
} bufs_off SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

static __always_inline void set_buf_off(int buf_idx, u32 new_off)
{
    bpf_map_update_elem(&bufs_off, &buf_idx, &new_off, BPF_ANY);
}


#define READ_KERN(ptr)                                                  \
    ({                                                                  \
        typeof(ptr) _val;                                               \
        __builtin_memset((void *)&_val, 0, sizeof(_val));               \
        bpf_probe_read((void *)&_val, sizeof(_val), &ptr);              \
        _val;                                                           \
    })

#define READ_USER(ptr)                                                  \
    ({                                                                  \
        typeof(ptr) _val;                                               \
        __builtin_memset((void *)&_val, 0, sizeof(_val));               \
        bpf_probe_read_user((void *)&_val, sizeof(_val), &ptr);         \
        _val;                                                           \
    })


static __always_inline struct dentry* get_mnt_root_ptr_from_vfsmnt(struct vfsmount *vfsmnt)
{
  return READ_KERN(vfsmnt->mnt_root);
}

static __always_inline struct dentry* get_d_parent_ptr_from_dentry(struct dentry *dentry)
{
    return READ_KERN(dentry->d_parent);
}

static __always_inline struct qstr get_d_name_from_dentry(struct dentry *dentry)
{
    return READ_KERN(dentry->d_name);
}


SEC("raw_tracepoint/sys_enter")
int raw_tracepoint_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
  unsigned long syscall_id = ctx->args[1];
  struct pt_regs *regs;
  const char *pathname;
  u32 map_id;
  int res;
  struct event_t *event;

  if (syscall_id != __NR_openat)
    return 0;

  regs = (struct pt_regs *)ctx->args[0];

  res = bpf_probe_read(&pathname, sizeof(pathname), &regs->si);

  map_id = 0;
  event = bpf_map_lookup_elem(&tmp_storage_map, &map_id);
  if (!event) {
    bpf_printk("is_open_at no map_val\n");
    return 0;
  }

  res = bpf_probe_read_str(&event->str, PATH_MAX, pathname);
  if (res > 0) {
    event->str[(res - 1) & (PATH_MAX - 1)] = 0;
  } else {
    return 0;
  }

  event->pid = bpf_get_current_pid_tgid();
  event->type = EVENT_TYPE_ENTER;
  bpf_printk("open_at: %d %s\n", sizeof(*event), event->str);
  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));

  return 0;
}

static inline struct mount *real_mount(struct vfsmount *mnt)
{
  return container_of(mnt, struct mount, mnt);
}

static __always_inline void* get_path_str(struct path *path)
{
  struct path f_path;
  bpf_probe_read(&f_path, sizeof(f_path), path);
  char slash = '/';
  int zero = 0;
  struct dentry *dentry = f_path.dentry;
  struct vfsmount *vfsmnt = f_path.mnt;
  struct mount *mnt_parent_p;

  struct mount *mnt_p = real_mount(vfsmnt);
  bpf_probe_read(&mnt_parent_p, sizeof(struct mount*), &mnt_p->mnt_parent);

  u32 buf_off = (MAX_PERCPU_BUFSIZE >> 1);
  struct dentry *mnt_root;
  struct dentry *d_parent;
  struct qstr d_name;
  unsigned int len;
  unsigned int off;
  int sz;


  int idx = STRING_BUF_IDX;
  struct simple_buf *string_p;
  string_p = bpf_map_lookup_elem(&tmp_buf_map, &idx);
  if (string_p == NULL) {
    return NULL;
  }

  #pragma unroll
  for (int i = 0; i < MAX_PATH_COMPONENTS; i++) {
    mnt_root = get_mnt_root_ptr_from_vfsmnt(vfsmnt);
    d_parent = get_d_parent_ptr_from_dentry(dentry);
    if (dentry == mnt_root || dentry == d_parent) {
      if (dentry != mnt_root) {
        // We reached root, but not mount root - escaped?
        break;
      }
      if (mnt_p != mnt_parent_p) {
        // We reached root, but not global root - continue with mount point path
        bpf_probe_read(&dentry, sizeof(struct dentry*), &mnt_p->mnt_mountpoint);
        bpf_probe_read(&mnt_p, sizeof(struct mount*), &mnt_p->mnt_parent);
        bpf_probe_read(&mnt_parent_p, sizeof(struct mount*), &mnt_p->mnt_parent);
        vfsmnt = &mnt_p->mnt;
        continue;
      }
      // Global root - path fully parsed
      break;
    }
    // Add this dentry name to path
    d_name = get_d_name_from_dentry(dentry);
    len = (d_name.len+1) & (MAX_STRING_SIZE-1);
    off = buf_off - len;

    // Is string buffer big enough for dentry name?
    sz = 0;
    if (off <= buf_off) { // verify no wrap occurred
      len = len & ((MAX_PERCPU_BUFSIZE >> 1)-1);
      sz = bpf_probe_read_str(&(string_p->buf[off & ((MAX_PERCPU_BUFSIZE >> 1)-1)]), len, (void *)d_name.name);
    }
    else
      break;
    if (sz > 1) {
      buf_off -= 1; // remove null byte termination with slash sign
      bpf_probe_read(&(string_p->buf[buf_off & (MAX_PERCPU_BUFSIZE-1)]), 1, &slash);
      buf_off -= sz - 1;
    } else {
      // If sz is 0 or 1 we have an error (path can't be null nor an empty string)
      break;
    }
    dentry = d_parent;
  }

  if (buf_off == (MAX_PERCPU_BUFSIZE >> 1)) {
    // memfd files have no path in the filesystem -> extract their name
    buf_off = 0;
    d_name = get_d_name_from_dentry(dentry);
    bpf_probe_read_str(&(string_p->buf[0]), MAX_STRING_SIZE, (void *)d_name.name);
  } else {
    // Add leading slash
    buf_off -= 1;
    bpf_probe_read(&(string_p->buf[buf_off & (MAX_PERCPU_BUFSIZE-1)]), 1, &slash);
    // Null terminate the path string
    bpf_probe_read(&(string_p->buf[(MAX_PERCPU_BUFSIZE >> 1)-1]), 1, &zero);
  }

  set_buf_off(STRING_BUF_IDX, buf_off);

  bpf_printk("pathstr s=%s\n", &(string_p->buf[buf_off]));

  return &string_p->buf[buf_off];
}

SEC("raw_tracepoint/sys_exit")
int raw_tracepoint_sys_exit(struct bpf_raw_tracepoint_args *ctx)
{
  long fd_num = ctx->args[1]; // return arg
  struct pt_regs *regs = (struct pt_regs*)ctx->args[0];
  int res;
  int syscall_id;
#if defined(bpf_target_x86)
  bpf_probe_read(&syscall_id, sizeof(syscall_id), &regs->orig_ax);
#elif defined(bpf_target_arm64)
  bpf_probe_read(&syscall_id, sizeof(syscall_id), &regs->syscallno);
#endif

  if (syscall_id != __NR_openat)
    return 0;

  bpf_printk("open_at return: fd=%d\n", fd_num);

  u32 map_id = 0;
  struct event_t *event = bpf_map_lookup_elem(&tmp_storage_map, &map_id);
  if (!event) {
    bpf_printk("is_open_at no map_val\n");
    return 0;
  }

  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  if (task == NULL) {
    return 0;
  }

  struct files_struct *files;
  bpf_probe_read(&files, sizeof(files), &task->files);
  if (files == NULL) {
    return 0;
  }

  struct fdtable *fdt;
  bpf_probe_read(&fdt, sizeof(fdt), &files->fdt);
  if (fdt == NULL) {
    return 0;
  }

  struct file **fd;
  bpf_probe_read(&fd, sizeof(fd), &fdt->fd);
  if (fd == NULL) {
    return 0;
  }

  struct file *f;
  bpf_probe_read(&f, sizeof(f), &fd[fd_num]);
  if (f == NULL) {
    return 0;
  }

  void *file_path = get_path_str(&f->f_path);

  struct inode *f_inode;
  bpf_probe_read(&f_inode, sizeof(f_inode), &f->f_inode);
  if (f_inode == NULL) {
    return 0;
  }

  struct super_block *i_sb;
  bpf_probe_read(&i_sb, sizeof(i_sb), &f_inode->i_sb);
  if (i_sb == NULL) {
    return 0;
  }

  dev_t s_dev = 0;
  bpf_probe_read(&s_dev, sizeof(s_dev), &i_sb->s_dev);

  event->type = EVENT_TYPE_EXIT;
  event->pid = bpf_get_current_pid_tgid();
  event->cgid = bpf_get_current_cgroup_id();
  res = bpf_probe_read_str(&event->str, 4096, file_path);

  bpf_printk("open_at exit: dev=%x cg=%d mnt:%s\n", s_dev, event->cgid, event->str);
  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));

  return 0;
}
