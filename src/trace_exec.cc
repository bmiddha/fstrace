#include <errno.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <linux/limits.h>
#include <linux/openat2.h>
#include <malloc.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <linux/types.h>
#include <map>
#include <stddef.h>
#include <sys/reg.h>
#include <sys/prctl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#if DEBUG
#define LOG_DEBUG(fmt, ...) dprintf(DEBUGFD, "[DEBUG] " fmt "\n", ##__VA_ARGS__);
#else
#define LOG_DEBUG(fmt, ...)
#endif

struct ptrace_syscall_info
{
  __u8 op; /* PTRACE_SYSCALL_INFO_* */
  __u8 pad[3];
  __u32 arch;
  __u64 instruction_pointer;
  __u64 stack_pointer;
  union
  {
    struct
    {
      __u64 nr;
      __u64 args[6];
    } entry;
    struct
    {
      __s64 rval;
      __u8 is_error;
    } exit;
    struct
    {
      __u64 nr;
      __u64 args[6];
      __u32 ret_data;
    } seccomp;
  };
};

extern char **environ;

int run_tracee(char *program, char **args)
{
  struct sock_filter filter[] = {
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execve, 32, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execveat, 31, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_open, 30, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_creat, 29, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 28, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat2, 27, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_readlink, 26, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_readlinkat, 25, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_lstat, 24, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_stat, 23, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_faccessat, 22, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_faccessat2, 21, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_access, 20, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_unlinkat, 19, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_unlink, 18, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_rmdir, 17, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_rename, 16, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_renameat, 15, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_renameat2, 14, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getdents, 13, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getdents64, 12, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_chmod, 11, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_symlink, 10, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_symlinkat, 9, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_linkat, 8, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_link, 7, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mkdir, 6, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mkdirat, 5, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_utime, 4, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_utimes, 3, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_truncate, 2, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_newfstatat, 1, 0),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE),
  };
  struct sock_fprog prog = {
      .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
      .filter = filter,
  };
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1)
  {
    perror("prctl(PR_SET_NO_NEW_PRIVS)");
    return 1;
  }
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1)
  {
    perror("prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)");
    return 1;
  }

  ptrace(PTRACE_TRACEME, 0, 0, 0);
  raise(SIGSTOP);
#if DEBUG
  LOG_DEBUG("execvp %s with args: ", program)
  for (char **arg = args; *arg; arg++)
  {
    LOG_DEBUG("%s ", *arg)
  }
  LOG_DEBUG("")
#endif
  return execvp(program, args);
}

struct fs_operation
{
  char path[PATH_MAX];
  char op[1];
  char comment[1000];
  char file_type;
};

int get_fd_path(pid_t proc_pid, long long fd, char *buf)
{
  unsigned bufsize = PATH_MAX;
  char linkpath[PATH_MAX];
  int n;

  if (fd < 0)
  {
    return -1;
  }

  sprintf(linkpath, "/proc/%u/fd/%lld", proc_pid, fd);
  n = readlink(linkpath, buf, bufsize - 1);
  if (n < 0)
  {
    return n;
  }

  buf[n] = '\0';

  return n;
}

#define ROUND_UP_TO_MULTIPLE(value, multiple) (((value) + (multiple) - 1) / (multiple) * (multiple));

void read_memory_from_tracee(pid_t pid, __u64 addr, void *buffer, size_t buffer_size)
{
  const size_t alloc_sz = ROUND_UP_TO_MULTIPLE(buffer_size, sizeof(long));
  unsigned long *data = (unsigned long *)malloc(alloc_sz);

  for (size_t i = 0; i < alloc_sz / sizeof(long); i++)
  {
    data[i] = ptrace(PTRACE_PEEKDATA, pid, addr + i * sizeof(long), NULL);
  }

  if (errno != 0)
  {
    perror("read_memory_from_tracee ptrace(PTRACE_PEEKDATA)");
    return;
  }

  memcpy(buffer, data, buffer_size);
  free(data);

  return;
}

void read_struct_from_tracee(pid_t pid, __u64 addr, void *buffer, size_t buffer_size)
{
  read_memory_from_tracee(pid, addr, buffer, buffer_size);
}

void read_cstring_from_tracee(pid_t pid, __u64 addr, char *buffer, size_t buffer_size)
{
  const size_t alloc_sz = ROUND_UP_TO_MULTIPLE(buffer_size, sizeof(long));
  unsigned long *data = (unsigned long *)malloc(alloc_sz);

  for (size_t i = 0; i < alloc_sz / sizeof(long); i++)
  {
    data[i] = ptrace(PTRACE_PEEKDATA, pid, addr + i * sizeof(long), NULL);
    if (memchr(&data[i], '\0', sizeof(long)) != NULL)
    {
      break;
    }
  }

  if (errno != 0)
  {
    perror("read_cstring_from_tracee ptrace(PTRACE_PEEKDATA)");
    return;
  }

  memcpy(buffer, data, buffer_size);
  free(data);

  return;
}

void read_maybe_relative_pathname_from_tracee(pid_t pid, __u64 addr, char *buffer, size_t buffer_size)
{
  read_cstring_from_tracee(pid, addr, buffer, buffer_size);

  // trim ./
  if (buffer[0] == '.' && buffer[1] == '/')
  {
    // LOG_DEBUG("trim ./: %s", buffer)
    memmove(buffer, buffer + 2, strlen(buffer) - 2);
    buffer[strlen(buffer) - 2] = '\0';
  }

  // LOG_DEBUG("buffer: %s", buffer)
  if (buffer[0] != '/')
  {
    char cwd[PATH_MAX];
    char cwd_link_path[PATH_MAX];
    sprintf(cwd_link_path, "/proc/%u/cwd", pid);
    if (readlink(cwd_link_path, cwd, PATH_MAX) == -1)
    {
      perror("readlink");
      return;
    }
    // LOG_DEBUG("cwd: %s", cwd)

    if (strlen(buffer) == 1 && buffer[0] == '.')
    {
      strncpy(buffer, cwd, buffer_size);
      return;
    }

    char temp_buffer[PATH_MAX];
    if (buffer[strlen(buffer) - 1] == '/')
    {
      snprintf(temp_buffer, PATH_MAX, "%s%s", cwd, buffer);
    }
    else
    {
      snprintf(temp_buffer, PATH_MAX, "%s/%s", cwd, buffer);
    }
    strncpy(buffer, temp_buffer, buffer_size);
  }
}

void parse_dirfd_pathname_from_tracee(pid_t pid, __u64 dirfd, __u64 pathname, char *fullpath, size_t fullpath_size)
{
  char path[PATH_MAX];
  read_cstring_from_tracee(pid, pathname, path, PATH_MAX);
  if (path[0] == '/')
  {
    sprintf(fullpath, "%s", path);
  }
  else
  {
    char dirpath[PATH_MAX];
    get_fd_path(pid, dirfd, dirpath);
    sprintf(fullpath, "%s/%s", dirpath, path);
  }
}

#define GET_FILE_TYPE_FROM_STAT_RESULT(stat_result)                                                                    \
  (S_ISDIR((stat_result)->st_mode)                                                                                     \
       ? 'D'                                                                                                           \
       : (S_ISREG((stat_result)->st_mode) ? 'F' : (S_ISLNK((stat_result)->st_mode) ? 'L' : '?')))

struct pid_info
{
  pid_t ppid;
  pid_t pid;
  int fs_op_idx;
  struct fs_operation fs_ops[2];
  unsigned long long nr;
  unsigned long long args[6];
  // char comment[1000];
  // union
  // {
  //   struct
  //   {
  //     char oldpath[PATH_MAX];
  //     char newpath[PATH_MAX];
  //   } op_rename;
  //   struct
  //   {
  //     char path[PATH_MAX];
  //     char access_mode;
  //   } op_open;
  //   struct
  //   {
  //     char path[PATH_MAX];
  //     char access_mode;
  //   } op_stat;
  //   struct
  //   {
  //     char path[PATH_MAX];
  //     char access_mode;
  //   } op_exec;
  // };
};

std::map<pid_t, struct pid_info> pid_info_map = {};
pid_t initial_pid;

int ptrace_syscall(pid_t child_pid, int status)
{
  LOG_DEBUG("PTRACE_SYSCALL pid: %d", child_pid)
  if (ptrace(PTRACE_SYSCALL, child_pid, 0, status) != 0)
  {
    if (errno)
    {
      if (errno == ESRCH)
      {
        LOG_DEBUG("Child %d died unexpectedly", child_pid)
        if (child_pid == initial_pid)
        {
          exit(0);
        }
        pid_info_map.erase(child_pid);
        return 0;
      }
      else
      {
        fprintf(stderr, "\nchild %d ptrace(PTRACE_SYSCALL)\n", child_pid);
        fprintf(stderr, "Error: %s\n", strerror(errno));
        return -1;
      }
    }
  }

  return 0;
}

int read_cmdline(pid_t pid, char *cmdline)
{
  char cmdline_path[PATH_MAX];
  sprintf(cmdline_path, "/proc/%d/cmdline", pid);
  FILE *cmdline_file = fopen(cmdline_path, "r");
  if (cmdline_file == NULL)
  {
    perror("fopen");
    return -1;
  }
  fread(cmdline, 1, PATH_MAX, cmdline_file);
  fclose(cmdline_file);
  return 0;
}

int run_tracer(pid_t child_pid)
{
  initial_pid = child_pid;
  LOG_DEBUG("Tracing pid %d", child_pid)

  int status = 0;
  LOG_DEBUG("wait for child to stop after TRACEME %d", child_pid)
  do
  {
    wait4(child_pid, &status, 0, NULL);
  } while (!WIFSTOPPED(status));
  LOG_DEBUG("child stopped")

  int ptrace_options = 0;
  ptrace_options |= PTRACE_O_TRACESECCOMP;
  ptrace_options |= PTRACE_O_TRACESYSGOOD;
  ptrace_options |= PTRACE_O_EXITKILL;
  ptrace_options |= PTRACE_O_TRACEFORK;
  ptrace_options |= PTRACE_O_TRACEEXEC;
  ptrace_options |= PTRACE_O_TRACEVFORK;
  ptrace_options |= PTRACE_O_TRACECLONE;
  ptrace_options |= PTRACE_O_TRACEEXIT;

  LOG_DEBUG("set ptrace options %d", ptrace_options)
  if (ptrace(PTRACE_SETOPTIONS, child_pid, 0, ptrace_options) == -1)
  {
    fprintf(stderr, "\nptrace(PTRACE_SETOPTIONS)\n");
    exit(-1);
  }
  LOG_DEBUG("continue from initial stop")
  if (ptrace(PTRACE_CONT, child_pid, 0, 0) == -1)
  {
    fprintf(stderr, "\nchild %d ptrace(PTRACE_CONT)\n", child_pid);
    if (errno != 0)
    {
      fprintf(stderr, "Error: %s\n", strerror(errno));
    }
    exit(-1);
  }

  for (;;)
  {
    child_pid = wait4(-1, &status, 0, NULL);

    if (child_pid == -1)
    {
      if (errno != ECHILD)
      {
        fprintf(stderr, "\nwaitpid returned -1 but did not set errno to ECHILD\n");
        return -1;
      }
      return 0;
    }

    if (WIFEXITED(status) || WIFSIGNALED(status))
    {
      LOG_DEBUG("child %d exited with status %d", child_pid, WSTOPSIG(status))
      if (child_pid == initial_pid)
      {
        LOG_DEBUG("initial child %d exited", child_pid)
        exit(WSTOPSIG(status));
        break;
      }
      continue;
    }
    else if (!WIFSTOPPED(status))
    {
      fprintf(stderr, "\nwaitpid returned unhandled status %d\n", status);
      return -1;
    }
    else if ((WIFSTOPPED(status) && (WSTOPSIG(status) & 0x80)) ||
             (status >> 8 == (SIGTRAP | (PTRACE_EVENT_SECCOMP << 8))))
    {
      // LOG_DEBUG("Child %d stopped by seccomp or syscall. nr: %", child_pid, info.entry.nr)
      // LOG_DEBUG("===========================")
      // LOG_DEBUG("BEGIN handle_syscall")

      struct ptrace_syscall_info info;
      if (ptrace(PTRACE_GET_SYSCALL_INFO, child_pid, sizeof(info), &info) == -1)
      {
        perror("ptrace(PTRACE_GET_SYSCALL_INFO)");
        fprintf(stderr, "Error: %s\n", strerror(errno));
        return -1;
      }

      if (info.op == PTRACE_SYSCALL_INFO_SECCOMP || info.op == PTRACE_SYSCALL_INFO_ENTRY)
      {
        LOG_DEBUG("Child %d stopped by seccomp or syscall entry. nr: %llu", child_pid, info.entry.nr)
        struct pid_info *thread_op;
        thread_op = &pid_info_map[child_pid];
        struct fs_operation *fs_op = thread_op->fs_ops;
        int *fs_op_idx = &thread_op->fs_op_idx;

        thread_op = &pid_info_map[child_pid];
        thread_op->fs_op_idx = 0;
        thread_op->nr = info.entry.nr;
        memcpy(thread_op->args, info.entry.args, sizeof(info.entry.args));

        *fs_op_idx = 0;

        unsigned long long nr = thread_op->nr;
        unsigned long long arg0 = thread_op->args[0];
        unsigned long long arg1 = thread_op->args[1];
        unsigned long long arg2 = thread_op->args[2];
        unsigned long long arg3 = thread_op->args[3];
        // unsigned long long arg4 = thread_op->args[4];
        // unsigned long long arg5 = thread_op->args[5];

        // LOG_DEBUG("PTRACE_SYSCALL_INFO_SECCOMP BEGIN: %llu", nr)

        switch (nr)
        {
        // int execve(const char *pathname, char *const argv[], char *const envp[]);
        case __NR_execve:
        {
          read_cstring_from_tracee(child_pid, arg0, fs_op[*fs_op_idx].path, PATH_MAX);
          sprintf(fs_op[*fs_op_idx].comment, "execve");
          fs_op[*fs_op_idx].op[0] = 'R';
          fs_op[*fs_op_idx].file_type = '?';
          (*fs_op_idx)++;
          break;
        }
        // int execveat(int dirfd, const char *pathname, char *const argv[], char *const envp[], int flags);
        case __NR_execveat:
        {
          parse_dirfd_pathname_from_tracee(child_pid, arg0, arg1, fs_op[*fs_op_idx].path, PATH_MAX);
          sprintf(fs_op[*fs_op_idx].comment, "execveat");
          fs_op[*fs_op_idx].op[0] = 'R';
          fs_op[*fs_op_idx].file_type = '?';
          (*fs_op_idx)++;
          break;
        }
        // int open(const char *pathname, int flags);
        // int open(const char *pathname, int flags, mode_t mode);
        case __NR_open:
        {
          read_cstring_from_tracee(child_pid, arg0, fs_op[*fs_op_idx].path, PATH_MAX);
          int flags = arg1;
          if (flags & O_RDONLY)
          {
            fs_op[*fs_op_idx].op[0] = 'R';
          }
          else if (flags & O_WRONLY || flags & O_RDWR)
          {
            fs_op[*fs_op_idx].op[0] = 'W';
          }
          sprintf(fs_op[*fs_op_idx].comment, "open");
          fs_op[*fs_op_idx].file_type = '?';
          (*fs_op_idx)++;
          break;
        }
        // int creat(const char *pathname, mode_t mode);
        case __NR_creat:
        {
          read_cstring_from_tracee(child_pid, arg0, fs_op[*fs_op_idx].path, PATH_MAX);
          sprintf(fs_op[*fs_op_idx].comment, "creat");
          fs_op[*fs_op_idx].op[0] = 'W';
          fs_op[*fs_op_idx].file_type = '?';
          (*fs_op_idx)++;
          break;
        }
        // int openat(int dirfd, const char *pathname, int flags);
        // int openat(int dirfd, const char *pathname, int flags, mode_t mode);
        case __NR_openat:
        {
          // LOG_DEBUG("openat")
          parse_dirfd_pathname_from_tracee(child_pid, arg0, arg1, fs_op[*fs_op_idx].path, PATH_MAX);
          // LOG_DEBUG("pathname: %s", fs_op[*fs_op_idx].path)
          int access_mode = arg2 & 3;
          if (access_mode == O_RDONLY)
          {
            // LOG_DEBUG("O_RDONLY")
            fs_op[*fs_op_idx].op[0] = 'R';
          }
          else if ((access_mode == O_WRONLY) || (access_mode == O_RDWR))
          {
            // LOG_DEBUG("O_WRONLY or O_RDWR")
            fs_op[*fs_op_idx].op[0] = 'W';
          }
          // if (arg2 & O_DIRECTORY)
          // {
          //   fs_op[*fs_op_idx].file_type = 'D';
          // }
          // else
          // {
          //   fs_op[*fs_op_idx].file_type = '?';
          // }
          fs_op[*fs_op_idx].file_type = '?';
          sprintf(fs_op[*fs_op_idx].comment, "openat %llu", arg2);
          (*fs_op_idx)++;
          break;
        }
        // int openat2(int dirfd, const char *pathname, struct open_how *how, size_t size);
        case __NR_openat2:
        {
          char path[PATH_MAX];
          if ((int)arg0 == AT_FDCWD)
          {
            // LOG_DEBUG("AT_FDCWD")
            read_maybe_relative_pathname_from_tracee(child_pid, arg1, fs_op[*fs_op_idx].path, PATH_MAX);
          }
          else
          {
            parse_dirfd_pathname_from_tracee(child_pid, arg0, arg1, fs_op[*fs_op_idx].path, PATH_MAX);
          }

          struct open_how *how = (struct open_how *)malloc(sizeof(struct open_how));
          read_struct_from_tracee(child_pid, arg2, how, sizeof(struct open_how));
          if (how->flags & O_RDONLY)
          {
            fs_op[*fs_op_idx].op[0] = 'R';
          }
          else if (how->flags & O_WRONLY || how->flags & O_RDWR)
          {
            fs_op[*fs_op_idx].op[0] = 'W';
          }
          // free(how);
          sprintf(fs_op[*fs_op_idx].comment, "openat2");
          fs_op[*fs_op_idx].file_type = '?';
          (*fs_op_idx)++;
          break;
        }
        // ssize_t readlink(const char *pathname, char *buf, size_t bufsiz);
        case __NR_readlink:
        {
          read_cstring_from_tracee(child_pid, arg0, fs_op[*fs_op_idx].path, PATH_MAX);
          sprintf(fs_op[*fs_op_idx].comment, "readlink");
          fs_op[*fs_op_idx].op[0] = 'R';
          fs_op[*fs_op_idx].file_type = '?';
          (*fs_op_idx)++;
          break;
        }
        // ssize_t readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz);
        case __NR_readlinkat:
        {
          parse_dirfd_pathname_from_tracee(child_pid, arg0, arg1, fs_op[*fs_op_idx].path, PATH_MAX);
          sprintf(fs_op[*fs_op_idx].comment, "readlinkat");
          fs_op[*fs_op_idx].op[0] = 'R';
          fs_op[*fs_op_idx].file_type = '?';
          (*fs_op_idx)++;
          break;
        }
        // int lstat(const char *pathname, struct stat *statbuf);
        case __NR_lstat:
        // int stat(const char *pathname, struct stat *statbuf);
        case __NR_stat:
        {
          read_cstring_from_tracee(child_pid, arg0, fs_op[*fs_op_idx].path, PATH_MAX);
          sprintf(fs_op[*fs_op_idx].comment, "stat/lstat");
          fs_op[*fs_op_idx].op[0] = 'R';
          fs_op[*fs_op_idx].file_type = '?';
          (*fs_op_idx)++;
          break;
        }
        // int statx(int dirfd, const char *pathname, int flags, unsigned int mask, struct statx *statxbuf);
        case __NR_statx:
        {
          parse_dirfd_pathname_from_tracee(child_pid, arg0, arg1, fs_op[*fs_op_idx].path, PATH_MAX);
          sprintf(fs_op[*fs_op_idx].comment, "statx");
          fs_op[*fs_op_idx].op[0] = 'R';
          fs_op[*fs_op_idx].file_type = '?';
          (*fs_op_idx)++;
          break;
        }
        // int fstatat(int dirfd, const char *pathname, struct stat *statbuf, int flags);
        case __NR_newfstatat:
        {
          parse_dirfd_pathname_from_tracee(child_pid, arg0, arg1, fs_op[*fs_op_idx].path, PATH_MAX);
          sprintf(fs_op[*fs_op_idx].comment, "fstatat");
          fs_op[*fs_op_idx].op[0] = 'R';
          fs_op[*fs_op_idx].file_type = '?';
          (*fs_op_idx)++;
          break;
        }
        // int faccessat(int dirfd, const char *pathname, int mode, int flags);
        case __NR_faccessat:
        case __NR_faccessat2:
        {
          parse_dirfd_pathname_from_tracee(child_pid, arg0, arg1, fs_op[*fs_op_idx].path, PATH_MAX);
          sprintf(fs_op[*fs_op_idx].comment, "faccessat/faccessat2");
          fs_op[*fs_op_idx].op[0] = 'R';
          fs_op[*fs_op_idx].file_type = '?';
          (*fs_op_idx)++;
          break;
        }
        // int access(const char *pathname, int mode);
        case __NR_access:
        {
          read_maybe_relative_pathname_from_tracee(child_pid, arg0, fs_op[*fs_op_idx].path, PATH_MAX);
          sprintf(fs_op[*fs_op_idx].comment, "access");
          fs_op[*fs_op_idx].op[0] = 'R';
          fs_op[*fs_op_idx].file_type = '?';
          (*fs_op_idx)++;
          break;
        }
        // int unlinkat(int dirfd, const char *pathname, int flags);
        case __NR_unlinkat:
        {
          parse_dirfd_pathname_from_tracee(child_pid, arg0, arg1, fs_op[*fs_op_idx].path, PATH_MAX);
          sprintf(fs_op[*fs_op_idx].comment, "unlinkat");
          fs_op[*fs_op_idx].op[0] = 'D';
          fs_op[*fs_op_idx].file_type = '?';
          (*fs_op_idx)++;
          break;
        }
        // int unlink(const char *pathname);
        case __NR_unlink:
        {
          read_cstring_from_tracee(child_pid, arg0, fs_op[*fs_op_idx].path, PATH_MAX);
          sprintf(fs_op[*fs_op_idx].comment, "unlink");
          fs_op[*fs_op_idx].op[0] = 'D';
          fs_op[*fs_op_idx].file_type = '?';
          (*fs_op_idx)++;
          break;
        }
        // int rmdir(const char *pathname);
        case __NR_rmdir:
        {
          read_cstring_from_tracee(child_pid, arg0, fs_op[*fs_op_idx].path, PATH_MAX);
          sprintf(fs_op[*fs_op_idx].comment, "rmdir");
          fs_op[*fs_op_idx].op[0] = 'D';
          fs_op[*fs_op_idx].file_type = '?';
          (*fs_op_idx)++;
          break;
        }
        // int rename(const char *oldpath, const char *newpath);
        case __NR_rename:
        {
          read_maybe_relative_pathname_from_tracee(child_pid, arg0, fs_op[*fs_op_idx].path, PATH_MAX);
          sprintf(fs_op[*fs_op_idx].comment, "rename");
          fs_op[*fs_op_idx].op[0] = 'D';
          fs_op[*fs_op_idx].file_type = '?';
          (*fs_op_idx)++;
          sprintf(fs_op[*fs_op_idx].comment, "rename");
          read_maybe_relative_pathname_from_tracee(child_pid, arg1, fs_op[*fs_op_idx].path, PATH_MAX);
          fs_op[*fs_op_idx].op[0] = 'W';
          fs_op[*fs_op_idx].file_type = '?';
          (*fs_op_idx)++;
          break;
        }
        // int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath);
        // int renameat2(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags);
        case __NR_renameat:
        case __NR_renameat2:
        {
          parse_dirfd_pathname_from_tracee(child_pid, arg0, arg1, fs_op[*fs_op_idx].path, PATH_MAX);
          sprintf(fs_op[*fs_op_idx].comment, "renameat/renameat2");
          fs_op[*fs_op_idx].op[0] = 'D';
          fs_op[*fs_op_idx].file_type = '?';
          (*fs_op_idx)++;
          sprintf(fs_op[*fs_op_idx].comment, "renameat/renameat2");
          parse_dirfd_pathname_from_tracee(child_pid, arg2, arg3, fs_op[*fs_op_idx].path, PATH_MAX);
          fs_op[*fs_op_idx].op[0] = 'W';
          fs_op[*fs_op_idx].file_type = '?';
          (*fs_op_idx)++;
          break;
        }
        // long getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count);
        // ssize_t getdents64(int fd, void *dirp, size_t count);
        case __NR_getdents:
        case __NR_getdents64:
        {
          get_fd_path(child_pid, arg0, fs_op[*fs_op_idx].path);
          sprintf(fs_op[*fs_op_idx].comment, "getdents/getdents64");
          fs_op[*fs_op_idx].op[0] = 'E';
          fs_op[*fs_op_idx].file_type = '?';
          (*fs_op_idx)++;
          break;
        }
        // int chmod(const char *pathname, mode_t mode);
        case __NR_chmod:
        {
          read_cstring_from_tracee(child_pid, arg0, fs_op[*fs_op_idx].path, PATH_MAX);
          sprintf(fs_op[*fs_op_idx].comment, "chmod");
          fs_op[*fs_op_idx].op[0] = 'W';
          fs_op[*fs_op_idx].file_type = '?';
          (*fs_op_idx)++;
          break;
        }
        // int symlink(const char *target, const char *linkpath);
        case __NR_symlink:
        {
          read_maybe_relative_pathname_from_tracee(child_pid, arg1, fs_op[*fs_op_idx].path, PATH_MAX);
          sprintf(fs_op[*fs_op_idx].comment, "symlink");
          fs_op[*fs_op_idx].op[0] = 'W';
          fs_op[*fs_op_idx].file_type = '?';
          (*fs_op_idx)++;
          break;
        }
        // int symlinkat(const char *target, int newdirfd, const char *linkpath);
        case __NR_symlinkat:
        {
          parse_dirfd_pathname_from_tracee(child_pid, arg1, arg2, fs_op[*fs_op_idx].path, PATH_MAX);
          sprintf(fs_op[*fs_op_idx].comment, "symlinkat");
          fs_op[*fs_op_idx].op[0] = 'W';
          fs_op[*fs_op_idx].file_type = '?';
          (*fs_op_idx)++;
          break;
        }
        // int linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags);
        case __NR_linkat:
        {
          parse_dirfd_pathname_from_tracee(child_pid, arg2, arg3, fs_op[*fs_op_idx].path, PATH_MAX);
          sprintf(fs_op[*fs_op_idx].comment, "linkat");
          fs_op[*fs_op_idx].op[0] = 'W';
          fs_op[*fs_op_idx].file_type = '?';
          (*fs_op_idx)++;
          break;
        }
        // int link(const char *oldpath, const char *newpath);
        case __NR_link:
        {
          read_maybe_relative_pathname_from_tracee(child_pid, arg1, fs_op[*fs_op_idx].path, PATH_MAX);
          sprintf(fs_op[*fs_op_idx].comment, "link");
          fs_op[*fs_op_idx].op[0] = 'W';
          fs_op[*fs_op_idx].file_type = '?';
          (*fs_op_idx)++;
          break;
        }
        // int mkdir(const char *pathname, mode_t mode);
        case __NR_mkdir:
        {
          read_cstring_from_tracee(child_pid, arg0, fs_op[*fs_op_idx].path, PATH_MAX);
          sprintf(fs_op[*fs_op_idx].comment, "mkdir");
          fs_op[*fs_op_idx].op[0] = 'C';
          fs_op[*fs_op_idx].file_type = '?';
          (*fs_op_idx)++;
          break;
        }
        // int mkdirat(int dirfd, const char *pathname, mode_t mode);
        case __NR_mkdirat:
        {
          parse_dirfd_pathname_from_tracee(child_pid, arg0, arg1, fs_op[*fs_op_idx].path, PATH_MAX);
          sprintf(fs_op[*fs_op_idx].comment, "mkdirat");
          fs_op[*fs_op_idx].op[0] = 'C';
          fs_op[*fs_op_idx].file_type = '?';
          (*fs_op_idx)++;
          break;
        }
        // int utime(const char *filename, const struct utimbuf *times);
        case __NR_utime:
        // int utimes(const char *filename, const struct timeval times[2]);
        case __NR_utimes:
        {
          read_cstring_from_tracee(child_pid, arg0, fs_op[*fs_op_idx].path, PATH_MAX);
          sprintf(fs_op[*fs_op_idx].comment, "utime/utimes");
          fs_op[*fs_op_idx].op[0] = 'W';
          fs_op[*fs_op_idx].file_type = '?';
          (*fs_op_idx)++;
          break;
        }
        // int truncate(const char *path, off_t length);
        case __NR_truncate:
        {
          read_cstring_from_tracee(child_pid, arg0, fs_op[*fs_op_idx].path, PATH_MAX);
          sprintf(fs_op[*fs_op_idx].comment, "truncate");
          fs_op[*fs_op_idx].op[0] = 'W';
          fs_op[*fs_op_idx].file_type = '?';
          (*fs_op_idx)++;
          break;
        }
        }
        // LOG_DEBUG("PTRACE_SYSCALL_INFO_SECCOMP END: %llu", nr)
        if (ptrace_syscall(child_pid, 0) != 0)
        {
          return -1;
        }
      }

      else if (info.op == PTRACE_SYSCALL_INFO_EXIT)
      {
        struct pid_info *thread_op;
        thread_op = &pid_info_map[child_pid];
        struct fs_operation *fs_op = thread_op->fs_ops;
        int *fs_op_idx = &thread_op->fs_op_idx;

        // LOG_DEBUG("Child %d stopped by syscall exit. nr: %llu", child_pid, thread_op->nr)

        long rVal = info.exit.rval;
        long isError = info.exit.is_error;

        LOG_DEBUG("Child %d PTRACE_SYSCALL_INFO_EXIT BEGIN: %llu. rVal: %ld, isError: %ld", child_pid, thread_op->nr,
                  rVal, isError)

        if (isError)
        {
          if (rVal == -ENOENT)
          {
            // LOG_DEBUG("ENOENT file %s does not exist", fs_op[0].path)
            fs_op[0].file_type = 'X';
          }
          else if (rVal == -EBADF)
          {
            LOG_DEBUG("PTRACE_CONT pid: %d", child_pid)
            if (ptrace(PTRACE_CONT, child_pid, 0, 0) != 0)
            {
              fprintf(stderr, "\nptrace(PTRACE_CONT)\n");
              fprintf(stderr, "Error: %s\n", strerror(errno));
              return -1;
            }
            continue;
          }
        }
        else
        {
          struct stat *stat_result = (struct stat *)malloc(sizeof(struct stat));
          switch (thread_op->nr)
          {
            /*
            __NR_access
            __NR_open
            __NR_creat
            __NR_openat
            __NR_openat2
            __NR_chmod
            __NR_utime
            __NR_utimes
            __NR_truncate
            */
          case __NR_rmdir:
          case __NR_unlink:
          case __NR_unlinkat:
          {
            fs_op[0].file_type = 'X';
            break;
          }
          case __NR_symlink:
          case __NR_symlinkat:
          case __NR_linkat:
          case __NR_link:
          case __NR_readlinkat:
          case __NR_readlink:
          {
            fs_op[0].file_type = 'L';
            break;
          }

          case __NR_execveat:
          case __NR_execve:
          {
            fs_op[0].file_type = 'F';
            break;
          }

          case __NR_mkdirat:
          case __NR_mkdir:
          case __NR_getdents:
          case __NR_getdents64:
          {
            fs_op[0].file_type = 'D';
            break;
          }
          case __NR_lstat:
          case __NR_stat:
          {
            read_struct_from_tracee(child_pid, thread_op->args[1], stat_result, sizeof(struct stat));
            fs_op[0].file_type = GET_FILE_TYPE_FROM_STAT_RESULT(stat_result);
            break;
          }
          case __NR_statx:
          {
            read_struct_from_tracee(child_pid, thread_op->args[4], stat_result, sizeof(struct stat));
            fs_op[0].file_type = GET_FILE_TYPE_FROM_STAT_RESULT(stat_result);
            break;
          }
          case __NR_newfstatat:
          {
            read_struct_from_tracee(child_pid, thread_op->args[2], stat_result, sizeof(struct stat));
            fs_op[0].file_type = GET_FILE_TYPE_FROM_STAT_RESULT(stat_result);
            break;
          }
          case __NR_rename:
          case __NR_renameat:
          case __NR_renameat2:
          {
            fs_op[0].file_type = 'X';
            fs_op[1].file_type = '?';
            break;
          }
          }
        }
        // LOG_DEBUG("fs_op_idx: %d", *fs_op_idx)

        for (int i = 0; i < *fs_op_idx; i++)
        {
          // skip failed writes
          if (fs_op[i].op[0] == 'W' && isError)
          {
            continue;
          }
          if (strncmp((fs_op[i]).path, "/proc/", 6) == 0 || strncmp((fs_op[i]).path, "/dev/", 5) == 0 ||
              strncmp((fs_op[i]).path, "pipe:[", 6) == 0)
          {
            continue;
          }
          if (strncmp((fs_op[i]).path, "/usr/lib/", 9) == 0)
          {
            continue;
          }

          char file_type = fs_op->file_type;
#if DEBUG
          if (file_type != '?')
          {
            // LOG_DEBUG("file_type found.")
          }
#endif
          if (file_type == '?')
          {
            // LOG_DEBUG("file_type missing. stating %s", (fs_op[i]).path)
            struct stat stat_result;
            if (stat((fs_op[i]).path, &stat_result) == 0)
            {
              file_type = GET_FILE_TYPE_FROM_STAT_RESULT(&stat_result);
            }
            else
            {
              if (errno == ENOENT || errno == ENOTDIR)
              {
                file_type = 'X';
              }
            }
          }

          if ((fs_op[i]).path[strlen((fs_op[i]).path) - 1] == '/')
          {
            (fs_op[i]).path[strlen((fs_op[i]).path) - 1] = '\0';
          }

#ifdef DEBUG
          if (strlen((fs_op[i]).comment) > 0)
          {
            LOG_DEBUG("# %s", (fs_op[i]).comment)
            LOG_DEBUG("%c%c %s", (fs_op[i]).op[0], file_type, (fs_op[i]).path)
            dprintf(3, "# %s\n%c%c %s\n", (fs_op[i]).comment, (fs_op[i]).op[0], file_type, (fs_op[i]).path);
          }
          else
          {
            LOG_DEBUG("%c%c %s\n", (fs_op[i]).op[0], file_type, (fs_op[i]).path)
            dprintf(3, "%c%c %s\n", (fs_op[i]).op[0], file_type, (fs_op[i]).path);
          }
#else
          dprintf(3, "# %s\n%c%c %s\n", (fs_op[i]).comment, (fs_op[i]).op[0], file_type, (fs_op[i]).path);
          // dprintf(3, "BEGIN%c%c %sEND\n", (fs_op[i]).op[0], file_type, (fs_op[i]).path);
#endif
        }
        // LOG_DEBUG("PTRACE_SYSCALL_INFO_EXIT END: %llu. rVal: %ld, isError: %ld", thread_op->nr, rVal, isError)
        LOG_DEBUG("PTRACE_CONT pid: %d", child_pid)
        if (ptrace(PTRACE_CONT, child_pid, 0, 0) != 0)
        {
          fprintf(stderr, "\nptrace(PTRACE_CONT)\n");
          fprintf(stderr, "Error: %s\n", strerror(errno));
          return -1;
        }
      }

      // LOG_DEBUG("END handle_syscall")
      // LOG_DEBUG("==============================")
    }
    else if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_VFORK << 8)))
    {
#if DEBUG
      // get the PID of the new process
      pid_t new_child_pid;
      if (ptrace(PTRACE_GETEVENTMSG, child_pid, 0, &new_child_pid) == -1)
      {
        fprintf(stderr, "\nPTRACE_EVENT_VFORK ptrace(PTRACE_GET_EVENTMSG)\n");
        fprintf(stderr, "Error: %s\n", strerror(errno));
        return -1;
      }
      LOG_DEBUG("Child %d stopped by vfork (new child %d)\n", child_pid, new_child_pid)
      char cmdline_buf[PATH_MAX];
      read_cmdline(new_child_pid, cmdline_buf);
      LOG_DEBUG("new_child_pid: %d, cmdline: %s", new_child_pid, cmdline_buf)
#endif

      if (ptrace_syscall(child_pid, WSTOPSIG(status)) != 0)
      {
        return -1;
      }
    }
    else if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_FORK << 8)))
    {
#if DEBUG
      pid_t new_child_pid;
      if (ptrace(PTRACE_GETEVENTMSG, child_pid, 0, &new_child_pid) == -1)
      {
        fprintf(stderr, "\nPTRACE_EVENT_FORK ptrace(PTRACE_GETEVENTMSG)\n");
        fprintf(stderr, "Error: %s\n", strerror(errno));
        return -1;
      }
      LOG_DEBUG("Child %d stopped by fork (new child %d)", child_pid, new_child_pid)
      char cmdline_buf[PATH_MAX];
      read_cmdline(new_child_pid, cmdline_buf);
      LOG_DEBUG("new_child_pid: %d, cmdline: %s", new_child_pid, cmdline_buf)
#endif
      if (ptrace_syscall(child_pid, WSTOPSIG(status)) != 0)
      {
        return -1;
      }
    }
    else if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_CLONE << 8)))
    {
#if DEBUG
      pid_t new_child_pid;
      if (ptrace(PTRACE_GETEVENTMSG, child_pid, 0, &new_child_pid) == -1)
      {
        fprintf(stderr, "\nPTRACE_EVENT_CLONE ptrace(PTRACE_GETEVENTMSG)\n");
        fprintf(stderr, "Error: %s\n", strerror(errno));
        return -1;
      }
      LOG_DEBUG("Child %d stopped by clone (new child %d)", child_pid, new_child_pid)
      char cmdline_buf[PATH_MAX];
      read_cmdline(new_child_pid, cmdline_buf);
      LOG_DEBUG("new_child_pid: %d, cmdline: %s", new_child_pid, cmdline_buf)
#endif
      if (ptrace_syscall(child_pid, WSTOPSIG(status)) != 0)
      {
        return -1;
      }
    }
    else if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_EXEC << 8)))
    {
#if DEBUG
      LOG_DEBUG("Child %d stopped by exec", child_pid)
      char cmdline_buf[PATH_MAX];
      read_cmdline(child_pid, cmdline_buf);
      LOG_DEBUG("child_pid: %d, cmdline: %s", child_pid, cmdline_buf)
#endif
      if (ptrace_syscall(child_pid, WSTOPSIG(status)) != 0)
      {
        return -1;
      }
    }
    else if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_EXIT << 8)))
    {
      // get the exit status of the child
#if DEBUG
      unsigned long traceeStatus = 0;
      if (ptrace(PTRACE_GETEVENTMSG, child_pid, 0, &traceeStatus) == -1)
      {
        if (errno)
        {
          if (errno == ESRCH)
          {
            LOG_DEBUG("Child %d died unexpectedly", child_pid)
            if (child_pid == initial_pid)
            {
              exit(0);
            }
            pid_info_map.erase(child_pid);
            continue;
          }
        }
        else
        {
          LOG_DEBUG("Child %d exited with code %lu", child_pid, traceeStatus)
          fprintf(stderr, "\nPTRACE_EVENT_EXIT ptrace(PTRACE_GETEVENTMSG)\n");
          fprintf(stderr, "Error: %s\n", strerror(errno));
          return -1;
        }
      }
#endif
      if (ptrace_syscall(child_pid, WSTOPSIG(status)) != 0)
      {
        return -1;
      }
    }
    else if (WIFSTOPPED(status) && !(WSTOPSIG(status) & 0x80))
    {
      LOG_DEBUG("Child %d. stopped with signal %d", child_pid, WSTOPSIG(status))
      if (ptrace_syscall(child_pid, WSTOPSIG(status)) != 0)
      {
        return -1;
      }
    }
    else
    {
      LOG_DEBUG("Child %d. unexpected stop. status: %d", child_pid, status)
      if (ptrace_syscall(child_pid, NULL) != 0)
      {
        return -1;
      }
    }
  }

  return 0;
}

int trace_exec(char *program, char **args)
{
  pid_t child_pid = fork();

  if (child_pid == 0)
  {
    run_tracee(program, args);
    fprintf(stderr, "\nexecvp error\n");
    return 1;
  }
  else if (child_pid > 0)
  {
    if (run_tracer(child_pid) != 0)
    {
      return 1;
    }
  }
  else
  {
    fprintf(stderr, "\nfork\n");
    return 1;
  }

  return 0;
}
