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
#include <sys/time.h>
#include <linux/types.h>
#include <map>
#include <stddef.h>
#include <sys/reg.h>
#include <sys/prctl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#ifndef DEBUGFD
#define DEBUGFD 1
#endif

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

void normalize_path(char *fullpath)
{
  char *cursor = fullpath;
  char *cursor_end = fullpath + strlen(fullpath);
  char *output_cursor = fullpath;

  while (cursor < cursor_end)
  {
    if (cursor[0] == '/' && cursor[1] == '/')
    {
      // Skip consecutive slashes
      cursor++;
    }
    else if (cursor[0] == '/' && cursor[1] == '.' && cursor[2] == '/')
    {
      // Skip "/./"
      cursor += 2;
    }
    else if (cursor[0] == '/' && cursor[1] == '.' && cursor[2] == '.' && cursor[3] == '/')
    {
      // Handle "/../" by moving back one directory
      cursor += 3;
      if (output_cursor > fullpath)
      {
        output_cursor--;
        while (output_cursor > fullpath && *output_cursor != '/')
        {
          output_cursor--;
        }
      }
    }
    else
    {
      // Copy the current character to the output
      *output_cursor++ = *cursor++;
    }
  }
  // Null-terminate the resulting string
  *output_cursor = '\0';
}

extern char **environ;

int prepare_tracee()
{
  struct sock_filter filter[] = {
      // BPF_STMT(opcode,	operand)
      // BPF_JUMP(opcode, operand, true_offset, false_offset).
      // BPF_JMP + BPF_JEQ + BPF_K: pc += (A == k)	? jt : jf
      // BPF_LD + BPF_W + BPF_ABS = load word at fixed offset into accumulator
      // BPF_JMP + BPF_JSET + BPF_K: pc += (A & k) ? jt : jf
      // BPF_RET + BPF_K = return constant
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, nr)),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_statx, 7, 0),      // flags arg[2]
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_openat, 6, 0),     // flags arg[2]
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_unlinkat, 5, 0),   // flags arg[2]
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_faccessat, 6, 0),  // flags arg[3]
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_faccessat2, 5, 0), // flags arg[3]
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_newfstatat, 4, 0), // flags arg[3]
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_execveat, 5, 0),   // flags arg[4]
      BPF_JUMP(BPF_JMP + BPF_JA + BPF_K, 8, 0, 0),
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, args[2])),
      BPF_JUMP(BPF_JMP + BPF_JSET + BPF_K, AT_EMPTY_PATH, 4, 5),
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, args[3])),
      BPF_JUMP(BPF_JMP + BPF_JSET + BPF_K, AT_EMPTY_PATH, 2, 3),
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, args[4])),
      BPF_JUMP(BPF_JMP + BPF_JSET + BPF_K, AT_EMPTY_PATH, 0, 1),
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_TRACE),

      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_open, 25, 0),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_creat, 24, 0),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_openat2, 23, 0),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_readlink, 22, 0),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_readlinkat, 21, 0),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_lstat, 20, 0),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_stat, 19, 0),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_access, 18, 0),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_fchdir, 17, 0),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_chdir, 16, 0),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_execve, 15, 0),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_unlink, 14, 0),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_rmdir, 13, 0),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_rename, 12, 0),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_renameat, 11, 0),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_renameat2, 10, 0),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_getdents, 9, 0),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_getdents64, 8, 0),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_symlinkat, 7, 0),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_linkat, 6, 0),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_link, 5, 0),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_mkdir, 4, 0),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_mkdirat, 3, 0),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_truncate, 2, 0),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_symlink, 1, 0),
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_TRACE),
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

  return 0;
}

struct fs_operation
{
  char path[PATH_MAX];
  char op[1];
  char comment[1000];
  char file_type;
};

int get_fd_path(pid_t proc_pid, std::map<unsigned long, char *> fd_cache, long long fd, char *buf)
{
  unsigned bufsize = PATH_MAX;
  char linkpath[PATH_MAX];
  int n;

  if (fd < 0)
  {
    return -1;
  }

  if (fd_cache.find(fd) != fd_cache.end())
  {
    strncpy(buf, fd_cache[fd], bufsize);
    LOG_DEBUG("fd_cache: hit %lld %s", fd, buf)
    return strlen(buf);
  }

  sprintf(linkpath, "/proc/%u/fd/%lld", proc_pid, fd);
  n = readlink(linkpath, buf, bufsize - 1);
  if (n < 0)
  {
    return n;
  }

  buf[n] = '\0';
  fd_cache[fd] = strdup(buf);
  LOG_DEBUG("fd_cache: save (miss) %lld %s", fd, buf)

  return n;
}

#define ROUND_UP_TO_MULTIPLE(value, multiple) (((value) + (multiple) - 1) / (multiple) * (multiple));

void read_memory_from_tracee(pid_t pid, __u64 addr, void *buffer, size_t buffer_size)
{
  LOG_DEBUG("[PID: %d] read_memory_from_tracee(pid=%d, addr=%p, buffer=%p, buffer_size=%zu)", getpid(), pid, addr,
            buffer, buffer_size)
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
  LOG_DEBUG("[PID: %d] read_struct_from_tracee(pid=%d, addr=%p, buffer=%p, buffer_size=%zu)", pid, pid, addr, buffer,
            buffer_size)
  read_memory_from_tracee(pid, addr, buffer, buffer_size);
}

void read_cstring_from_tracee(pid_t pid, __u64 addr, char *buffer, size_t buffer_size)
{
  LOG_DEBUG("[PID: %d] read_cstring_from_tracee(pid=%d, addr=%p, buffer=%p, buffer_size=%zu)", pid, pid, addr, buffer,
            buffer_size)
  if (addr == NULL)
  {
    buffer[0] = '\0';
    return;
  }
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
    LOG_DEBUG("[PID: %d] read_cstring_from_tracee - ptrace(PTRACE_PEEKDATA) failed", pid)
    fprintf(stderr, "[PID: %d] read_cstring_from_tracee - ptrace(PTRACE_PEEKDATA) failed", pid);
    return;
  }

  memcpy(buffer, data, buffer_size);
  free(data);

  return;
}

void read_maybe_relative_pathname_from_tracee(pid_t pid, char *cwd, __u64 addr, char *buffer, size_t buffer_size)
{
  LOG_DEBUG("[PID: %d] read_maybe_relative_pathname_from_tracee(pid=%d, cwd=%s, addr=%p, buffer=%p, buffer_size=%zu)",
            pid, pid, cwd, addr, buffer, buffer_size)
  LOG_DEBUG("cwd: %s", cwd)
  read_cstring_from_tracee(pid, addr, buffer, buffer_size);
  LOG_DEBUG("buffer: %s", buffer)

  if (buffer[0] != '/')
  {
    if (strlen(cwd) == 0)
    {
      LOG_DEBUG("[PID: %d] read_maybe_relative_pathname_from_tracee. cwd cache not available. reading cwd", pid)
      char cwd_link_path[PATH_MAX];
      sprintf(cwd_link_path, "/proc/%u/cwd", pid);
      if (readlink(cwd_link_path, cwd, PATH_MAX) == -1)
      {
        LOG_DEBUG("[PID: %d] read_maybe_relative_pathname_from_tracee - readlink failed", pid)
        fprintf(stderr, "[PID: %d] read_maybe_relative_pathname_from_tracee - readlink failed", pid);
        return;
      }
    }
#if DEBUG
    else
    {
      LOG_DEBUG("[PID: %d] read_maybe_relative_pathname_from_tracee. cwd cache available. cwd: %s", pid, cwd)
    }
#endif

    if (strlen(buffer) == 1 && buffer[0] == '.')
    {
      strncpy(buffer, cwd, buffer_size);
      return;
    }

    if (buffer[0] == '.' && buffer[1] == '/')
    {
      char temp_buffer[PATH_MAX];
      snprintf(temp_buffer, PATH_MAX, "%s%s", cwd, buffer + 1);
      strncpy(buffer, temp_buffer, buffer_size);
    }
    else
    {
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
}

void parse_dirfd_pathname_from_tracee(pid_t pid, std::map<unsigned long, char *> fd_cache, __u64 dirfd, __u64 pathname,
                                      char *fullpath, size_t fullpath_size)
{
  LOG_DEBUG("parse_dirfd_pathname_from_tracee")
  char path[PATH_MAX];
  read_cstring_from_tracee(pid, pathname, path, PATH_MAX);
  // LOG_DEBUG("path: %s", path)
  if (path[0] == '/')
  {
    LOG_DEBUG("path is absolute")
    sprintf(fullpath, "%s", path);
  }
  else
  {
    LOG_DEBUG("path is relative")
    char dirpath[PATH_MAX];
    get_fd_path(pid, fd_cache, dirfd, dirpath);
    // LOG_DEBUG("dirpath: %s", dirpath)
    if (strlen(path) == 0)
    {
      snprintf(fullpath, fullpath_size, "%s", dirpath);
    }
    else
    {
      snprintf(fullpath, fullpath_size, "%s/%s", dirpath, path);
    }
    normalize_path(fullpath);
  }
  // LOG_DEBUG("fullpath: %s", fullpath)
}

void parse_at_syscall_dirfd_pathname_from_tracee(pid_t pid, std::map<unsigned long, char *> fd_cache, char *cwd,
                                                 __u64 dirfd, __u64 pathname, char *fullpath, size_t fullpath_size)
{
  if ((int)dirfd == AT_FDCWD)
  {
    read_maybe_relative_pathname_from_tracee(pid, cwd, pathname, fullpath, fullpath_size);
  }
  else
  {
    parse_dirfd_pathname_from_tracee(pid, fd_cache, dirfd, pathname, fullpath, fullpath_size);
  }
}

void parse_at_syscall_with_flags_dirfd_pathname_from_tracee(pid_t pid, std::map<unsigned long, char *> fd_cache,
                                                            char *cwd, long flags, __u64 dirfd, __u64 pathname,
                                                            char *fullpath, size_t fullpath_size)
{
  if ((int)dirfd == AT_FDCWD)
  {
    if (flags & AT_EMPTY_PATH)
    {
      LOG_DEBUG("AT_EMPTY_PATH")
      get_fd_path(pid, fd_cache, dirfd, fullpath);
    }
    else
    {
      read_maybe_relative_pathname_from_tracee(pid, cwd, pathname, fullpath, fullpath_size);
    }
  }
  else
  {
    parse_dirfd_pathname_from_tracee(pid, fd_cache, dirfd, pathname, fullpath, fullpath_size);
  }
}

#define GET_FILE_TYPE_FROM_STAT_RESULT_MODE(stat_result_mode)                                                          \
  (S_ISDIR((stat_result_mode)) ? 'D' : (S_ISREG((stat_result_mode)) ? 'F' : (S_ISLNK((stat_result_mode)) ? 'L' : '?')))

struct pid_info
{
  pid_t ppid;
  pid_t pid;
  unsigned long long nr;
  unsigned long long args[6];
  char cwd[PATH_MAX];
  std::map<unsigned long, char *> fd_cache;
  timeval start_time;
  char comment[1000];
  union
  {
    struct
    {
      long long fd;
    } op_close;
    struct
    {
      char path[PATH_MAX];
    } op_chdir;
    struct
    {
      char oldpath[PATH_MAX];
      char newpath[PATH_MAX];
    } op_rename;
    struct
    {
      char path[PATH_MAX];
      long flags;
    } op_open;
    struct
    {
      char path[PATH_MAX];
      struct stat *statbuf;
    } op_stat;
    struct
    {
      char path[PATH_MAX];
      struct statx *statxbuf;
    } op_statx;
    struct
    {
      char path[PATH_MAX];
    } op_exec;
    struct
    {
      char path[PATH_MAX];
    } op_readlink;
    struct
    {
      char path[PATH_MAX];
    } op_access;
    struct
    {
      char path[PATH_MAX];
      long flags;
    } op_faccessat;
    struct
    {
      char path[PATH_MAX];
    } op_unlink;
    struct
    {
      char path[PATH_MAX];
    } op_getdents;
    struct
    {
      char path[PATH_MAX];
    } op_chmod;
    struct
    {
      char linkpath[PATH_MAX];
    } op_link;
    struct
    {
      char path[PATH_MAX];
    } op_mkdir;
    struct
    {
      char path[PATH_MAX];
    } op_utime;
    struct
    {
      char path[PATH_MAX];
    } op_truncate;
  };
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

int ptrace_cont(pid_t child_pid, int status)
{
  LOG_DEBUG("PTRACE_CONT pid: %d", child_pid)
  if (ptrace(PTRACE_CONT, child_pid, 0, status) != 0)
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
        fprintf(stderr, "\nchild %d ptrace(PTRACE_CONT)\n", child_pid);
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
  LOG_DEBUG("[PID: %d] run_tracer(pid=%d)", child_pid, child_pid)

  int status = 0;
  LOG_DEBUG("[PID: %d] waiting for initial stop", child_pid)
  do
  {
    wait4(child_pid, &status, 0, NULL);
  } while (!WIFSTOPPED(status));
  LOG_DEBUG("[PID: %d] initial stop hit", child_pid)

  int ptrace_options = 0;
  ptrace_options |= PTRACE_O_TRACESECCOMP;
  ptrace_options |= PTRACE_O_TRACESYSGOOD;
  ptrace_options |= PTRACE_O_EXITKILL;
  ptrace_options |= PTRACE_O_TRACEFORK;
  ptrace_options |= PTRACE_O_TRACEEXEC;
  ptrace_options |= PTRACE_O_TRACEVFORK;
  ptrace_options |= PTRACE_O_TRACECLONE;
  ptrace_options |= PTRACE_O_TRACEEXIT;

  LOG_DEBUG("[PID: %d] set ptrace options %d", child_pid, ptrace_options)
  if (ptrace(PTRACE_SETOPTIONS, child_pid, 0, ptrace_options) == -1)
  {
    LOG_DEBUG("[PID: %d] ptrace(PTRACE_SETOPTIONS)", child_pid)
    fprintf(stderr, "[PID: %d] ptrace(PTRACE_SETOPTIONS)\n", child_pid);
    exit(-1);
  }
  LOG_DEBUG("[PID: %d] continue from initial stop", child_pid)
  if (ptrace(PTRACE_CONT, child_pid, 0, 0) == -1)
  {
    LOG_DEBUG("[PID: %d] ptrace(PTRACE_CONT) failed. Error: %s", child_pid, strerror(errno))
    fprintf(stderr, "[PID: %d] ptrace(PTRACE_CONT) failed. Error: %s\n", child_pid, strerror(errno));
    exit(-1);
  }

  struct timeval end_time;
  struct stat stat_result;

  struct open_how temp_open_how;

#define PATH_FILTER(path)                                                                                              \
  path[0] == '\0' || path[0] != '/' /* filter pipe:[], socket:[] */ || strncmp(path, "/proc/", 6) == 0 ||              \
      strncmp(path, "/dev/", 5) == 0 || strstr(path, "/.pnpm/") != NULL

#define SYS_ENTER_PATH_FITLER(path)                                                                                    \
  if (PATH_FILTER(path))                                                                                               \
  {                                                                                                                    \
    LOG_DEBUG("[PID: %d] SYS_ENTER_PATH_FITLER: continue. uninteresting path %s", child_pid, path)                     \
    if (ptrace_cont(child_pid, 0) != 0)                                                                                \
    {                                                                                                                  \
      return -1;                                                                                                       \
    }                                                                                                                  \
  }                                                                                                                    \
  else                                                                                                                 \
  {                                                                                                                    \
    if (ptrace_syscall(child_pid, 0) != 0)                                                                             \
    {                                                                                                                  \
      return -1;                                                                                                       \
    }                                                                                                                  \
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
      LOG_DEBUG("[PID: %d] child exited with status %d", child_pid, WSTOPSIG(status))
      if (child_pid == initial_pid)
      {
        LOG_DEBUG("[PID: %d] initial child exited", child_pid)
        exit(WSTOPSIG(status));
        break;
      }
      continue;
    }
    else if (!WIFSTOPPED(status))
    {
      LOG_DEBUG("[PID: %d] waitpid returned unhandled status %d", child_pid, status)
      fprintf(stderr, "[PID: %d] waitpid returned unhandled status %d\n", child_pid, status);
      return -1;
    }
    else if ((WIFSTOPPED(status) && (WSTOPSIG(status) & 0x80)) ||
             (status >> 8 == (SIGTRAP | (PTRACE_EVENT_SECCOMP << 8))))
    {
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
        LOG_DEBUG("[PID: %d] Child stopped by seccomp or syscall entry. nr: %llu", child_pid, info.entry.nr)
        struct pid_info *thread_op;
        thread_op = &pid_info_map[child_pid];

#if DEBUG
        gettimeofday(&thread_op->start_time, NULL);
#endif

        thread_op = &pid_info_map[child_pid];
        thread_op->nr = info.entry.nr;
        memcpy(thread_op->args, info.entry.args, sizeof(info.entry.args));

        unsigned long long nr = thread_op->nr;
        unsigned long long arg0 = thread_op->args[0];
        unsigned long long arg1 = thread_op->args[1];
        unsigned long long arg2 = thread_op->args[2];
        unsigned long long arg3 = thread_op->args[3];
        unsigned long long arg4 = thread_op->args[4];
        // unsigned long long arg5 = thread_op->args[5];
        thread_op->comment[0] = '\0';

        // LOG_DEBUG("PTRACE_SYSCALL_INFO_SECCOMP BEGIN: %llu", nr)

        switch (nr)
        {
        // int chdir(const char *path);
        case __NR_chdir:
        {
          read_maybe_relative_pathname_from_tracee(child_pid, thread_op->cwd, arg0, thread_op->op_chdir.path, PATH_MAX);
          SYS_ENTER_PATH_FITLER(thread_op->op_chdir.path)
          break;
        }
        // int fchdir(int fd);
        case __NR_fchdir:
        {
          get_fd_path(child_pid, thread_op->fd_cache, arg0, thread_op->op_chdir.path);
          SYS_ENTER_PATH_FITLER(thread_op->op_chdir.path)
          break;
        }
        // int execve(const char *pathname, char *const argv[], char *const envp[]);
        case __NR_execve:
        {
          read_maybe_relative_pathname_from_tracee(child_pid, thread_op->cwd, arg0, thread_op->op_exec.path, PATH_MAX);
          SYS_ENTER_PATH_FITLER(thread_op->op_exec.path)
          break;
        }
        // int execveat(int dirfd, const char *pathname, char *const argv[], char *const envp[], int flags);
        case __NR_execveat:
        {
          parse_at_syscall_with_flags_dirfd_pathname_from_tracee(child_pid, thread_op->fd_cache, thread_op->cwd, arg4,
                                                                 arg0, arg1, thread_op->op_exec.path, PATH_MAX);
          SYS_ENTER_PATH_FITLER(thread_op->op_exec.path)
          break;
        }
        // int open(const char *pathname, int flags);
        // int open(const char *pathname, int flags, mode_t mode);
        case __NR_open:
        {
          read_maybe_relative_pathname_from_tracee(child_pid, thread_op->cwd, arg0, thread_op->op_open.path, PATH_MAX);
          thread_op->op_open.flags = arg1;
          SYS_ENTER_PATH_FITLER(thread_op->op_open.path)
          break;
        }
        // int creat(const char *pathname, mode_t mode);
        case __NR_creat:
        {
          read_maybe_relative_pathname_from_tracee(child_pid, thread_op->cwd, arg0, thread_op->op_open.path, PATH_MAX);
          thread_op->op_open.flags = O_CREAT;
          SYS_ENTER_PATH_FITLER(thread_op->op_open.path)
          break;
        }
        // int openat(int dirfd, const char *pathname, int flags);
        // int openat(int dirfd, const char *pathname, int flags, mode_t mode);
        case __NR_openat:
        {
          parse_at_syscall_with_flags_dirfd_pathname_from_tracee(child_pid, thread_op->fd_cache, thread_op->cwd, arg2,
                                                                 arg0, arg1, thread_op->op_open.path, PATH_MAX);
          thread_op->op_open.flags = arg2;
          SYS_ENTER_PATH_FITLER(thread_op->op_open.path)
          break;
        }
        // int openat2(int dirfd, const char *pathname, struct open_how *how, size_t size);
        case __NR_openat2:
        {
          __u64 flags;
          read_memory_from_tracee(child_pid, arg2, &flags, sizeof(flags));
          parse_at_syscall_with_flags_dirfd_pathname_from_tracee(child_pid, thread_op->fd_cache, thread_op->cwd, flags,
                                                                 arg0, arg1, thread_op->op_open.path, PATH_MAX);
          thread_op->op_open.flags = flags;
          SYS_ENTER_PATH_FITLER(thread_op->op_open.path)
          break;
        }
        // ssize_t readlink(const char *pathname, char *buf, size_t bufsiz);
        case __NR_readlink:
        {
          read_maybe_relative_pathname_from_tracee(child_pid, thread_op->cwd, arg0, thread_op->op_readlink.path,
                                                   PATH_MAX);
          SYS_ENTER_PATH_FITLER(thread_op->op_open.path)
          break;
        }
        // ssize_t readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz);
        case __NR_readlinkat:
        {
          parse_at_syscall_dirfd_pathname_from_tracee(child_pid, thread_op->fd_cache, thread_op->cwd, arg0, arg1,
                                                      thread_op->op_readlink.path, PATH_MAX);
          SYS_ENTER_PATH_FITLER(thread_op->op_readlink.path)
          break;
        }
        // int lstat(const char *pathname, struct stat *statbuf);
        // int stat(const char *pathname, struct stat *statbuf);
        case __NR_stat:
        case __NR_lstat:
        {
          read_maybe_relative_pathname_from_tracee(child_pid, thread_op->cwd, arg0, thread_op->op_stat.path, PATH_MAX);
          thread_op->op_stat.statbuf = (struct stat *)arg1;
          SYS_ENTER_PATH_FITLER(thread_op->op_stat.path)
          break;
        }
        // int statx(int dirfd, const char *pathname, int flags, unsigned int mask, struct statx *statxbuf);
        case __NR_statx:
        {
          parse_at_syscall_with_flags_dirfd_pathname_from_tracee(child_pid, thread_op->fd_cache, thread_op->cwd, arg2,
                                                                 arg0, arg1, thread_op->op_statx.path, PATH_MAX);
          thread_op->op_statx.statxbuf = (struct statx *)arg4;
          SYS_ENTER_PATH_FITLER(thread_op->op_statx.path)
          break;
        }
        // int fstatat(int dirfd, const char *pathname, struct stat *statbuf, int flags);
        case __NR_newfstatat:
        {
          parse_at_syscall_with_flags_dirfd_pathname_from_tracee(child_pid, thread_op->fd_cache, thread_op->cwd, arg3,
                                                                 arg0, arg1, thread_op->op_stat.path, PATH_MAX);
          thread_op->op_stat.statbuf = (struct stat *)arg2;
          SYS_ENTER_PATH_FITLER(thread_op->op_stat.path)
          break;
        }
        // int faccessat(int dirfd, const char *pathname, int mode, int flags);
        case __NR_faccessat:
        case __NR_faccessat2:
        {
          parse_at_syscall_with_flags_dirfd_pathname_from_tracee(child_pid, thread_op->fd_cache, thread_op->cwd, arg3,
                                                                 arg0, arg1, thread_op->op_faccessat.path, PATH_MAX);
          thread_op->op_faccessat.flags = arg3;
          SYS_ENTER_PATH_FITLER(thread_op->op_faccessat.path)
          break;
        }
        // int access(const char *pathname, int mode);
        case __NR_access:
        {
          read_maybe_relative_pathname_from_tracee(child_pid, thread_op->cwd, arg0, thread_op->op_access.path,
                                                   PATH_MAX);
          SYS_ENTER_PATH_FITLER(thread_op->op_access.path)
          break;
        }
        // int unlinkat(int dirfd, const char *pathname, int flags);
        case __NR_unlinkat:
        {
          parse_at_syscall_with_flags_dirfd_pathname_from_tracee(child_pid, thread_op->fd_cache, thread_op->cwd, arg2,
                                                                 arg0, arg1, thread_op->op_unlink.path, PATH_MAX);
          SYS_ENTER_PATH_FITLER(thread_op->op_unlink.path)
          break;
        }
        // int unlink(const char *pathname);
        case __NR_unlink:
        {
          read_maybe_relative_pathname_from_tracee(child_pid, thread_op->cwd, arg0, thread_op->op_unlink.path,
                                                   PATH_MAX);
          SYS_ENTER_PATH_FITLER(thread_op->op_unlink.path)
          break;
        }
        // int rmdir(const char *pathname);
        case __NR_rmdir:
        {
          read_maybe_relative_pathname_from_tracee(child_pid, thread_op->cwd, arg0, thread_op->op_unlink.path,
                                                   PATH_MAX);
          SYS_ENTER_PATH_FITLER(thread_op->op_unlink.path)
          break;
        }
        // int rename(const char *oldpath, const char *newpath);
        case __NR_rename:
        {
          read_maybe_relative_pathname_from_tracee(child_pid, thread_op->cwd, arg0, thread_op->op_rename.oldpath,
                                                   PATH_MAX);
          read_maybe_relative_pathname_from_tracee(child_pid, thread_op->cwd, arg1, thread_op->op_rename.newpath,
                                                   PATH_MAX);
          SYS_ENTER_PATH_FITLER(thread_op->op_rename.newpath)
          break;
        }
        // int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath);
        // int renameat2(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags);
        case __NR_renameat2:
        {
          parse_at_syscall_with_flags_dirfd_pathname_from_tracee(child_pid, thread_op->fd_cache, thread_op->cwd, arg4,
                                                                 arg0, arg1, thread_op->op_rename.oldpath, PATH_MAX);
          parse_at_syscall_with_flags_dirfd_pathname_from_tracee(child_pid, thread_op->fd_cache, thread_op->cwd, arg4,
                                                                 arg2, arg3, thread_op->op_rename.newpath, PATH_MAX);
          SYS_ENTER_PATH_FITLER(thread_op->op_rename.newpath)
          break;
        }
        case __NR_renameat:
        {
          parse_at_syscall_dirfd_pathname_from_tracee(child_pid, thread_op->fd_cache, thread_op->cwd, arg0, arg1,
                                                      thread_op->op_rename.oldpath, PATH_MAX);

          parse_at_syscall_dirfd_pathname_from_tracee(child_pid, thread_op->fd_cache, thread_op->cwd, arg2, arg3,
                                                      thread_op->op_rename.newpath, PATH_MAX);
          SYS_ENTER_PATH_FITLER(thread_op->op_rename.newpath)
          break;
        }
        // long getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count);
        // ssize_t getdents64(int fd, void *dirp, size_t count);
        case __NR_getdents:
        case __NR_getdents64:
        {
          get_fd_path(child_pid, thread_op->fd_cache, arg0, thread_op->op_getdents.path);
          SYS_ENTER_PATH_FITLER(thread_op->op_getdents.path)
          break;
        }
        // int symlink(const char *target, const char *linkpath);
        case __NR_symlink:
        {
          read_maybe_relative_pathname_from_tracee(child_pid, thread_op->cwd, arg1, thread_op->op_link.linkpath,
                                                   PATH_MAX);
          SYS_ENTER_PATH_FITLER(thread_op->op_link.linkpath)
          break;
        }
        // int symlinkat(const char *target, int newdirfd, const char *linkpath);
        case __NR_symlinkat:
        {
          parse_at_syscall_dirfd_pathname_from_tracee(child_pid, thread_op->fd_cache, thread_op->cwd, arg1, arg2,
                                                      thread_op->op_link.linkpath, PATH_MAX);
          SYS_ENTER_PATH_FITLER(thread_op->op_link.linkpath)
          break;
        }
        // int linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags);
        case __NR_linkat:
        {
          parse_at_syscall_with_flags_dirfd_pathname_from_tracee(child_pid, thread_op->fd_cache, thread_op->cwd, arg4,
                                                                 arg2, arg3, thread_op->op_link.linkpath, PATH_MAX);
          SYS_ENTER_PATH_FITLER(thread_op->op_link.linkpath)
          break;
        }
        // int link(const char *oldpath, const char *newpath);
        case __NR_link:
        {
          read_maybe_relative_pathname_from_tracee(child_pid, thread_op->cwd, arg1, thread_op->op_link.linkpath,
                                                   PATH_MAX);
          SYS_ENTER_PATH_FITLER(thread_op->op_link.linkpath)
          break;
        }
        // int mkdir(const char *pathname, mode_t mode);
        case __NR_mkdir:
        {
          read_maybe_relative_pathname_from_tracee(child_pid, thread_op->cwd, arg0, thread_op->op_mkdir.path, PATH_MAX);
          SYS_ENTER_PATH_FITLER(thread_op->op_mkdir.path)
          break;
        }
        // int mkdirat(int dirfd, const char *pathname, mode_t mode);
        case __NR_mkdirat:
        {
          parse_at_syscall_dirfd_pathname_from_tracee(child_pid, thread_op->fd_cache, thread_op->cwd, arg0, arg1,
                                                      thread_op->op_mkdir.path, PATH_MAX);
          SYS_ENTER_PATH_FITLER(thread_op->op_mkdir.path)
          break;
        }
        // int truncate(const char *path, off_t length);
        case __NR_truncate:
        {
          read_maybe_relative_pathname_from_tracee(child_pid, thread_op->cwd, arg0, thread_op->op_truncate.path,
                                                   PATH_MAX);
          SYS_ENTER_PATH_FITLER(thread_op->op_truncate.path)
          break;
        }
        default:
        {
          if (ptrace_syscall(child_pid, 0) != 0)
          {
            return -1;
          }
        }
        }
        LOG_DEBUG("PTRACE_SYSCALL_INFO_SECCOMP END: %llu", nr)
      }

      else if (info.op == PTRACE_SYSCALL_INFO_EXIT)
      {
        char file_type, access_type;
        char *path;
        long time_spent_usec;
        struct pid_info *thread_op;

        thread_op = &pid_info_map[child_pid];

        long rVal = info.exit.rval;
        long isError = info.exit.is_error;

        LOG_DEBUG("[PID: %d] Child stopped by syscall exit. rVal: %ld, isError: %ld. thread_op.nr: %llu", child_pid,
                  rVal, isError, thread_op->nr)

#if DEBUG
#define LOG_ACCESS(comment, access_type, file_type, path)                                                              \
  normalize_path(path);                                                                                                \
  gettimeofday(&end_time, NULL);                                                                                       \
  time_spent_usec =                                                                                                    \
      (end_time.tv_sec - thread_op->start_time.tv_sec) * 1000000 + (end_time.tv_usec - thread_op->start_time.tv_usec); \
  dprintf(3, "%c%c %s\n", access_type, file_type, path);                                                               \
  LOG_DEBUG("# %s (time_spent_usec: %ld)", #comment, time_spent_usec)                                                  \
  LOG_DEBUG("%c%c %s", access_type, file_type, path)
#else
#define LOG_ACCESS(comment, access_type, file_type, path)                                                              \
  normalize_path(path);                                                                                                \
  dprintf(3, "%c%c %s\n", access_type, file_type, path);
#endif

#define CONTINUE_TRACEE                                                                                                \
  if (continued == 0)                                                                                                  \
  {                                                                                                                    \
    LOG_DEBUG("PTRACE_CONT pid: %d", child_pid)                                                                        \
    if (ptrace(PTRACE_CONT, child_pid, 0, 0) != 0)                                                                     \
    {                                                                                                                  \
      fprintf(stderr, "\nptrace(PTRACE_CONT)\n");                                                                      \
      fprintf(stderr, "Error: %s\n", strerror(errno));                                                                 \
      return -1;                                                                                                       \
    }                                                                                                                  \
  }                                                                                                                    \
  continued = 1;

        int continued = 0;
        switch (thread_op->nr)
        {
        case __NR_chdir:
        case __NR_fchdir:
        {
          CONTINUE_TRACEE
          if (isError != 0)
          {
            break;
          }
          // LOG_DEBUG("chdir/fchdir")
          strncpy(thread_op->cwd, thread_op->op_chdir.path, PATH_MAX);
          break;
        }
        case __NR_execve:
        case __NR_execveat:
        {
          CONTINUE_TRACEE
          file_type = 'F';
          access_type = 'R';
          path = thread_op->op_exec.path;

          if (isError != 0)
          {
            if (rVal == -ENOENT || rVal == -ENOTDIR || rVal == -EBADF)
            {
              file_type = 'X';
            }
            else
            {
              break;
            }
          }
          LOG_ACCESS("execve/execveat", access_type, file_type, path)
          break;
        }
        case __NR_creat:
        {
          CONTINUE_TRACEE
          if (isError == 0)
          {
            LOG_DEBUG("fd_cache: save %ld %s", rVal, thread_op->op_open.path)
            thread_op->fd_cache[rVal] = strdup(thread_op->op_open.path);
          }
          file_type = 'F';
          access_type = 'W';
          path = thread_op->op_open.path;

          if (isError != 0)
          {
            break;
          }
          LOG_ACCESS("creat", access_type, file_type, path)
          break;
        }
        case __NR_open:
        case __NR_openat:
        case __NR_openat2:
        {
          CONTINUE_TRACEE
          if (isError == 0)
          {
            LOG_DEBUG("fd_cache: save %ld %s", rVal, thread_op->op_open.path)
            thread_op->fd_cache[rVal] = strdup(thread_op->op_open.path);
          }

          int flags = thread_op->op_open.flags;
          path = thread_op->op_open.path;

          LOG_DEBUG("flags: %d", flags)

          access_type = (flags & O_WRONLY || flags & O_RDWR || flags & O_CREAT) ? 'W' : 'R';
          file_type = (flags & O_DIRECTORY) ? 'D' : 'F';

          if (file_type == 'F' && access_type == 'R' && isError == 0)
          {
            // if open flags do not have O_DIRECTORY but path ends in '/' then it is a directory
            int pathLen = strlen(path);
            if (pathLen > 0 && path[pathLen - 1] == '/')
            {
              file_type = 'D';
            }
          }
          else if (isError != 0)
          {
            if (rVal == -EISDIR)
            {
              file_type = 'D';
            }
            else if (rVal == -ENOENT || rVal == -ENOTDIR || rVal == -EBADF)
            {
              file_type = 'X';
            }
            else
            {
              break;
            }
          }

          LOG_ACCESS("open/openat/openat2", access_type, file_type, path)
          break;
        }
        case __NR_readlink:
        case __NR_readlinkat:
        {
          CONTINUE_TRACEE
          access_type = 'R';
          file_type = 'L';
          path = thread_op->op_readlink.path;

          if (isError != 0)
          {
            if (rVal == -ENOENT || rVal == -ENOTDIR || rVal == -EBADF)
            {
              file_type = 'X';
            }
            else
            {
              break;
            }
          }
          LOG_ACCESS("readlink/readlinkat", access_type, file_type, path)
          break;
        }
        case __NR_statx:
        {
          CONTINUE_TRACEE
          access_type = 'R';
          path = thread_op->op_statx.path;
          file_type = '?';
          if (isError != 0)
          {
            if (rVal == -ENOENT || rVal == -ENOTDIR || rVal == -EBADF)
            {
              file_type = 'X';
            }
            else
            {
              break;
            }
          }
          LOG_ACCESS("statx", access_type, file_type, path)
          break;
        }
        case __NR_lstat:
        case __NR_stat:
        case __NR_newfstatat:
        {
          CONTINUE_TRACEE
          access_type = 'R';
          path = thread_op->op_stat.path;
          file_type = '?';
          if (isError != 0)
          {
            if (rVal == -ENOENT || rVal == -ENOTDIR || rVal == -EBADF)
            {
              file_type = 'X';
            }
            else
            {
              break;
            }
          }
          LOG_ACCESS("lstat/stat/newfstatat", access_type, file_type, path)
          break;
        }
        case __NR_faccessat:
        case __NR_faccessat2:
        {
          CONTINUE_TRACEE
          access_type = 'R';
          path = thread_op->op_faccessat.path;

          file_type = '?';
          if (isError != 0)
          {
            if (rVal == -ENOENT || rVal == -ENOTDIR || rVal == -EBADF)
            {
              file_type = 'X';
            }
            else
            {
              break;
            }
          }
          LOG_ACCESS("faccessat/faccessat2", access_type, file_type, path)
          break;
        }
        case __NR_access:
        {
          CONTINUE_TRACEE
          access_type = 'R';
          path = thread_op->op_access.path;

          file_type = '?';
          if (isError != 0)
          {
            if (rVal == -ENOENT || rVal == -ENOTDIR || rVal == -EBADF)
            {
              file_type = 'X';
            }
            else
            {
              break;
            }
          }
          LOG_ACCESS("access", access_type, file_type, path)
          break;
        }
        case __NR_unlinkat:
        case __NR_unlink:
        {
          CONTINUE_TRACEE
          access_type = 'D';
          file_type = 'X';
          path = thread_op->op_unlink.path;

          if (isError != 0)
          {
            break;
          }
          LOG_ACCESS("unlinkat/unlink", access_type, file_type, path)
          break;
        }
        case __NR_rmdir:
        {
          CONTINUE_TRACEE
          access_type = 'D';
          file_type = 'X';
          path = thread_op->op_unlink.path;

          if (isError != 0)
          {
            break;
          }
          LOG_ACCESS("rmdir", access_type, file_type, path)
          break;
        }
        case __NR_rename:
        case __NR_renameat:
        case __NR_renameat2:
        {
          CONTINUE_TRACEE
          if (isError != 0)
          {
            break;
          }
          access_type = 'D';
          file_type = 'X';
          path = thread_op->op_rename.oldpath;

          LOG_ACCESS("rename/renameat/renameat2", access_type, file_type, path)
          access_type = 'W';
          path = thread_op->op_rename.newpath;
          file_type = '?';
          LOG_ACCESS("rename/renameat/renameat2", access_type, file_type, path)
          break;
        }
        case __NR_getdents:
        case __NR_getdents64:
        {
          CONTINUE_TRACEE
          access_type = 'E';
          file_type = 'D';
          path = thread_op->op_getdents.path;

          if (isError != 0)
          {
            if (rVal == -ENOENT || rVal == -ENOTDIR || rVal == -EBADF)
            {
              file_type = 'X';
            }
            else
            {
              break;
            }
          }
          LOG_ACCESS("getdents/getdents64", access_type, file_type, path)
          break;
        }
        case __NR_symlink:
        case __NR_symlinkat:
        {
          CONTINUE_TRACEE
          access_type = 'W';
          file_type = 'L';
          path = thread_op->op_link.linkpath;

          if (isError != 0)
          {
            break;
          }
          LOG_ACCESS("symlink/symlinkat", access_type, file_type, path)
          break;
        }
        case __NR_linkat:
        case __NR_link:
        {
          CONTINUE_TRACEE
          access_type = 'W';
          file_type = 'F';
          path = thread_op->op_link.linkpath;

          if (isError != 0)
          {
            break;
          }
          LOG_ACCESS("linkat/link", access_type, file_type, path)
          break;
        }
        case __NR_mkdir:
        case __NR_mkdirat:
        {
          CONTINUE_TRACEE
          access_type = 'W';
          file_type = 'D';
          path = thread_op->op_mkdir.path;

          if (isError != 0)
          {
            break;
          }
          LOG_ACCESS("mkdir/mkdirat", access_type, file_type, path)
          break;
        }
        case __NR_truncate:
        {
          access_type = 'W';
          path = thread_op->op_truncate.path;

          file_type = '?';
          if (isError != 0)
          {
            if (rVal == -ENOENT || rVal == -ENOTDIR || rVal == -EBADF)
            {
              file_type = 'X';
            }
            else
            {
              break;
            }
          }
          if (file_type == '?')
          {
            if (stat(path, &stat_result) == 0)
            {
              file_type = GET_FILE_TYPE_FROM_STAT_RESULT_MODE(stat_result.st_mode);
            }
            else if (errno == ENOENT || errno == ENOTDIR || errno == EBADF)
            {
              file_type = 'X';
            }
          }
          CONTINUE_TRACEE
          LOG_ACCESS("truncate", access_type, file_type, path)
          break;
        }
        }
        LOG_DEBUG("PTRACE_SYSCALL_INFO_EXIT END: %llu. rVal: %ld, isError: %ld", thread_op->nr, rVal, isError)
        CONTINUE_TRACEE
      }
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

      if (ptrace_cont(child_pid, WSTOPSIG(status)) != 0)
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
      if (ptrace_cont(child_pid, WSTOPSIG(status)) != 0)
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
      if (ptrace_cont(child_pid, WSTOPSIG(status)) != 0)
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
      if (ptrace_syscall(child_pid, 0) != 0)
      {
        return -1;
      }
    }
  }

  return 0;
}

int exec_tracee(char *program, char **args)
{
#if DEBUG
  LOG_DEBUG("execvp %s with args: ", program)
  for (char **arg = args; *arg; arg++)
  {
    LOG_DEBUG("%s ", *arg)
  }
  LOG_DEBUG("")
#endif
  if (execvp(program, args) != 0)
  {
    fprintf(stderr, "\nexecvp error\n");
    fprintf(stderr, "Error: %s\n", strerror(errno));
  }
  return 1;
}

int trace_exec(char *program, char **args)
{
  pid_t child_pid = fork();

  if (child_pid == 0)
  {
    if (prepare_tracee() != 0)
    {
      perror("prepare_tracee");
      return 1;
    }
    else
    {
      return exec_tracee(program, args);
    }

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
