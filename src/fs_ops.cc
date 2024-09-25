#include <errno.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <linux/limits.h>
#include <linux/openat2.h>
#include <malloc.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include "ptrace_patch.h"

struct fs_operation
{
  char path[PATH_MAX];
  char op[1];
  char comment[1000];
};

void log_access(struct fs_operation *fs_op)
{
  // log filtering
  if (strncmp((*fs_op).path, "/proc/", 6) == 0 || strncmp((*fs_op).path, "/dev/", 5) == 0 ||
      strncmp((*fs_op).path, "pipe:[", 6) == 0)
  {
    return;
  }

  if ((*fs_op).op[0] == 'R')
  {
    if (strncmp((*fs_op).path, "/usr/lib/", 9) == 0)
    {
      return;
    }
  }

  // F - file, D - directory, X - does not exist
  char file_type = '?';

  // check if it is a link, file, or directory and if it exists
  struct stat stat_result;
  if (stat((*fs_op).path, &stat_result) == 0)
  {
    if (S_ISDIR(stat_result.st_mode))
    {
      file_type = 'D';
    }
    else if (S_ISREG(stat_result.st_mode))
    {
      file_type = 'F';
    }
    else if (S_ISLNK(stat_result.st_mode))
    {
      file_type = 'L';
    }
  }
  else
  {
    if (errno == ENOENT || errno == ENOTDIR)
    {
      file_type = 'X';
    }
  }

  if ((*fs_op).path[strlen((*fs_op).path) - 1] == '/')
  {
    (*fs_op).path[strlen((*fs_op).path) - 1] = '\0';
  }

  if ((*fs_op).op[0] == 'E')
  {
    {
      strcat((*fs_op).path, "/*");
    }
    (*fs_op).op[0] = 'R';
  }

#ifdef DEBUG
  if (strlen((*fs_op).comment) > 0)
  {
    dprintf(3, "# %s\n%c%c %s\n", (*fs_op).comment, (*fs_op).op[0], file_type, (*fs_op).path);
  }
#else
  dprintf(3, "%c%c %s\n", (*fs_op).op[0], file_type, (*fs_op).path);
#endif
}

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

template <typename T> int read_struct_from_tracee(pid_t pid, __u64 addr, T *buffer, size_t buffer_size)
{
  memset(buffer, '\0', buffer_size);
  __u64 data;
  size_t i = 0;
  do
  {
    data = ptrace(PTRACE_PEEKDATA, pid, addr + i * sizeof(__u64), NULL);
    if (data == -1 && errno != 0)
    {
      // perror("PTRACE_PEEKDATA");
      break;
    }
    memcpy(buffer + i * sizeof(__u64), &data, sizeof(__u64));
    i++;
  } while (i < buffer_size / sizeof(__u64));

  return i;
}

void read_cstring_from_tracee(pid_t pid, __u64 addr, char *buffer, size_t buffer_size)
{
  long data;
  size_t i = 0;
  for (i = 0; i < buffer_size / sizeof(long); i++)
  {
    errno = 0;
    data = ptrace(PTRACE_PEEKDATA, pid, addr + i * sizeof(long), NULL);
    if (errno != 0)
    {
      // perror("ptrace(PTRACE_PEEKDATA)");
      // exit(EXIT_FAILURE);
    }
    memcpy(buffer + i * sizeof(long), &data, sizeof(long));
    if (memchr(&data, 0, sizeof(long)) != NULL)
    {
      break;
    }
  };
  // buffer[buffer_size - 1] = '\0';
  return;
}

void read_cstring_array_from_tracee(pid_t pid, __u64 addr, char **buffer_array, size_t array_size, size_t buffer_size)
{
  __u64 ptr;
  for (size_t i = 0; i < buffer_size; i++)
  {
    ptr = ptrace(PTRACE_PEEKDATA, pid, addr + i * sizeof(__u64), NULL);
    if (ptr == 0 || (ptr == -1 && errno != 0))
    {
      buffer_array[i][0] = '\0'; // Null pointer or error, set empty string
      break;
    }
    read_cstring_from_tracee(pid, ptr, buffer_array[i], buffer_size);
  }
}

void read_maybe_relative_pathname_from_tracee(pid_t pid, __u64 addr, char *buffer, size_t buffer_size)
{
  read_cstring_from_tracee(pid, addr, buffer, buffer_size);
  if (buffer[0] != '/')
  {
    char cwd[PATH_MAX];
    char cwd_link_path[PATH_MAX];
    sprintf(cwd_link_path, "/proc/%u/cwd", pid);
    readlink(cwd_link_path, cwd, PATH_MAX);
    if (buffer[strlen(buffer) - 1] == '/')
    {
      sprintf(buffer, "%s%s", cwd, buffer);
    }
    else
    {
      sprintf(buffer, "%s/%s", cwd, buffer);
    }
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

#define MAX_CONCURRENT_THREADS 655360

struct thread_fs_operation
{
  struct fs_operation fs_ops[2];
  int fs_op_idx;
};

struct thread_fs_operation thread_fs_ops[MAX_CONCURRENT_THREADS];

int handle_syscall(pid_t child_pid)
{
  struct ptrace_syscall_info info;
  if (ptrace(PTRACE_GET_SYSCALL_INFO, child_pid, sizeof(info), &info) == -1)
  {
    fprintf(stderr, "\nptrace(PTRACE_GET_SYSCALL_INFO)\n");
    return -1;
  }

  if (info.op == PTRACE_SYSCALL_INFO_ENTRY)
  {
    struct thread_fs_operation *thread_op = &thread_fs_ops[child_pid];

    struct fs_operation *this_op = thread_op->fs_ops;
    int *fs_op_idx = &thread_op->fs_op_idx;
    *fs_op_idx = 0;

    memset(this_op, 0, sizeof(struct fs_operation));

    // std::string syscall_name = get_syscall_name(info.entry.nr);
    // printf("%s stack ptr ENTRY: %llu\n", syscall_name, info.stack_pointer);
    switch (info.entry.nr)
    {
    // int execve(const char *pathname, char *const argv[], char *const envp[]);
    case __NR_execve:
    {
      read_cstring_from_tracee(child_pid, info.entry.args[0], this_op[*fs_op_idx].path, PATH_MAX);
      sprintf(this_op[*fs_op_idx].comment, "execve");
      this_op[*fs_op_idx].op[0] = 'R';
      (*fs_op_idx)++;
      break;
    }
    // int execveat(int dirfd, const char *pathname, char *const argv[], char *const envp[], int flags);
    case __NR_execveat:
    {
      parse_dirfd_pathname_from_tracee(child_pid, info.entry.args[0], info.entry.args[1], this_op[*fs_op_idx].path,
                                       PATH_MAX);
      sprintf(this_op[*fs_op_idx].comment, "execveat");
      this_op[*fs_op_idx].op[0] = 'R';
      (*fs_op_idx)++;
      break;
    }
    // int open(const char *pathname, int flags);
    // int open(const char *pathname, int flags, mode_t mode);
    case __NR_open:
    {
      read_cstring_from_tracee(child_pid, info.entry.args[0], this_op[*fs_op_idx].path, PATH_MAX);
      int flags = info.entry.args[1];
      if (flags & O_RDONLY)
      {
        this_op[*fs_op_idx].op[0] = 'R';
      }
      else if (flags & O_WRONLY || flags & O_RDWR)
      {
        this_op[*fs_op_idx].op[0] = 'W';
      }
      sprintf(this_op[*fs_op_idx].comment, "open");
      (*fs_op_idx)++;
      break;
    }
    // int creat(const char *pathname, mode_t mode);
    case __NR_creat:
    {
      read_cstring_from_tracee(child_pid, info.entry.args[0], this_op[*fs_op_idx].path, PATH_MAX);
      sprintf(this_op[*fs_op_idx].comment, "creat");
      this_op[*fs_op_idx].op[0] = 'W';
      (*fs_op_idx)++;
      break;
    }
    // int openat(int dirfd, const char *pathname, int flags);
    // int openat(int dirfd, const char *pathname, int flags, mode_t mode);
    case __NR_openat:
    {
      parse_dirfd_pathname_from_tracee(child_pid, info.entry.args[0], info.entry.args[1], this_op[*fs_op_idx].path,
                                       PATH_MAX);
      int access_mode = info.entry.args[2] & 3;
      if (access_mode == O_RDONLY)
      {
        this_op[*fs_op_idx].op[0] = 'R';
      }
      else if ((access_mode == O_WRONLY) || (access_mode == O_RDWR))
      {
        this_op[*fs_op_idx].op[0] = 'W';
      }
      sprintf(this_op[*fs_op_idx].comment, "openat %llu", info.entry.args[2]);
      (*fs_op_idx)++;
      break;
    }
    // int openat2(int dirfd, const char *pathname, struct open_how *how, size_t size);
    case __NR_openat2:
    {
      parse_dirfd_pathname_from_tracee(child_pid, info.entry.args[0], info.entry.args[1], this_op[*fs_op_idx].path,
                                       PATH_MAX);
      struct open_how *how;
      read_struct_from_tracee(child_pid, info.entry.args[2], how, sizeof(struct open_how));
      if (how->flags & O_RDONLY)
      {
        this_op[*fs_op_idx].op[0] = 'R';
      }
      else if (how->flags & O_WRONLY || how->flags & O_RDWR)
      {
        this_op[*fs_op_idx].op[0] = 'W';
      }
      // free(how);
      sprintf(this_op[*fs_op_idx].comment, "openat2");
      (*fs_op_idx)++;
      break;
    }
    // ssize_t readlink(const char *pathname, char *buf, size_t bufsiz);
    case __NR_readlink:
    {
      read_cstring_from_tracee(child_pid, info.entry.args[0], this_op[*fs_op_idx].path, PATH_MAX);
      sprintf(this_op[*fs_op_idx].comment, "readlink");
      this_op[*fs_op_idx].op[0] = 'R';
      (*fs_op_idx)++;
      break;
    }
    // ssize_t readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz);
    case __NR_readlinkat:
    {
      parse_dirfd_pathname_from_tracee(child_pid, info.entry.args[0], info.entry.args[1], this_op[*fs_op_idx].path,
                                       PATH_MAX);
      sprintf(this_op[*fs_op_idx].comment, "readlinkat");
      this_op[*fs_op_idx].op[0] = 'R';
      (*fs_op_idx)++;
      break;
    }
    // int lstat(const char *pathname, struct stat *statbuf);
    case __NR_lstat:
    // int stat(const char *pathname, struct stat *statbuf);
    case __NR_stat:
    {
      read_cstring_from_tracee(child_pid, info.entry.args[0], this_op[*fs_op_idx].path, PATH_MAX);
      sprintf(this_op[*fs_op_idx].comment, "stat");
      this_op[*fs_op_idx].op[0] = 'R';
      (*fs_op_idx)++;
      break;
    }
    // int fstatat(int dirfd, const char *pathname, struct stat *statbuf, int flags);
    case __NR_newfstatat:
    {
      parse_dirfd_pathname_from_tracee(child_pid, info.entry.args[0], info.entry.args[1], this_op[*fs_op_idx].path,
                                       PATH_MAX);
      sprintf(this_op[*fs_op_idx].comment, "fstatat");
      this_op[*fs_op_idx].op[0] = 'R';
      (*fs_op_idx)++;
      break;
    }
    // int faccessat(int dirfd, const char *pathname, int mode, int flags);
    case __NR_faccessat:
    case __NR_faccessat2:
    {
      parse_dirfd_pathname_from_tracee(child_pid, info.entry.args[0], info.entry.args[1], this_op[*fs_op_idx].path,
                                       PATH_MAX);
      sprintf(this_op[*fs_op_idx].comment, "faccessat");
      this_op[*fs_op_idx].op[0] = 'R';
      (*fs_op_idx)++;
      break;
    }
    // int access(const char *pathname, int mode);
    case __NR_access:
    {
      read_cstring_from_tracee(child_pid, info.entry.args[0], this_op[*fs_op_idx].path, PATH_MAX);
      sprintf(this_op[*fs_op_idx].comment, "access");
      this_op[*fs_op_idx].op[0] = 'R';
      (*fs_op_idx)++;
      break;
    }
    // int unlinkat(int dirfd, const char *pathname, int flags);
    case __NR_unlinkat:
    {
      parse_dirfd_pathname_from_tracee(child_pid, info.entry.args[0], info.entry.args[1], this_op[*fs_op_idx].path,
                                       PATH_MAX);
      sprintf(this_op[*fs_op_idx].comment, "unlinkat");
      this_op[*fs_op_idx].op[0] = 'D';
      (*fs_op_idx)++;
      break;
    }
    // int unlink(const char *pathname);
    case __NR_unlink:
    {
      read_cstring_from_tracee(child_pid, info.entry.args[0], this_op[*fs_op_idx].path, PATH_MAX);
      sprintf(this_op[*fs_op_idx].comment, "unlink");
      this_op[*fs_op_idx].op[0] = 'D';
      (*fs_op_idx)++;
      break;
    }
    // int rmdir(const char *pathname);
    case __NR_rmdir:
    {
      read_cstring_from_tracee(child_pid, info.entry.args[0], this_op[*fs_op_idx].path, PATH_MAX);
      sprintf(this_op[*fs_op_idx].comment, "rmdir");
      this_op[*fs_op_idx].op[0] = 'D';
      (*fs_op_idx)++;
      break;
    }
    // int rename(const char *oldpath, const char *newpath);
    case __NR_rename:
    {
      read_maybe_relative_pathname_from_tracee(child_pid, info.entry.args[0], this_op[*fs_op_idx].path, PATH_MAX);
      sprintf(this_op[*fs_op_idx].comment, "rename");
      this_op[*fs_op_idx].op[0] = 'D';
      (*fs_op_idx)++;
      sprintf(this_op[*fs_op_idx].comment, "rename");
      read_maybe_relative_pathname_from_tracee(child_pid, info.entry.args[1], this_op[*fs_op_idx].path, PATH_MAX);
      this_op[*fs_op_idx].op[0] = 'W';
      (*fs_op_idx)++;
      break;
    }
    // int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath);
    // int renameat2(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags);
    case __NR_renameat:
    case __NR_renameat2:
    {
      parse_dirfd_pathname_from_tracee(child_pid, info.entry.args[0], info.entry.args[1], this_op[*fs_op_idx].path,
                                       PATH_MAX);
      sprintf(this_op[*fs_op_idx].comment, "renameat");
      this_op[*fs_op_idx].op[0] = 'D';
      (*fs_op_idx)++;
      sprintf(this_op[*fs_op_idx].comment, "renameat");
      parse_dirfd_pathname_from_tracee(child_pid, info.entry.args[2], info.entry.args[3], this_op[*fs_op_idx].path,
                                       PATH_MAX);
      this_op[*fs_op_idx].op[0] = 'W';
      (*fs_op_idx)++;
      break;
    }
    // long getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count);
    // ssize_t getdents64(int fd, void *dirp, size_t count);
    case __NR_getdents:
    case __NR_getdents64:
    {
      get_fd_path(child_pid, info.entry.args[0], this_op[*fs_op_idx].path);
      sprintf(this_op[*fs_op_idx].comment, "getdents");
      this_op[*fs_op_idx].op[0] = 'E';
      (*fs_op_idx)++;
      break;
    }
    // int chmod(const char *pathname, mode_t mode);
    case __NR_chmod:
    {
      read_cstring_from_tracee(child_pid, info.entry.args[0], this_op[*fs_op_idx].path, PATH_MAX);
      sprintf(this_op[*fs_op_idx].comment, "chmod");
      this_op[*fs_op_idx].op[0] = 'W';
      (*fs_op_idx)++;
      break;
    }
    // int symlink(const char *target, const char *linkpath);
    case __NR_symlink:
    {
      read_maybe_relative_pathname_from_tracee(child_pid, info.entry.args[1], this_op[*fs_op_idx].path, PATH_MAX);
      sprintf(this_op[*fs_op_idx].comment, "symlink");
      this_op[*fs_op_idx].op[0] = 'W';
      (*fs_op_idx)++;
      break;
    }
    // int symlinkat(const char *target, int newdirfd, const char *linkpath);
    case __NR_symlinkat:
    {
      parse_dirfd_pathname_from_tracee(child_pid, info.entry.args[1], info.entry.args[2], this_op[*fs_op_idx].path,
                                       PATH_MAX);
      sprintf(this_op[*fs_op_idx].comment, "symlinkat");
      this_op[*fs_op_idx].op[0] = 'W';
      (*fs_op_idx)++;
      break;
    }
    // int linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags);
    case __NR_linkat:
    {
      parse_dirfd_pathname_from_tracee(child_pid, info.entry.args[2], info.entry.args[3], this_op[*fs_op_idx].path,
                                       PATH_MAX);
      sprintf(this_op[*fs_op_idx].comment, "linkat");
      this_op[*fs_op_idx].op[0] = 'W';
      (*fs_op_idx)++;
      break;
    }
    // int link(const char *oldpath, const char *newpath);
    case __NR_link:
    {
      read_maybe_relative_pathname_from_tracee(child_pid, info.entry.args[1], this_op[*fs_op_idx].path, PATH_MAX);
      sprintf(this_op[*fs_op_idx].comment, "link");
      this_op[*fs_op_idx].op[0] = 'W';
      (*fs_op_idx)++;
      break;
    }
    // int mkdir(const char *pathname, mode_t mode);
    case __NR_mkdir:
    {
      read_cstring_from_tracee(child_pid, info.entry.args[0], this_op[*fs_op_idx].path, PATH_MAX);
      sprintf(this_op[*fs_op_idx].comment, "mkdir");
      this_op[*fs_op_idx].op[0] = 'C';
      (*fs_op_idx)++;
      break;
    }
    // int mkdirat(int dirfd, const char *pathname, mode_t mode);
    case __NR_mkdirat:
    {
      parse_dirfd_pathname_from_tracee(child_pid, info.entry.args[0], info.entry.args[1], this_op[*fs_op_idx].path,
                                       PATH_MAX);
      sprintf(this_op[*fs_op_idx].comment, "mkdirat");
      this_op[*fs_op_idx].op[0] = 'C';
      (*fs_op_idx)++;
      break;
    }
    // int utime(const char *filename, const struct utimbuf *times);
    case __NR_utime:
    // int utimes(const char *filename, const struct timeval times[2]);
    case __NR_utimes:
    {
      read_cstring_from_tracee(child_pid, info.entry.args[0], this_op[*fs_op_idx].path, PATH_MAX);
      sprintf(this_op[*fs_op_idx].comment, "utime");
      this_op[*fs_op_idx].op[0] = 'W';
      (*fs_op_idx)++;
      break;
    }
    // int truncate(const char *path, off_t length);
    case __NR_truncate:
    {
      read_cstring_from_tracee(child_pid, info.entry.args[0], this_op[*fs_op_idx].path, PATH_MAX);
      sprintf(this_op[*fs_op_idx].comment, "truncate");
      this_op[*fs_op_idx].op[0] = 'W';
      (*fs_op_idx)++;
      break;
    }
    }
  }
  else if (info.op == PTRACE_SYSCALL_INFO_EXIT)
  {
    struct thread_fs_operation *thread_op = &thread_fs_ops[child_pid];

    struct fs_operation *this_op = thread_op->fs_ops;
    int *fs_op_idx = &thread_op->fs_op_idx;

    for (int i = 0; i < *fs_op_idx; i++)
    {
      if (this_op[i].op[0] == 'W')
      {
        if (!info.exit.is_error)
        {
          log_access(&this_op[i]);
        }
      }
      else
      {
        log_access(&this_op[i]);
      }
    }
  }
  return 0;
}
