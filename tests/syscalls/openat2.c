#include <sys/types.h>
#include <sys/stat.h>
#include <linux/fcntl.h>
#include <linux/openat2.h>
#include <unistd.h>
#include <sys/syscall.h>

// int openat2(int dirfd, const char *pathname, const struct open_how *how, size_t size);

int dirfd1()
{
  int dirfd = open("/tmp", O_RDONLY);

  const char *pathname = "/tmp";
  struct open_how how = {.flags = O_PATH, .mode = 0};
  int size = sizeof(struct open_how);
  syscall(SYS_openat2, dirfd, pathname, &how, size);
}

int dirfd2()
{
  int dirfd = open("/tmp", O_RDONLY);
  const char *pathname = "./";
  struct open_how how = {.flags = O_PATH, .mode = 0};
  int size = sizeof(struct open_how);
  syscall(SYS_openat2, dirfd, pathname, &how, size);
}

int atfdcwd1()
{
  int dirfd = AT_FDCWD;
  const char *pathname = "/tmp";
  struct open_how how = {.flags = O_PATH, .mode = 0};
  int size = sizeof(struct open_how);
  syscall(SYS_openat2, dirfd, pathname, &how, size);
}

int atfdcwd2()
{
  int dirfd = AT_FDCWD;
  chdir("/tmp");
  const char *pathname = "./";
  struct open_how how = {.flags = O_PATH, .mode = 0};
  int size = sizeof(struct open_how);
  syscall(SYS_openat2, dirfd, pathname, &how, size);
}

int main()
{
  // dirfd1();
  dirfd2();
  // atfdcwd1();
  // atfdcwd2();
  return 0;
}
