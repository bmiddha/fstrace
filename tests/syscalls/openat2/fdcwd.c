#include <sys/types.h>
#include <sys/stat.h>
#include <linux/fcntl.h>
#include <linux/openat2.h>
#include <unistd.h>
#include <sys/syscall.h>

int main()
{
  int dirfd = AT_FDCWD;
  const char *pathname = "/tmp";
  struct open_how how = {.flags = O_PATH, .mode = 0};
  int size = sizeof(struct open_how);
  int fd = syscall(SYS_openat2, dirfd, pathname, &how, size);

  return 0;
}
