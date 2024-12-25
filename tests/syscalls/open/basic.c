#include <sys/types.h>
#include <sys/stat.h>
#include <linux/fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>

// int open(const char *pathname, int flags);
// int open(const char *pathname, int flags, mode_t mode);

int main()
{
  const char *pathname = "/tmp";
  int flags = O_RDONLY;
  int mode = 0;
  int fd = syscall(SYS_open, pathname, flags, mode);

  return 0;
}
