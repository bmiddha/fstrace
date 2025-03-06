
// clang-format off
//go:build ignore
// clang-format on

#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>

char *tempdir = "/tmp/fstrace-test-dir";
char *path_newfile0 = "/tmp/fstrace-test-dir/newfile0";
char *path_newfile1_rel = "./newfile1";

void testfn_creat()
{
  syscall(__NR_chdir, tempdir);
  int tempfd;
  tempfd = syscall(__NR_creat, path_newfile0, 0666 /* rw-rw-rw- */);
  syscall(__NR_close, tempfd);
  tempfd = syscall(__NR_creat, path_newfile1_rel, 0666 /* rw-rw-rw- */);
  syscall(__NR_close, tempfd);

  // syscall(__NR_exit, EXIT_SUCCESS);
}

void testfn_openat()
{
  syscall(__NR_chdir, tempdir);
  int tempfd;
  tempfd = syscall(__NR_openat, AT_FDCWD, path_newfile0, O_CREAT | O_RDWR, 0666 /* rw-rw-rw- */);
  syscall(__NR_close, tempfd);
  tempfd = syscall(__NR_openat, AT_FDCWD, path_newfile1_rel, O_CREAT | O_RDWR, 0666 /* rw-rw-rw- */);
  syscall(__NR_close, tempfd);

  // syscall(__NR_exit, EXIT_SUCCESS);
}

int main(int argc, char *argv[])
{
  int pid = syscall(__NR_getpid);
  while(1) {
    printf("PID: %d\n", pid);
    testfn_openat();
    sleep(1);
  }
  return 0;
}
