
// clang-format off
//go:build ignore
// clang-format on

#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

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

  syscall(__NR_exit, EXIT_SUCCESS);
}

int main(int argc, char *argv[])
{
  testfn_creat();
  return 0;
}
