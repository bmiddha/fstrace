#include <sys/ptrace.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cassert>

const char *test_string_1 = "Hello, world!";

void test_syscall_write()
{
  // open file
  int fd = open("test.txt", O_RDWR | O_CREAT | O_TRUNC, 0666);
  if (fd < 0)
  {
    perror("open");
    exit(1);
  }

  // write to file
  int n = write(fd, test_string_1, strlen(test_string_1));
  if (n < 0)
  {
    perror("write");
    exit(1);
  }

  // close file
  close(fd);
}

void test_syscall_read()
{
  // open file
  int fd = open("test.txt", O_RDONLY);
  if (fd < 0)
  {
    perror("open");
    exit(1);
  }

  // read from file
  char buf[128];
  int n = read(fd, buf, sizeof(buf));
  if (n < 0)
  {
    perror("read");
    exit(1);
  }

  assert(n == strlen(test_string_1));
  assert(strncmp(buf, test_string_1, n) == 0);

  // print read data
  buf[n] = '\0';
  printf("Read: %s\n", buf);

  // close file
  close(fd);
}
