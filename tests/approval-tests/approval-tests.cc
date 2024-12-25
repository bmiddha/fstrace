#include <gtest/gtest.h>

#define APPROVALS_GOOGLETEST
#include "ApprovalTests/ApprovalTests.hpp"

#include <iostream>
#include <string>
#include <cstdio>
#include <memory>
#include <unistd.h>
#include <fcntl.h>

std::string getFsTraceOutput(const char *cmd)
{
  std::array<char, 128> buffer;
  std::string result;

  int pipefd[2];
  if (pipe(pipefd) == -1)
  {
    throw std::runtime_error("pipe() failed!");
  }

  pid_t pid = fork();
  if (pid == -1)
  {
    throw std::runtime_error("fork() failed!");
  }

  if (pid == 0)
  {
    close(pipefd[0]);

    dup2(pipefd[1], 3);
    close(pipefd[1]);

    execl("fstrace", "fstrace", cmd, nullptr);

    perror("execl");
    exit(EXIT_FAILURE);
  }
  else
  {
    close(pipefd[1]);

    ssize_t bytes_read;
    while ((bytes_read = read(pipefd[0], buffer.data(), buffer.size())) > 0)
    {
      result.append(buffer.data(), bytes_read);
    }
    close(pipefd[0]);

    wait(NULL);
  }

  return result;
}

TEST(Syscalls, OpenAt2_FDCWD)
{
  std::string output = getFsTraceOutput("./tests_syscalls_openat2_fdcwd.c");
  ApprovalTests::Approvals::verify(output);
}


TEST(Syscalls, Open)
{
  std::string output = getFsTraceOutput("./tests_syscalls_open_basic.c");
  ApprovalTests::Approvals::verify(output);
}
