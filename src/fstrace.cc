#include <stdio.h>
#include <sys/ptrace.h>
#include <stdarg.h>
#include "trace_exec.cc"

int main(int argc, char *argv[])
{
  if (argc < 2)
  {
    fprintf(stderr, "Usage: %s <program> [args...]\n", argv[0]);
    return 1;
  }

  char *program = argv[1];
  char **args = &argv[1];

  return trace_exec(program, args);
}