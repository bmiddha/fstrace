#include "trace_exec.cc"
#include "test_syscalls.cc"

void run_tracee()
{
  ptrace(PTRACE_TRACEME, 0, 0, 0);
  raise(SIGSTOP);
  test_syscall_write();
  test_syscall_read();
  exit(0);
}

int main(int argc, char *argv[])
{
  pid_t child_pid = fork();
  if (child_pid == 0)
  {
    printf("Running tracee\n");
    run_tracee();
  }
  else if (child_pid > 0)
  {
    printf("Running tracer on %d\n", child_pid);
    // TODO check file accesses from FD3
    run_tracer(child_pid);
  }
  else
  {
    perror("fork");
    exit(1);
  }
  return 0;
}
