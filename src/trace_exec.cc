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
// #include "syscallnames.cc"
#include "fs_ops.cc"

extern char **environ;

int run_tracee(char *program, char **args)
{
  ptrace(PTRACE_TRACEME, 0, 0, 0);
  raise(SIGSTOP);
  // printf("Running %s\n", program);
  // printf("Arguments: ");
  // for (int i = 0; args[i] != NULL; i++)
  // {
  //   printf("%s ", args[i]);
  // }
  // printf("\n");
  return execvp(program, args);
}

int ptrace_syscall(pid_t pid, int signal)
{
  if (ptrace(PTRACE_SYSCALL, pid, NULL, signal) == -1)
  {
    fprintf(stderr, "\nptrace(PTRACE_SYSCALL)\n");
    return -1;
  }
  return 0;
}

int run_tracer(pid_t child_pid)
{
  // ProcessTree tree = ProcessTree(child_pid);
  int status = 0;
  // wait for child to stop after TRACEME
  do
  {
    waitpid(child_pid, &status, 0);
  } while (!WIFSTOPPED(status));

  int ptrace_options = 0;
  /*
   * When delivering system call traps, set bit 7 in the signal number (i.e., deliver SIGTRAP|0x80). This makes it easy
   * for the tracer to distinguish normal traps from those caused by a system call.
   */
  ptrace_options |= PTRACE_O_TRACESYSGOOD;
  /*
   * Send a SIGKILL signal to the tracee if the tracer exits.  This option is useful for ptrace jailers that want
   * to ensure that tracees can never escape the tracer's control.
   */
  ptrace_options |= PTRACE_O_EXITKILL;
  /*
   * Stop the tracee at the next fork(2) and automatically start tracing the newly forked  process,  which  will
   * start  with  a SIGSTOP, or PTRACE_EVENT_STOP if PTRACE_SEIZE was used.  A waitpid(2) by the tracer will return
   * a status value such that
   *
   *   status>>8 == (SIGTRAP | (PTRACE_EVENT_FORK<<8))
   *
   * The PID of the new process can be retrieved with PTRACE_GETEVENTMSG.
   */
  ptrace_options |= PTRACE_O_TRACEFORK;
  /*
   * Stop  the  tracee at the next execve(2).  A waitpid(2) by the tracer will return a status
   * value such that
   *
   *   status>>8 == (SIGTRAP | (PTRACE_EVENT_EXEC<<8))
   *
   * If the execing thread is not a thread group leader, the thread  ID  is  reset  to  thread
   * group  leader's  ID  before  this stop.  Since Linux 3.0, the former thread ID can be retrieved with
   * PTRACE_GETEVENTMSG.
   */
  ptrace_options |= PTRACE_O_TRACEEXEC;
  /*
   * Stop  the  tracee  at the next vfork(2) and automatically start tracing the newly vforked
   * process, which will start with a SIGSTOP, or PTRACE_EVENT_STOP if PTRACE_SEIZE was  used.
   * A waitpid(2) by the tracer will return a status value such that
   *
   *   status>>8 == (SIGTRAP | (PTRACE_EVENT_VFORK<<8))
   *
   * The PID of the new process can be retrieved with PTRACE_GETEVENTMSG.
   */
  ptrace_options |= PTRACE_O_TRACEVFORK;
  /*
   * Stop the tracee at the next clone(2) and automatically start  tracing  the  newly  cloned
   * process,  which will start with a SIGSTOP, or PTRACE_EVENT_STOP if PTRACE_SEIZE was used.
   * A waitpid(2) by the tracer will return a status value such that
   *
   *   status>>8 == (SIGTRAP | (PTRACE_EVENT_CLONE<<8))
   *
   * The PID of the new process can be retrieved with PTRACE_GETEVENTMSG.
   *
   * This option may not catch clone(2) calls in all cases.  If the tracee calls clone(2) with
   * the CLONE_VFORK flag, PTRACE_EVENT_VFORK will be delivered instead if PTRACE_O_TRACEVFORK
   * is set; otherwise if the tracee calls clone(2) with  the  exit  signal  set  to  SIGCHLD,
   * PTRACE_EVENT_FORK will be delivered if PTRACE_O_TRACEFORK is set.
   */
  ptrace_options |= PTRACE_O_TRACECLONE;
  /*
   * Stop the tracee at exit.  A waitpid(2) by the tracer will return a status value such that
   *
   * status>>8 == (SIGTRAP | (PTRACE_EVENT_EXIT<<8))
   *
   * The tracee's exit status can be retrieved with PTRACE_GETEVENTMSG.
   *
   * The tracee is stopped early during process exit, when registers are still available,  allowing
   * the tracer to see where the exit occurred, whereas the normal exit notification is
   * done after the process is finished exiting.  Even though context is available, the tracer
   * cannot prevent the exit from happening at this point.
   */
  ptrace_options |= PTRACE_O_TRACEEXIT;

  if (ptrace(PTRACE_SETOPTIONS, child_pid, 0, ptrace_options) == -1)
  {
    fprintf(stderr, "\nptrace(PTRACE_SETOPTIONS)\n");
    exit(-1);
  }
  if (ptrace_syscall(child_pid, 0) == -1)
  {
    exit(-1);
  }

  for (;;)
  {
    child_pid = waitpid(-1, &status, 0);

    if (child_pid == -1)
    {
      if (errno != ECHILD)
      {
        fprintf(stderr, "\nwaitpid returned -1 but did not set errno to ECHILD\n");
        return -1;
      }
      return 0;
    }

    if (WIFEXITED(status) || WIFSIGNALED(status))
    {
      continue;
    }
    else if (!WIFSTOPPED(status))
    {
      fprintf(stderr, "\nwaitpid returned bad status %d\n", status);
      return -1;
    }

    if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_VFORK << 8)))
    {
      // get the PID of the new process
      if (ptrace(PTRACE_SYSCALL, child_pid, 0, NULL) == -1)
      {
        fprintf(stderr, "\nptrace(PTRACE_SYSCALL)\n");
        return -1;
      }
    }
    else if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_FORK << 8)))
    {
      pid_t new_child_pid;
      if (ptrace(PTRACE_GETEVENTMSG, child_pid, 0, &new_child_pid) == -1)
      {
        fprintf(stderr, "\nptrace(PTRACE_GETEVENTMSG)\n");
        return -1;
      }
      // printf("fstrace: Child %d stopped by fork (new child %d)\n", child_pid, new_child_pid);
      if (ptrace(PTRACE_SYSCALL, child_pid, 0, NULL) == -1)
      {
        fprintf(stderr, "\nptrace(PTRACE_SYSCALL)\n");
        return -1;
      }
    }
    else if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_EXEC << 8)))
    {
      // printf("fstrace: Child %d stopped by exec\n", child_pid);
      if (ptrace(PTRACE_SYSCALL, child_pid, 0, NULL) == -1)
      {
        fprintf(stderr, "\nptrace(PTRACE_SYSCALL)\n");
        return -1;
      }
    }
    else if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_EXIT << 8)))
    {
      // get the exit status of the child
      unsigned long traceeStatus = 0;
      if (ptrace(PTRACE_GETEVENTMSG, child_pid, 0, &traceeStatus) == -1)
      {
        fprintf(stderr, "\nptrace(PTRACE_GETEVENTMSG)\n");
        return -1;
      }
      // printf("fstrace: Child %d exited with status %lu\n", child_pid, traceeStatus);
      ptrace(PTRACE_SYSCALL, child_pid, 0, NULL);
    }
    else if (WIFSTOPPED(status) && !(WSTOPSIG(status) & 0x80))
    {
      ptrace_syscall(child_pid, WSTOPSIG(status));
    }
    else if (WIFSTOPPED(status) && (WSTOPSIG(status) & 0x80))
    {
      // syscall-enter-stop
      // printf("fstrace: Child %d stopped by syscall %d\n", child_pid, WSTOPSIG(status) & 0x7f);
      handle_syscall(child_pid);
      ptrace_syscall(child_pid, 0);
    }
    else
    {
      fprintf(stderr, "\nunexpected stop. status: %d\n", status);
      ptrace_syscall(child_pid, 0);
    }
  }
}

int trace_exec(char *program, char **args)
{
  pid_t child_pid = fork();

  if (child_pid == 0)
  {
    run_tracee(program, args);
    fprintf(stderr, "\nexecvp error\n");
    return 1;
  }
  else if (child_pid > 0)
  {
    run_tracer(child_pid);
  }
  else
  {
    fprintf(stderr, "\nfork\n");
    return 1;
  }

  return 0;
}
