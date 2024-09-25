#include <unistd.h>
#include <string>

std::string get_syscall_name(long nr)
{
  switch (nr)
  {
  case __NR_read:
    return "read";
    break;
  case __NR_write:
    return "write";
    break;
  case __NR_open:
    return "open";
    break;
  case __NR_close:
    return "close";
    break;
  case __NR_stat:
    return "stat";
    break;
  case __NR_fstat:
    return "fstat";
    break;
  case __NR_lstat:
    return "lstat";
    break;
  case __NR_poll:
    return "poll";
    break;
  case __NR_lseek:
    return "lseek";
    break;
  case __NR_mmap:
    return "mmap";
    break;
  case __NR_mprotect:
    return "mprotect";
    break;
  case __NR_munmap:
    return "munmap";
    break;
  case __NR_brk:
    return "brk";
    break;
  case __NR_rt_sigaction:
    return "rt_sigaction";
    break;
  case __NR_rt_sigprocmask:
    return "rt_sigprocmask";
    break;
  case __NR_rt_sigreturn:
    return "rt_sigreturn";
    break;
  case __NR_ioctl:
    return "ioctl";
    break;
  case __NR_pread64:
    return "pread64";
    break;
  case __NR_pwrite64:
    return "pwrite64";
    break;
  case __NR_readv:
    return "readv";
    break;
  case __NR_writev:
    return "writev";
    break;
  case __NR_access:
    return "access";
    break;
  case __NR_pipe:
    return "pipe";
    break;
  case __NR_select:
    return "select";
    break;
  case __NR_sched_yield:
    return "sched_yield";
    break;
  case __NR_mremap:
    return "mremap";
    break;
  case __NR_msync:
    return "msync";
    break;
  case __NR_mincore:
    return "mincore";
    break;
  case __NR_madvise:
    return "madvise";
    break;
  case __NR_shmget:
    return "shmget";
    break;
  case __NR_shmat:
    return "shmat";
    break;
  case __NR_shmctl:
    return "shmctl";
    break;
  case __NR_dup:
    return "dup";
    break;
  case __NR_dup2:
    return "dup2";
    break;
  case __NR_pause:
    return "pause";
    break;
  case __NR_nanosleep:
    return "nanosleep";
    break;
  case __NR_getitimer:
    return "getitimer";
    break;
  case __NR_alarm:
    return "alarm";
    break;
  case __NR_setitimer:
    return "setitimer";
    break;
  case __NR_getpid:
    return "getpid";
    break;
  case __NR_sendfile:
    return "sendfile";
    break;
  case __NR_socket:
    return "socket";
    break;
  case __NR_connect:
    return "connect";
    break;
  case __NR_accept:
    return "accept";
    break;
  case __NR_sendto:
    return "sendto";
    break;
  case __NR_recvfrom:
    return "recvfrom";
    break;
  case __NR_sendmsg:
    return "sendmsg";
    break;
  case __NR_recvmsg:
    return "recvmsg";
    break;
  case __NR_shutdown:
    return "shutdown";
    break;
  case __NR_bind:
    return "bind";
    break;
  case __NR_listen:
    return "listen";
    break;
  case __NR_getsockname:
    return "getsockname";
    break;
  case __NR_getpeername:
    return "getpeername";
    break;
  case __NR_socketpair:
    return "socketpair";
    break;
  case __NR_setsockopt:
    return "setsockopt";
    break;
  case __NR_getsockopt:
    return "getsockopt";
    break;
  case __NR_clone:
    return "clone";
    break;
  case __NR_fork:
    return "fork";
    break;
  case __NR_vfork:
    return "vfork";
    break;
  case __NR_execve:
    return "execve";
    break;
  case __NR_exit:
    return "exit";
    break;
  case __NR_wait4:
    return "wait4";
    break;
  case __NR_kill:
    return "kill";
    break;
  case __NR_uname:
    return "uname";
    break;
  case __NR_semget:
    return "semget";
    break;
  case __NR_semop:
    return "semop";
    break;
  case __NR_semctl:
    return "semctl";
    break;
  case __NR_shmdt:
    return "shmdt";
    break;
  case __NR_msgget:
    return "msgget";
    break;
  case __NR_msgsnd:
    return "msgsnd";
    break;
  case __NR_msgrcv:
    return "msgrcv";
    break;
  case __NR_msgctl:
    return "msgctl";
    break;
  case __NR_fcntl:
    return "fcntl";
    break;
  case __NR_flock:
    return "flock";
    break;
  case __NR_fsync:
    return "fsync";
    break;
  case __NR_fdatasync:
    return "fdatasync";
    break;
  case __NR_truncate:
    return "truncate";
    break;
  case __NR_ftruncate:
    return "ftruncate";
    break;
  case __NR_getdents:
    return "getdents";
    break;
  case __NR_getcwd:
    return "getcwd";
    break;
  case __NR_chdir:
    return "chdir";
    break;
  case __NR_fchdir:
    return "fchdir";
    break;
  case __NR_rename:
    return "rename";
    break;
  case __NR_mkdir:
    return "mkdir";
    break;
  case __NR_rmdir:
    return "rmdir";
    break;
  case __NR_creat:
    return "creat";
    break;
  case __NR_link:
    return "link";
    break;
  case __NR_unlink:
    return "unlink";
    break;
  case __NR_symlink:
    return "symlink";
    break;
  case __NR_readlink:
    return "readlink";
    break;
  case __NR_chmod:
    return "chmod";
    break;
  case __NR_fchmod:
    return "fchmod";
    break;
  case __NR_chown:
    return "chown";
    break;
  case __NR_fchown:
    return "fchown";
    break;
  case __NR_lchown:
    return "lchown";
    break;
  case __NR_umask:
    return "umask";
    break;
  case __NR_gettimeofday:
    return "gettimeofday";
    break;
  case __NR_getrlimit:
    return "getrlimit";
    break;
  case __NR_getrusage:
    return "getrusage";
    break;
  case __NR_sysinfo:
    return "sysinfo";
    break;
  case __NR_times:
    return "times";
    break;
  case __NR_ptrace:
    return "ptrace";
    break;
  case __NR_getuid:
    return "getuid";
    break;
  case __NR_syslog:
    return "syslog";
    break;
  case __NR_getgid:
    return "getgid";
    break;
  case __NR_setuid:
    return "setuid";
    break;
  case __NR_setgid:
    return "setgid";
    break;
  case __NR_geteuid:
    return "geteuid";
    break;
  case __NR_getegid:
    return "getegid";
    break;
  case __NR_setpgid:
    return "setpgid";
    break;
  case __NR_getppid:
    return "getppid";
    break;
  case __NR_getpgrp:
    return "getpgrp";
    break;
  case __NR_setsid:
    return "setsid";
    break;
  case __NR_setreuid:
    return "setreuid";
    break;
  case __NR_setregid:
    return "setregid";
    break;
  case __NR_getgroups:
    return "getgroups";
    break;
  case __NR_setgroups:
    return "setgroups";
    break;
  case __NR_setresuid:
    return "setresuid";
    break;
  case __NR_getresuid:
    return "getresuid";
    break;
  case __NR_setresgid:
    return "setresgid";
    break;
  case __NR_getresgid:
    return "getresgid";
    break;
  case __NR_getpgid:
    return "getpgid";
    break;
  case __NR_setfsuid:
    return "setfsuid";
    break;
  case __NR_setfsgid:
    return "setfsgid";
    break;
  case __NR_getsid:
    return "getsid";
    break;
  case __NR_capget:
    return "capget";
    break;
  case __NR_capset:
    return "capset";
    break;
  case __NR_rt_sigpending:
    return "rt_sigpending";
    break;
  case __NR_rt_sigtimedwait:
    return "rt_sigtimedwait";
    break;
  case __NR_rt_sigqueueinfo:
    return "rt_sigqueueinfo";
    break;
  case __NR_rt_sigsuspend:
    return "rt_sigsuspend";
    break;
  case __NR_sigaltstack:
    return "sigaltstack";
    break;
  case __NR_utime:
    return "utime";
    break;
  case __NR_mknod:
    return "mknod";
    break;
  case __NR_uselib:
    return "uselib";
    break;
  case __NR_personality:
    return "personality";
    break;
  case __NR_ustat:
    return "ustat";
    break;
  case __NR_statfs:
    return "statfs";
    break;
  case __NR_fstatfs:
    return "fstatfs";
    break;
  case __NR_sysfs:
    return "sysfs";
    break;
  case __NR_getpriority:
    return "getpriority";
    break;
  case __NR_setpriority:
    return "setpriority";
    break;
  case __NR_sched_setparam:
    return "sched_setparam";
    break;
  case __NR_sched_getparam:
    return "sched_getparam";
    break;
  case __NR_sched_setscheduler:
    return "sched_setscheduler";
    break;
  case __NR_sched_getscheduler:
    return "sched_getscheduler";
    break;
  case __NR_sched_get_priority_max:
    return "sched_get_priority_max";
    break;
  case __NR_sched_get_priority_min:
    return "sched_get_priority_min";
    break;
  case __NR_sched_rr_get_interval:
    return "sched_rr_get_interval";
    break;
  case __NR_mlock:
    return "mlock";
    break;
  case __NR_munlock:
    return "munlock";
    break;
  case __NR_mlockall:
    return "mlockall";
    break;
  case __NR_munlockall:
    return "munlockall";
    break;
  case __NR_vhangup:
    return "vhangup";
    break;
  case __NR_modify_ldt:
    return "modify_ldt";
    break;
  case __NR_pivot_root:
    return "pivot_root";
    break;
  case __NR__sysctl:
    return "_sysctl";
    break;
  case __NR_prctl:
    return "prctl";
    break;
  case __NR_arch_prctl:
    return "arch_prctl";
    break;
  case __NR_adjtimex:
    return "adjtimex";
    break;
  case __NR_setrlimit:
    return "setrlimit";
    break;
  case __NR_chroot:
    return "chroot";
    break;
  case __NR_sync:
    return "sync";
    break;
  case __NR_acct:
    return "acct";
    break;
  case __NR_settimeofday:
    return "settimeofday";
    break;
  case __NR_mount:
    return "mount";
    break;
  case __NR_umount2:
    return "umount2";
    break;
  case __NR_swapon:
    return "swapon";
    break;
  case __NR_swapoff:
    return "swapoff";
    break;
  case __NR_reboot:
    return "reboot";
    break;
  case __NR_sethostname:
    return "sethostname";
    break;
  case __NR_setdomainname:
    return "setdomainname";
    break;
  case __NR_iopl:
    return "iopl";
    break;
  case __NR_ioperm:
    return "ioperm";
    break;
  case __NR_create_module:
    return "create_module";
    break;
  case __NR_init_module:
    return "init_module";
    break;
  case __NR_delete_module:
    return "delete_module";
    break;
  case __NR_get_kernel_syms:
    return "get_kernel_syms";
    break;
  case __NR_query_module:
    return "query_module";
    break;
  case __NR_quotactl:
    return "quotactl";
    break;
  case __NR_nfsservctl:
    return "nfsservctl";
    break;
  case __NR_getpmsg:
    return "getpmsg";
    break;
  case __NR_putpmsg:
    return "putpmsg";
    break;
  case __NR_afs_syscall:
    return "afs_syscall";
    break;
  case __NR_tuxcall:
    return "tuxcall";
    break;
  case __NR_security:
    return "security";
    break;
  case __NR_gettid:
    return "gettid";
    break;
  case __NR_readahead:
    return "readahead";
    break;
  case __NR_setxattr:
    return "setxattr";
    break;
  case __NR_lsetxattr:
    return "lsetxattr";
    break;
  case __NR_fsetxattr:
    return "fsetxattr";
    break;
  case __NR_getxattr:
    return "getxattr";
    break;
  case __NR_lgetxattr:
    return "lgetxattr";
    break;
  case __NR_fgetxattr:
    return "fgetxattr";
    break;
  case __NR_listxattr:
    return "listxattr";
    break;
  case __NR_llistxattr:
    return "llistxattr";
    break;
  case __NR_flistxattr:
    return "flistxattr";
    break;
  case __NR_removexattr:
    return "removexattr";
    break;
  case __NR_lremovexattr:
    return "lremovexattr";
    break;
  case __NR_fremovexattr:
    return "fremovexattr";
    break;
  case __NR_tkill:
    return "tkill";
    break;
  case __NR_time:
    return "time";
    break;
  case __NR_futex:
    return "futex";
    break;
  case __NR_sched_setaffinity:
    return "sched_setaffinity";
    break;
  case __NR_sched_getaffinity:
    return "sched_getaffinity";
    break;
  case __NR_set_thread_area:
    return "set_thread_area";
    break;
  case __NR_io_setup:
    return "io_setup";
    break;
  case __NR_io_destroy:
    return "io_destroy";
    break;
  case __NR_io_getevents:
    return "io_getevents";
    break;
  case __NR_io_submit:
    return "io_submit";
    break;
  case __NR_io_cancel:
    return "io_cancel";
    break;
  case __NR_get_thread_area:
    return "get_thread_area";
    break;
  case __NR_lookup_dcookie:
    return "lookup_dcookie";
    break;
  case __NR_epoll_create:
    return "epoll_create";
    break;
  case __NR_epoll_ctl_old:
    return "epoll_ctl_old";
    break;
  case __NR_epoll_wait_old:
    return "epoll_wait_old";
    break;
  case __NR_remap_file_pages:
    return "remap_file_pages";
    break;
  case __NR_getdents64:
    return "getdents64";
    break;
  case __NR_set_tid_address:
    return "set_tid_address";
    break;
  case __NR_restart_syscall:
    return "restart_syscall";
    break;
  case __NR_semtimedop:
    return "semtimedop";
    break;
  case __NR_fadvise64:
    return "fadvise64";
    break;
  case __NR_timer_create:
    return "timer_create";
    break;
  case __NR_timer_settime:
    return "timer_settime";
    break;
  case __NR_timer_gettime:
    return "timer_gettime";
    break;
  case __NR_timer_getoverrun:
    return "timer_getoverrun";
    break;
  case __NR_timer_delete:
    return "timer_delete";
    break;
  case __NR_clock_settime:
    return "clock_settime";
    break;
  case __NR_clock_gettime:
    return "clock_gettime";
    break;
  case __NR_clock_getres:
    return "clock_getres";
    break;
  case __NR_clock_nanosleep:
    return "clock_nanosleep";
    break;
  case __NR_exit_group:
    return "exit_group";
    break;
  case __NR_epoll_wait:
    return "epoll_wait";
    break;
  case __NR_epoll_ctl:
    return "epoll_ctl";
    break;
  case __NR_tgkill:
    return "tgkill";
    break;
  case __NR_utimes:
    return "utimes";
    break;
  case __NR_vserver:
    return "vserver";
    break;
  case __NR_mbind:
    return "mbind";
    break;
  case __NR_set_mempolicy:
    return "set_mempolicy";
    break;
  case __NR_get_mempolicy:
    return "get_mempolicy";
    break;
  case __NR_mq_open:
    return "mq_open";
    break;
  case __NR_mq_unlink:
    return "mq_unlink";
    break;
  case __NR_mq_timedsend:
    return "mq_timedsend";
    break;
  case __NR_mq_timedreceive:
    return "mq_timedreceive";
    break;
  case __NR_mq_notify:
    return "mq_notify";
    break;
  case __NR_mq_getsetattr:
    return "mq_getsetattr";
    break;
  case __NR_kexec_load:
    return "kexec_load";
    break;
  case __NR_waitid:
    return "waitid";
    break;
  case __NR_add_key:
    return "add_key";
    break;
  case __NR_request_key:
    return "request_key";
    break;
  case __NR_keyctl:
    return "keyctl";
    break;
  case __NR_ioprio_set:
    return "ioprio_set";
    break;
  case __NR_ioprio_get:
    return "ioprio_get";
    break;
  case __NR_inotify_init:
    return "inotify_init";
    break;
  case __NR_inotify_add_watch:
    return "inotify_add_watch";
    break;
  case __NR_inotify_rm_watch:
    return "inotify_rm_watch";
    break;
  case __NR_migrate_pages:
    return "migrate_pages";
    break;
  case __NR_openat:
    return "openat";
    break;
  case __NR_mkdirat:
    return "mkdirat";
    break;
  case __NR_mknodat:
    return "mknodat";
    break;
  case __NR_fchownat:
    return "fchownat";
    break;
  case __NR_futimesat:
    return "futimesat";
    break;
  case __NR_newfstatat:
    return "newfstatat";
    break;
  case __NR_unlinkat:
    return "unlinkat";
    break;
  case __NR_renameat:
    return "renameat";
    break;
  case __NR_linkat:
    return "linkat";
    break;
  case __NR_symlinkat:
    return "symlinkat";
    break;
  case __NR_readlinkat:
    return "readlinkat";
    break;
  case __NR_fchmodat:
    return "fchmodat";
    break;
  case __NR_faccessat:
    return "faccessat";
    break;
  case __NR_pselect6:
    return "pselect6";
    break;
  case __NR_ppoll:
    return "ppoll";
    break;
  case __NR_unshare:
    return "unshare";
    break;
  case __NR_set_robust_list:
    return "set_robust_list";
    break;
  case __NR_get_robust_list:
    return "get_robust_list";
    break;
  case __NR_splice:
    return "splice";
    break;
  case __NR_tee:
    return "tee";
    break;
  case __NR_sync_file_range:
    return "sync_file_range";
    break;
  case __NR_vmsplice:
    return "vmsplice";
    break;
  case __NR_move_pages:
    return "move_pages";
    break;
  case __NR_utimensat:
    return "utimensat";
    break;
  case __NR_epoll_pwait:
    return "epoll_pwait";
    break;
  case __NR_signalfd:
    return "signalfd";
    break;
  case __NR_timerfd_create:
    return "timerfd_create";
    break;
  case __NR_eventfd:
    return "eventfd";
    break;
  case __NR_fallocate:
    return "fallocate";
    break;
  case __NR_timerfd_settime:
    return "timerfd_settime";
    break;
  case __NR_timerfd_gettime:
    return "timerfd_gettime";
    break;
  case __NR_accept4:
    return "accept4";
    break;
  case __NR_signalfd4:
    return "signalfd4";
    break;
  case __NR_eventfd2:
    return "eventfd2";
    break;
  case __NR_epoll_create1:
    return "epoll_create1";
    break;
  case __NR_dup3:
    return "dup3";
    break;
  case __NR_pipe2:
    return "pipe2";
    break;
  case __NR_inotify_init1:
    return "inotify_init1";
    break;
  case __NR_preadv:
    return "preadv";
    break;
  case __NR_pwritev:
    return "pwritev";
    break;
  case __NR_rt_tgsigqueueinfo:
    return "rt_tgsigqueueinfo";
    break;
  case __NR_perf_event_open:
    return "perf_event_open";
    break;
  case __NR_recvmmsg:
    return "recvmmsg";
    break;
  case __NR_fanotify_init:
    return "fanotify_init";
    break;
  case __NR_fanotify_mark:
    return "fanotify_mark";
    break;
  case __NR_prlimit64:
    return "prlimit64";
    break;
  case __NR_name_to_handle_at:
    return "name_to_handle_at";
    break;
  case __NR_open_by_handle_at:
    return "open_by_handle_at";
    break;
  case __NR_clock_adjtime:
    return "clock_adjtime";
    break;
  case __NR_syncfs:
    return "syncfs";
    break;
  case __NR_sendmmsg:
    return "sendmmsg";
    break;
  case __NR_setns:
    return "setns";
    break;
  case __NR_getcpu:
    return "getcpu";
    break;
  case __NR_process_vm_readv:
    return "process_vm_readv";
    break;
  case __NR_process_vm_writev:
    return "process_vm_writev";
    break;
  case __NR_kcmp:
    return "kcmp";
    break;
  case __NR_finit_module:
    return "finit_module";
    break;
  case __NR_sched_setattr:
    return "sched_setattr";
    break;
  case __NR_sched_getattr:
    return "sched_getattr";
    break;
  case __NR_renameat2:
    return "renameat2";
    break;
  case __NR_seccomp:
    return "seccomp";
    break;
  case __NR_getrandom:
    return "getrandom";
    break;
  case __NR_memfd_create:
    return "memfd_create";
    break;
  case __NR_kexec_file_load:
    return "kexec_file_load";
    break;
  case __NR_bpf:
    return "bpf";
    break;
  case __NR_execveat:
    return "execveat";
    break;
  case __NR_userfaultfd:
    return "userfaultfd";
    break;
  case __NR_membarrier:
    return "membarrier";
    break;
  case __NR_mlock2:
    return "mlock2";
    break;
  case __NR_copy_file_range:
    return "copy_file_range";
    break;
  case __NR_preadv2:
    return "preadv2";
    break;
  case __NR_pwritev2:
    return "pwritev2";
    break;
  case __NR_pkey_mprotect:
    return "pkey_mprotect";
    break;
  case __NR_pkey_alloc:
    return "pkey_alloc";
    break;
  case __NR_pkey_free:
    return "pkey_free";
    break;
  case __NR_statx:
    return "statx";
    break;
  case __NR_io_pgetevents:
    return "io_pgetevents";
    break;
  case __NR_rseq:
    return "rseq";
    break;
  case __NR_pidfd_send_signal:
    return "pidfd_send_signal";
    break;
  case __NR_io_uring_setup:
    return "io_uring_setup";
    break;
  case __NR_io_uring_enter:
    return "io_uring_enter";
    break;
  case __NR_io_uring_register:
    return "io_uring_register";
    break;
  case __NR_open_tree:
    return "open_tree";
    break;
  case __NR_move_mount:
    return "move_mount";
    break;
  case __NR_fsopen:
    return "fsopen";
    break;
  case __NR_fsconfig:
    return "fsconfig";
    break;
  case __NR_fsmount:
    return "fsmount";
    break;
  case __NR_fspick:
    return "fspick";
    break;
  case __NR_pidfd_open:
    return "pidfd_open";
    break;
  case __NR_clone3:
    return "clone3";
    break;
  case __NR_close_range:
    return "close_range";
    break;
  case __NR_openat2:
    return "openat2";
    break;
  case __NR_pidfd_getfd:
    return "pidfd_getfd";
    break;
  case __NR_faccessat2:
    return "faccessat2";
    break;
  case __NR_process_madvise:
    return "process_madvise";
    break;
  case __NR_epoll_pwait2:
    return "epoll_pwait2";
    break;
  case __NR_mount_setattr:
    return "mount_setattr";
    break;
  case __NR_quotactl_fd:
    return "quotactl_fd";
    break;
  case __NR_landlock_create_ruleset:
    return "landlock_create_ruleset";
    break;
  case __NR_landlock_add_rule:
    return "landlock_add_rule";
    break;
  case __NR_landlock_restrict_self:
    return "landlock_restrict_self";
    break;
  case __NR_memfd_secret:
    return "memfd_secret";
    break;
  case __NR_process_mrelease:
    return "process_mrelease";
    break;
  default:
    return "";
  }
}