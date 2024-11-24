package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
)

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		fmt.Println("Usage: fstrace <program> <args>")
		os.Exit(1)
	}

	// Connect to the Unix domain socket
	conn, err := net.Dial("unix", "/var/run/fstrace.sock")
	if err != nil {
		fmt.Println("dial error:", err)
		os.Exit(1)
	}
	defer conn.Close()

	// Send a message
	_, err = conn.Write([]byte("PID: " + fmt.Sprint(os.Getpid()) + "\n"))
	if err != nil {
		fmt.Println("write error:", err)
		return
	}

	// Read the response
	var buf [512]byte
	n, err := conn.Read(buf[:])
	if err != nil {
		fmt.Println("read error:", err)
		return
	}

	fmt.Printf("Received message: %s\n", string(buf[:n]))

	// exec and forward all IO
	execCmd := exec.Command(args[0], args[1:]...)
	execCmd.Stdin = os.Stdin
	execCmd.Stdout = os.Stdout
	execCmd.Stderr = os.Stderr
	execCmd.Run()

}

// func main() {
// 	runtime.LockOSThread()
// 	args := os.Args[1:]
// 	if len(args) == 0 {
// 		fmt.Println("Usage: fstrace <program> <args>")
// 		os.Exit(1)
// 	}

// 	pid_uint, _, errno := syscall.Syscall(syscall.SYS_FORK, 0, 0, 0)
// 	if errno != 0 {
// 		fmt.Println("Fork failed:", errno)
// 		os.Exit(1)
// 	}

// 	pid := int(pid_uint)

// 	if pid == 0 {
// 		log.Println("My PID:", os.Getpid())
// 		_, _, errno = syscall.Syscall(syscall.SYS_PTRACE, syscall.PTRACE_TRACEME, 0, 0)
// 		if errno != 0 {
// 			fmt.Println("Ptrace failed:", errno)
// 			os.Exit(1)
// 		}

// 		// raize sigstop
// 		log.Println("Stopping child")
// 		err := syscall.Kill(os.Getpid(), syscall.SIGSTOP)
// 		if err != nil {
// 			fmt.Println("Kill failed:", err)
// 			os.Exit(1)
// 		}

// 		// run the program
// 		err = syscall.Exec(args[0], args, os.Environ())
// 		if err != nil {
// 			fmt.Println("Exec failed:", err)
// 			os.Exit(1)
// 		}

// 		return

// 	} else {
// 		log.Println("Child PID:", pid)

// 		log.Println("Waiting for child to stop")
// 		// Wait for the child to stop
// 		var waitStatus syscall.WaitStatus
// 		_, err := syscall.Wait4(pid, &waitStatus, 0, nil)
// 		if err != nil {
// 			fmt.Println("Wait4 failed:", err)
// 			os.Exit(1)
// 		}

// 		err = syscall.PtraceSetOptions(pid, syscall.PTRACE_O_TRACECLONE|syscall.PTRACE_O_TRACEFORK|syscall.PTRACE_O_TRACEVFORK|syscall.PTRACE_O_TRACEEXEC|syscall.PTRACE_O_TRACEEXIT)
// 		if err != nil {
// 			fmt.Println("PtraceSetOptions failed:", err)
// 			os.Exit(1)
// 		}

// 		// Continue the child process
// 		err = syscall.PtraceCont(pid, 0)
// 		if err != nil {
// 			fmt.Println("PtraceCont failed:", err)
// 			os.Exit(1)
// 		}

// 		log.Println("Child continued")

// 		initialPid := pid

// 		for {
// 			// Wait for the child to stop
// 			pid, err = syscall.Wait4(0, &waitStatus, 0, nil)
// 			if err != nil {
// 				fmt.Println("Wait4 failed:", err)
// 				os.Exit(1)
// 			}

// 			if waitStatus.Exited() {
// 				log.Printf("Child %d exited with status %d\n", pid, waitStatus.ExitStatus())
// 				if pid == initialPid {
// 					os.Exit(waitStatus.ExitStatus())
// 				}
// 			}

// 			if waitStatus.StopSignal() == syscall.SIGTRAP {
// 				log.Printf("Child %d SIGTRAP\n", pid)
// 				if waitStatus.TrapCause() == syscall.PTRACE_EVENT_CLONE {
// 					log.Println("Clone event")
// 				} else if waitStatus.TrapCause() == syscall.PTRACE_EVENT_FORK {
// 					log.Println("Fork event")
// 					// PTRACE_GETEVENTMSG
// 					var msg uintptr
// 					_, _, errno := syscall.Syscall6(syscall.SYS_PTRACE, syscall.PTRACE_GETEVENTMSG, uintptr(pid), 0, uintptr(unsafe.Pointer(&msg)), 0, 0)
// 					if errno != 0 {
// 						fmt.Println("Ptrace failed:", errno)
// 						os.Exit(1)
// 					}
// 					log.Println("Forked child PID:", msg)
// 				} else if waitStatus.TrapCause() == syscall.PTRACE_EVENT_VFORK {
// 					log.Println("Vfork event")
// 				} else if waitStatus.TrapCause() == syscall.PTRACE_EVENT_EXEC {
// 					log.Println("Exec event")
// 				} else if waitStatus.TrapCause() == syscall.PTRACE_EVENT_EXIT {
// 					log.Println("Exit event")
// 				}
// 			}

// 			// Continue the child process
// 			err = syscall.PtraceCont(pid, 0)
// 			if err != nil {
// 				if err == syscall.ESRCH {
// 						// Ignore "no such process" errors
// 						continue
// 				}
// 				fmt.Println("PtraceCont failed:", err)
// 				os.Exit(1)
// 		}
// 		}
// 	}

// }
