// package main

// import (
// 	"bytes"
// 	"context"
// 	"encoding/binary"
// 	"errors"
// 	"fmt"
// 	"log"
// 	"net"
// 	"os"
// 	"os/exec"
// 	"os/signal"
// 	"syscall"
// 	"time"

// 	"github.com/cilium/ebpf"
// 	"github.com/cilium/ebpf/link"
// 	"github.com/cilium/ebpf/ringbuf"
// 	"github.com/cilium/ebpf/rlimit"
// )

// func server() {
// 	// Create a Unix domain socket at /var/run/user/$UID/fstrace.sock
// 	socketPath := fmt.Sprintf("/var/run/fstrace.sock")

// 	var listener net.Listener

// 	for i := 0; i < 5; i++ {
// 		err := os.Remove(socketPath)
// 		if err != nil && !os.IsNotExist(err) {
// 			fmt.Println("Error removing socket file:", err)
// 			return
// 		}

// 		listener, err = net.Listen("unix", socketPath)
// 		if err != nil {
// 			if err.(*net.OpError).Err.Error() == "address already in use" {
// 				fmt.Println("Socket already in use, retrying...")
// 				time.Sleep(time.Second * time.Duration(i))
// 				continue
// 			}
// 			fmt.Println("Error listening:", err)
// 			return
// 		}
// 	}
// 	if listener == nil {
// 		log.Panicln("Failed to create socket after 5 retries")
// 	}

// 	log.Println("Listening on:", socketPath)

// 	exec.Command("groupadd", "fstrace").Run()
// 	exec.Command("chown", "root:fstrace", socketPath).Run()
// 	exec.Command("chmod", "775", socketPath).Run()

// 	for {
// 		conn, err := listener.Accept()
// 		if err != nil {
// 			fmt.Println("accept error:", err)
// 			continue
// 		}

// 		go func(conn net.Conn) {
// 			defer conn.Close()

// 			var buf [512]byte
// 			n, err := conn.Read(buf[:])
// 			if err != nil {
// 				fmt.Println("read error:", err)
// 				return
// 			}

// 			fmt.Printf("Received message: %s\n", string(buf[:n]))

// 			// Send a response
// 			_, err = conn.Write([]byte("Hello from server!\n"))
// 			if err != nil {
// 				fmt.Println("write error:", err)
// 			}
// 		}(conn)
// 	}
// }

// func initExecveProgram() {
// 	// Remove resource limits for kernels <5.11.
// 	if err := rlimit.RemoveMemlock(); err != nil {
// 		log.Fatal("Removing memlock:", err)
// 	}

// 	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
// 	defer stop()

// 	var objs execveObjects
// 	if err := loadExecveObjects(&objs, nil); err != nil {
// 		log.Fatal("Loading eBPF objects:", err)
// 	}
// 	defer objs.Close()

// 	link, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TracepointSyscallsSysEnterExecve, nil)
// 	if err != nil {
// 		log.Fatal("link error", err)
// 	}
// 	defer link.Close()

// 	go handleRingBufferExecve(ctx, objs.Events)

// 	<-ctx.Done()
// }

// func handleRingBufferExecve(ctx context.Context, events *ebpf.Map) {
// 	eventReader, err := ringbuf.NewReader(events)
// 	if err != nil {
// 		log.Fatal("Creating ring buffer reader:", err)
// 	}
// 	log.Println("Listening for events")
// 	go func() {
// 		<-ctx.Done()
// 		eventReader.Close()
// 	}()

// 	var ev struct {
// 		Pid      uint32
// 		Ppid     uint32
// 		Uid      uint32
// 		Filename [500]byte
// 		Envp     [8][50]byte
// 		Argv     [8][50]byte
// 	}

// 	for {
// 		event, err := eventReader.Read()
// 		if err != nil {
// 			if errors.Is(err, ringbuf.ErrClosed) {
// 				log.Println("Received signal, exiting..")
// 				return
// 			}
// 			log.Printf("reading from reader: %s", err)
// 			continue
// 		}

// 		if err := binary.Read(bytes.NewBuffer(event.RawSample), binary.LittleEndian, &ev); err != nil {
// 			log.Printf("binary.Read: %s", err)
// 			continue
// 		}

// 		// command := string(ev.Filename[:bytes.IndexByte(ev.Filename[:], 0)])
// 		argv_str := ""
// 		// log.Printf("---\n")
// 		for i := 0; i < len(ev.Argv); i++ {
// 			null_byte := bytes.IndexByte(ev.Argv[i][:], 0)
// 			if null_byte <= 0 {
// 				break
// 			}
// 			argv_str += string(ev.Argv[i][:null_byte]) + " "
// 			// log.Printf("argv_str: %s\n", ev.Argv[i][:null_byte])
// 		}
// 		// log.Printf("---\n")

// 		// log.Printf("PID: %d PPID: %d UID: %d COMM: %s ARGV: %s ENVP: %s\n", ev.Pid, ev.Ppid, ev.Uid, command, argv_str, envp_str)

// 		// print argv
// 		log.Printf("PID: %d: %s\n", ev.Pid, argv_str)
// 	}
// }

// func handleRingBufferVfs(ctx context.Context, events *ebpf.Map) {
// 	eventReader, err := ringbuf.NewReader(events)
// 	if err != nil {
// 		log.Fatal("Creating ring buffer reader:", err)
// 	}
// 	log.Println("Listening for events")
// 	go func() {
// 		<-ctx.Done()
// 		eventReader.Close()
// 	}()

// 	var ev struct {
// 		Pid      uint64
// 		Filename [4096]byte
// 	}

// 	for {
// 		event, err := eventReader.Read()
// 		if err != nil {
// 			if errors.Is(err, ringbuf.ErrClosed) {
// 				log.Println("Received signal, exiting..")
// 				return
// 			}
// 			log.Printf("reading from reader: %s", err)
// 			continue
// 		}

// 		if err := binary.Read(bytes.NewBuffer(event.RawSample), binary.LittleEndian, &ev); err != nil {
// 			log.Printf("binary.Read: %s", err)
// 			continue
// 		}

// 		// command := string(ev.Filename[:bytes.IndexByte(ev.Filename[:], 0)])
// 		// log.Printf("PID: %d PPID: %d UID: %d COMM: %s ARGV: %s ENVP: %s\n", ev.Pid, ev.Ppid, ev.Uid, command, argv_str, envp_str)
// 		filename := string(ev.Filename[:bytes.IndexByte(ev.Filename[:], 0)])
// 		// print argv
// 		log.Printf("PID: %d: %s\n", ev.Pid, filename)
// 	}
// }

// func initVfsProgram() {
// 	// Remove resource limits for kernels <5.11.
// 	if err := rlimit.RemoveMemlock(); err != nil {
// 		log.Fatal("Removing memlock:", err)
// 	}

// 	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
// 	defer stop()

// 	var objs vfsObjects
// 	if err := loadVfsObjects(&objs, nil); err != nil {
// 		// log.Fatal("Loading eBPF objects:", err)
// 		var verr *ebpf.VerifierError
// 		if errors.As(err, &verr) {
// 			fmt.Printf("%+v\n", verr)
// 		}
// 	}
// 	defer objs.Close()

// 	link, err := link.AttachTracing(link.TracingOptions{
// 		Program: objs.vfsPrograms.Prog,
// 	})
// 	if err != nil {
// 		log.Fatal("link error", err)
// 	}
// 	defer link.Close()

// 	go handleRingBufferVfs(ctx, objs.EventRingbuf)

// 	<-ctx.Done()
// }

// func initLsmProgram() {
// 	// Remove resource limits for kernels <5.11.
// 	if err := rlimit.RemoveMemlock(); err != nil {
// 		log.Fatal("Removing memlock:", err)
// 	}

// 	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
// 	defer stop()

// 	var objs lsmObjects
// 	if err := loadLsmObjects(&objs, nil); err != nil {
// 		// log.Fatal("Loading eBPF objects:", err)
// 		var verr *ebpf.VerifierError
// 		if errors.As(err, &verr) {
// 			fmt.Printf("%+v\n", verr)
// 		}
// 	}
// 	defer objs.Close()

// 	link, err := link.AttachLSM(link.LSMOptions{
// 		Program: objs.lsmPrograms.Prog,
// 	})
// 	if err != nil {
// 		log.Fatal("link error", err)
// 	}
// 	defer link.Close()

// 	// go handleRingBufferVfs(ctx, objs.lsmMaps)

// 	<-ctx.Done()
// }

// func main() {
// 	// go server()
// 	initLsmProgram()
// 	// initExecveProgram()
// 	// initVfsProgram()
// }

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"os/signal"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.

type Event struct {
	Type     uint32
	PID      uint32
	CgroupID uint64
	Str      [4096]byte
}

const (
	Enter = 1
	Exit  = 2
)

// const mapKey uint32 = 0

func main() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := vfsObjects{}
	if err := loadVfsObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	probeEnter, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_enter",
		Program: objs.RawTracepointSysEnter,
	})
	if err != nil {
		log.Fatalf("Attach raw tracepoint err: %s", err)
	}
	defer probeEnter.Close()

	probeExit, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_exit",
		Program: objs.RawTracepointSysExit,
	})
	if err != nil {
		log.Fatalf("Attach raw tracepoint err: %s", err)
	}
	defer probeExit.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("creating perf event reader: %s", err)
	}
	defer rd.Close()

	go func() {
		// Wait for a signal and close the perf reader,
		// which will interrupt rd.Read() and make the program exit.
		<-sig
		log.Println("Received signal, exiting program..")

		if err := rd.Close(); err != nil {
			log.Fatalf("closing perf event reader: %s", err)
		}
	}()

	var event Event
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				break
			}
			log.Printf("reading from perf event reader: %s", err)
			continue
		}

		// if record.LostSamples != 0 {
		// 	log.Printf("perf event ring buffer full, dropped %d samples", record.LostSamples)
		// 	continue
		// }

		// Parse the perf event entry into an Event structure.
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing perf event: %s", err)
			continue
		}

		typ := "enter"
		if event.Type == Exit {
			typ = "exit"
		}

		log.Printf("%d/%s cg=%d %s", event.PID, typ, event.CgroupID&0xFFFFFF, unix.ByteSliceToString(event.Str[:]))
	}
}