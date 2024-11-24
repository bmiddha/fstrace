package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

func server() {
	// Create a Unix domain socket at /var/run/user/$UID/fstrace.sock
	socketPath := fmt.Sprintf("/var/run/fstrace.sock")

	var listener net.Listener

	for i := 0; i < 5; i++ {
		err := os.Remove(socketPath)
		if err != nil && !os.IsNotExist(err) {
			fmt.Println("Error removing socket file:", err)
			return
		}

		listener, err = net.Listen("unix", socketPath)
		if err != nil {
			if err.(*net.OpError).Err.Error() == "address already in use" {
				fmt.Println("Socket already in use, retrying...")
				time.Sleep(time.Second * time.Duration(i))
				continue
			}
			fmt.Println("Error listening:", err)
			return
		}
	}
	if listener == nil {
		log.Panicln("Failed to create socket after 5 retries")
	}

	log.Println("Listening on:", socketPath)

	exec.Command("groupadd", "fstrace").Run()
	exec.Command("chown", "root:fstrace", socketPath).Run()
	exec.Command("chmod", "775", socketPath).Run()

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("accept error:", err)
			continue
		}

		go func(conn net.Conn) {
			defer conn.Close()

			var buf [512]byte
			n, err := conn.Read(buf[:])
			if err != nil {
				fmt.Println("read error:", err)
				return
			}

			fmt.Printf("Received message: %s\n", string(buf[:n]))

			// Send a response
			_, err = conn.Write([]byte("Hello from server!\n"))
			if err != nil {
				fmt.Println("write error:", err)
			}
		}(conn)
	}
}

func initBpfProgram() {
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var objs execveObjects
	if err := loadExecveObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	link, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TracepointSyscallsSysEnterExecve, nil)
	if err != nil {
		log.Fatal("link error", err)
	}
	defer link.Close()

	go handleRingBuffer(ctx, objs.Events)

	<-ctx.Done()
}

func handleRingBuffer(ctx context.Context, events *ebpf.Map) {
	eventReader, err := ringbuf.NewReader(events)
	if err != nil {
		log.Fatal("Creating ring buffer reader:", err)
	}
	log.Println("Listening for events")
	go func() {
		<-ctx.Done()
		eventReader.Close()
	}()

	var ev struct {
		Pid      uint32
		Ppid     uint32
		Uid      uint32
		Filename [500]byte
		Envp     [8][50]byte
		Argv     [8][50]byte
	}

	for {
		event, err := eventReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("Received signal, exiting..")
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}

		if err := binary.Read(bytes.NewBuffer(event.RawSample), binary.LittleEndian, &ev); err != nil {
			log.Printf("binary.Read: %s", err)
			continue
		}

		// command := string(ev.Filename[:bytes.IndexByte(ev.Filename[:], 0)])
		argv_str := ""
		// log.Printf("---\n")
		for i := 0; i < len(ev.Argv); i++ {
			null_byte := bytes.IndexByte(ev.Argv[i][:], 0)
			if null_byte <= 0 {
				break
			}
			argv_str += string(ev.Argv[i][:null_byte]) + " "
			// log.Printf("argv_str: %s\n", ev.Argv[i][:null_byte])
		}
		// log.Printf("---\n")

		// log.Printf("PID: %d PPID: %d UID: %d COMM: %s ARGV: %s ENVP: %s\n", ev.Pid, ev.Ppid, ev.Uid, command, argv_str, envp_str)

		// print argv
		log.Printf("PID: %d: %s\n", ev.Pid, argv_str)
	}
}

func main() {
	// go server()
	initBpfProgram()
}
