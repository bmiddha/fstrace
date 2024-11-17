package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

func main() {

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
		Pid  uint32
		Ppid uint32
		Uid  uint32
		Filename [500]byte
		Envp  [8][50]byte
		Argv  [8][50]byte
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
		for i := 0; i < len(ev.Argv); i++ {
			null_byte := bytes.IndexByte(ev.Argv[i][:], 0)
			if null_byte <= 0 {
				break
			}
			argv_str += string(ev.Argv[i][:null_byte]) + " "
		}


		// log.Printf("PID: %d PPID: %d UID: %d COMM: %s ARGV: %s ENVP: %s\n", ev.Pid, ev.Ppid, ev.Uid, command, argv_str, envp_str)

		// print argv
		log.Printf("PID: %d: %s\n", ev.Pid, argv_str)
	}
}
