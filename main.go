package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

func initOpenAtProgram(dev, ino uint64) {
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	openAtSpec, err := loadOpenat()
	if err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}

	if err := openAtSpec.Variables["NS_INO"].Set(ino); err != nil {
		log.Panicf("setting variable: %s", err)
	}

	if err := openAtSpec.Variables["NS_DEV"].Set(dev); err != nil {
		log.Panicf("setting variable: %s", err)
	}

	var openAtObjs openatObjects
	if err := openAtSpec.LoadAndAssign(&openAtObjs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer openAtObjs.Close()

	link1, err := link.Tracepoint("syscalls", "sys_enter_openat", openAtObjs.TracepointSyscallsSysEnterOpenat, nil)
	if err != nil {
		log.Fatal("link error", err)
	}
	defer link1.Close()

	link2, err := link.Tracepoint("syscalls", "sys_exit_openat", openAtObjs.TracepointSyscallsSysExitOpenat, nil)
	if err != nil {
		log.Fatal("link error", err)
	}
	defer link2.Close()

	link3, err := link.Tracepoint("syscalls", "sys_enter_openat2", openAtObjs.TracepointSyscallsSysEnterOpenat2, nil)
	if err != nil {
		log.Fatal("link error", err)
	}
	defer link3.Close()

	link4, err := link.Tracepoint("syscalls", "sys_exit_openat2", openAtObjs.TracepointSyscallsSysExitOpenat2, nil)
	if err != nil {
		log.Fatal("link error", err)
	}
	defer link4.Close()

	link5, err := link.Tracepoint("syscalls", "sys_enter_open", openAtObjs.TracepointSyscallsSysEnterOpen, nil)
	if err != nil {
		log.Fatal("link error", err)
	}
	defer link5.Close()

	link6, err := link.Tracepoint("syscalls", "sys_exit_open", openAtObjs.TracepointSyscallsSysExitOpen, nil)
	if err != nil {
		log.Fatal("link error", err)
	}
	defer link6.Close()

	go handleRingBufferOpenAt(ctx, openAtObjs.EventRingbuf)

	<-ctx.Done()
}

func B2S(bs []int8) string {
  b := make([]byte, len(bs))
  for i, v := range bs {
	b[i] = byte(v)
  }
  return string(b[:bytes.IndexByte(b, 0)])
}

func handleRingBufferOpenAt(ctx context.Context, events *ebpf.Map) {
	eventReader, err := ringbuf.NewReader(events)
	if err != nil {
		log.Fatal("Creating ring buffer reader:", err)
	}
	log.Println("Listening for events")
	go func() {
		<-ctx.Done()
		eventReader.Close()
	}()

	var ev openatPidTgidState

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

		fmt.Printf("[command=%s] [pid=%d] [tgid=%d] [nr=%d] [dfd=%d] [filename=%s] [flags=%d] [mode=%d] [ret=%d]\n",
		B2S(ev.Comm[:]), ev.Pid, ev.Tgid, ev.Nr, ev.Dfd, B2S(ev.Filename[:]), ev.Flags, ev.Mode, ev.Ret)
	}
}

func main() {
	log.Printf("Starting MyPID %d\n", os.Getpid())

	devinfo, err := os.Stat("/proc/self/ns/pid")
	if err != nil {
		log.Fatal("Error getting pid namespace info:", err)
	}

	dev := devinfo.Sys().(*syscall.Stat_t).Dev
	ino := devinfo.Sys().(*syscall.Stat_t).Ino
	fmt.Printf("NS info. DEV=%d, INODE=%d\n", dev, ino)

	initOpenAtProgram(dev, ino)
}
