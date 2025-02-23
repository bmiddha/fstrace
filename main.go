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

	syscalls := map[string]*ebpf.Program{
		"sys_enter_openat":  openAtObjs.TracepointSyscallsSysEnterOpenat,
		"sys_exit_openat":   openAtObjs.TracepointSyscallsSysExitOpenat,
		"sys_enter_openat2": openAtObjs.TracepointSyscallsSysEnterOpenat2,
		"sys_exit_openat2":  openAtObjs.TracepointSyscallsSysExitOpenat2,
		"sys_enter_open":    openAtObjs.TracepointSyscallsSysEnterOpen,
		"sys_exit_open":     openAtObjs.TracepointSyscallsSysExitOpen,
		"sys_enter_creat":   openAtObjs.TracepointSyscallsSysEnterCreat,
		"sys_exit_creat":    openAtObjs.TracepointSyscallsSysExitCreat,
	}

	for name, prog := range syscalls {
		link, err := link.Tracepoint("syscalls", name, prog, nil)
		if err != nil {
			log.Fatal("link error ", err)
		}
		defer link.Close()
	}

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

		fmt.Printf("[command: %16s]\t[pid: %10d]\t[tgid: %10d]\t[nr: %4d]\t[dfd: %5d]\t[flags: %5d]\t[ret: %5d]\t\t[filename: %s]\n",
		B2S(ev.Comm[:]), ev.Pid, ev.Tgid, ev.Nr, ev.Dfd, ev.Flags, ev.Ret, B2S(ev.Filename[:]))
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
