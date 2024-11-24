// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || arm || arm64 || loong64 || mips64le || mipsle || ppc64le || riscv64

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// loadVfs returns the embedded CollectionSpec for vfs.
func loadVfs() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_VfsBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load vfs: %w", err)
	}

	return spec, err
}

// loadVfsObjects loads vfs and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*vfsObjects
//	*vfsPrograms
//	*vfsMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadVfsObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadVfs()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// vfsSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type vfsSpecs struct {
	vfsProgramSpecs
	vfsMapSpecs
}

// vfsSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type vfsProgramSpecs struct {
	Prog *ebpf.ProgramSpec `ebpf:"prog"`
}

// vfsMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type vfsMapSpecs struct {
	EventRingbuf *ebpf.MapSpec `ebpf:"event_ringbuf"`
}

// vfsObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadVfsObjects or ebpf.CollectionSpec.LoadAndAssign.
type vfsObjects struct {
	vfsPrograms
	vfsMaps
}

func (o *vfsObjects) Close() error {
	return _VfsClose(
		&o.vfsPrograms,
		&o.vfsMaps,
	)
}

// vfsMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadVfsObjects or ebpf.CollectionSpec.LoadAndAssign.
type vfsMaps struct {
	EventRingbuf *ebpf.Map `ebpf:"event_ringbuf"`
}

func (m *vfsMaps) Close() error {
	return _VfsClose(
		m.EventRingbuf,
	)
}

// vfsPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadVfsObjects or ebpf.CollectionSpec.LoadAndAssign.
type vfsPrograms struct {
	Prog *ebpf.Program `ebpf:"prog"`
}

func (p *vfsPrograms) Close() error {
	return _VfsClose(
		p.Prog,
	)
}

func _VfsClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed vfs_bpfel.o
var _VfsBytes []byte