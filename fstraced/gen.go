package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go execve bpf/execve.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go vfs bpf/vfs.c
