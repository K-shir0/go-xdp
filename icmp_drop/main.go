package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf bpf/xdp_prog_kern.c -- -I../libbpf/src

var iface string

func main() {
	flag.StringVar(&iface, "I", "", "interface attached xdp program")
	flag.Parse()

	if iface == "" {
		fmt.Println("interface is not set")
		os.Exit(1)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	ifce, err := net.InterfaceByName(iface)
	if err != nil {
		log.Fatal(err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProgHello,
		Interface: ifce.Index,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	<-sig
}
