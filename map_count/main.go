package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf bpf/xdp_prog_kern.c -- -I../libbpf/src

var iface string

type datarec struct {
	RxPackets int64 `ebpf:"rx_packets"`
	RxBytes   int64 `ebpf:"rx_bytes"`
}

const mapKey uint32 = 2

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

	ctrlC := make(chan os.Signal, 1)
	signal.Notify(ctrlC, os.Interrupt)

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	fmt.Println("Ready...")

	for {
		select {
		case <-ticker.C:
			var v datarec

			err := objs.XdpStatsMap.Lookup(mapKey, &v)
			if err != nil {
				log.Fatalf("reading map: %v", err)
			}

			fmt.Printf("%v pkts\t%v bytes\n", v.RxPackets, v.RxBytes)
		case <-ctrlC:
			fmt.Println("\nDetaching program and exit")
			return
		}
	}
}
