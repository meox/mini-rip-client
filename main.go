package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"golang.org/x/net/ipv4"
)

type entry struct {
	ip      string
	srcAddr string
	netmask int
	metric  uint32
}

func main() {
	var installed []entry

	interfaceName := flag.String("i", "eth0", "interface name")
	port := flag.Uint("p", 520, "service port")
	listenAddr := flag.String("l", "0.0.0.0", "listen address")
	flag.Parse()

	group := net.IPv4(224, 0, 0, 9)
	dev, err := net.InterfaceByName(*interfaceName)
	if err != nil {
		log.Fatalf("cannot find the interface: %v", err)
	}

	c, err := net.ListenPacket("udp4", fmt.Sprintf("%s:%d", *listenAddr, *port))
	if err != nil {
		log.Fatalf("cannot listen: %v", err)
	}
	defer c.Close()

	p := ipv4.NewPacketConn(c)
	if err := p.JoinGroup(dev, &net.UDPAddr{IP: group}); err != nil {
		log.Fatalf("cannot join: %v", err)
	}

	ch := make(chan entry, 1)

	// spawn the packet reader
	go packetReader(p, ch)

	// setup the inactivity RIP server timeout
	var lastUpdate time.Time
	noRipTimer := time.NewTimer(1 * time.Minute)
	defer noRipTimer.Stop()

	for {
		select {
		case e := <-ch:
			if isAlreadyInstalled(installed, e) {
				continue
			}

			prog, route := route("add", *interfaceName, e)
			args := strings.Split(route, " ")
			cmd := exec.Command(prog, args...)
			err := cmd.Run()
			if err != nil {
				if exitErr, ok := err.(*exec.ExitError); ok {
					if exitErr.ExitCode() == 2 {
						log.Printf("already installed: %s", route)
						installed = append(installed, e)
					} else {
						log.Printf("cannot install: %s, reason: %v", route, exitErr)
					}
				}
			} else {
				log.Printf("installed: %s %s", prog, route)
				installed = append(installed, e)
			}
			lastUpdate = time.Now()

		case <-noRipTimer.C:
			// cleanup installed routes
			if len(installed) == 0 {
				continue
			}
			if lastUpdate.Add(5 * time.Minute).After(time.Now()) {
				continue
			}

			log.Print("Cleanup routes")
			for _, e := range installed {
				prog, route := route("del", *interfaceName, e)
				args := strings.Split(route, " ")
				cmd := exec.Command(prog, args...)
				err := cmd.Run()
				if err != nil {
					log.Printf("cannot remove: %s %s, reason: %v", prog, route, err)
				}
			}

			installed = []entry{}
		}
	}
}

func packetReader(p *ipv4.PacketConn, ch chan<- entry) {
	b := make([]byte, 1500)

	for {
		n, _, src, err := p.ReadFrom(b)
		if err != nil {
			log.Printf("error reading packet: %v", err)
			time.Sleep(1 * time.Second)
			continue
		}

		// parse the packet
		if n < 4 {
			log.Printf("strange packet: discard it")
			continue
		}

		srcAddr, _, err := net.SplitHostPort(src.String())
		if err != nil {
			log.Printf("invalid src address: discard it")
			continue
		}

		if b[0] == 0x02 && b[1] == 0x02 && b[2] == 0x00 && b[3] == 0x00 {
			// rip packet: parse it
			entries := parseRip(b[4:n])
			for _, e := range entries {
				e.srcAddr = srcAddr
				ch <- e
			}
		} else {
			log.Printf("not rip-v2 packet: discard it")
		}
	}
}

func parseRip(b []byte) []entry {
	n := len(b)
	entry_bytes := 5 * 4
	max_entries := n / entry_bytes

	entries := make([]entry, 0, max_entries)

	for i := 0; i < n; i += entry_bytes {
		family := binary.BigEndian.Uint16(b[i : i+2])
		if family != 2 {
			continue
		}
		ip := fmt.Sprintf("%d.%d.%d.%d", b[i+4], b[i+5], b[i+6], b[i+7])
		netmask := fmt.Sprintf("%d.%d.%d.%d", b[i+8], b[i+9], b[i+10], b[i+11])

		stringMask := net.IPMask(net.ParseIP(netmask).To4())
		prefixLen, _ := stringMask.Size()

		metric := binary.BigEndian.Uint32(b[i+16 : i+20])

		entries = append(entries, entry{
			ip:      ip,
			netmask: prefixLen,
			metric:  metric,
		})
	}

	return entries
}

func isAlreadyInstalled(installed []entry, e entry) bool {
	for _, o := range installed {
		if o.ip == e.ip && o.netmask == e.netmask && o.metric == e.metric {
			return true
		}
	}

	return false
}

func route(action string, interfaceName string, e entry) (string, string) {
	var ret string
	var prog string

	switch runtime.GOOS {
	case "linux":
		prog = "ip"
		ret = fmt.Sprintf(
			"route %s %s/%d via %s dev %s proto rip metric %d",
			action,
			e.ip,
			e.netmask,
			e.srcAddr,
			interfaceName,
			e.metric,
		)
	case "darwin":
		if action == "del" {
			action = "delete"
		}

		prog = "route"
		ret = fmt.Sprintf(
			"-n %s -net %s/%d %s",
			action,
			e.ip,
			e.netmask,
			e.srcAddr,
		)
	}

	return prog, ret
}
