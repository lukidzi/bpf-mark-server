package main

import (
	"context"
	"fmt"
	"hash/fnv"
	"net"
	"net/http"
	"path"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)


func IP2Linux(ipstr string) (uint32, error) {
	ip := net.ParseIP(ipstr)
	if ip == nil {
		return 0, fmt.Errorf("error parse ip: %s", ipstr)
	}
	return *(*uint32)(unsafe.Pointer(&ip[12])), nil
}

func hello(w http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(w, "hello\n")
}

func main() {
	netns := "/proc/1/ns/net"
	var addrs []net.Addr
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		if (iface.Flags&net.FlagLoopback) != 0 || (iface.Flags&net.FlagUp) == 0 {
			continue
		}
		ifAddrs, err := iface.Addrs()
		if err != nil || len(ifAddrs) == 0 {
			continue
		}
		addrs = append(addrs, ifAddrs...)
	}
	if len(addrs) == 0 {

		panic("")
	}
	if len(addrs) != 1 {

	}

	lc := listenConfig(addrs[0], netns)

	_, err := lc.Listen(context.Background(), "tcp", "0.0.0.0:39807")
	if err != nil {
		panic("")
	}

	http.HandleFunc("/hello", hello)
	http.ListenAndServe(":19999", nil)

}

func listenConfig(addr net.Addr, netns string) net.ListenConfig {
	return net.ListenConfig{
		Control: func(network, address string, conn syscall.RawConn) error {
			var operr error
			if err := conn.Control(func(fd uintptr) {
				m, err := ebpf.LoadPinnedMap(path.Join("/sys/fs/bpf", "mark_pod_ips_map"), &ebpf.LoadPinOptions{})
				if err != nil {
					operr = err
					return
				}
				var ip uint32
				switch v := addr.(type) { // todo instead of hash
				case *net.IPNet: // nolint: typecheck
					ip, err = IP2Linux(v.IP.String())
					fmt.Println(v.IP.String())
				case *net.IPAddr: // nolint: typecheck
					ip, err = IP2Linux(v.String())
					fmt.Println(v.IP.String())
				}

				if err != nil {
					operr = err
					return
				}
				key := getMarkKeyOfNetns(netns)
				operr = m.Update(key, ip, ebpf.UpdateAny)
				if operr != nil {
					return
				}
				operr = syscall.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(key))
			}); err != nil {
				return err
			}
			return operr
		},
	}
}

func getMarkKeyOfNetns(netns string) uint32 {
	// todo check conflict?
	algorithm := fnv.New32a()
	_, _ = algorithm.Write([]byte(netns))
	return algorithm.Sum32()
}
