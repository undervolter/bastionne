package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"krushitel/core/fwd"
	"krushitel/core/geo"
)

func main() {
	serial := "3L067DAPAZ89CC1"
	if len(os.Args) > 1 {
		serial = os.Args[1]
	}
	fmt.Printf("[*] Querying Dahua cloud for serial: %s ...\n", serial)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pub, local, code, err := fwd.ResolveDeviceAddr(ctx, serial)
	if err != nil {
		fmt.Printf("[-] Error: %v\n", err)
		os.Exit(1)
	}
	if code == 404 {
		fmt.Println("[-] Device not found in cloud (404)")
		os.Exit(1)
	}

	fmt.Printf("[+] Cloud Ack Code: %d\n", code)
	fmt.Printf("[+] Public  IP (NAT): %s\n", pub)
	fmt.Printf("[+] Private IP (LAN): %s\n", local)

	if pub != "" {
		host := pub
		if h, _, err := net.SplitHostPort(pub); err == nil {
			host = h
		}
		ip := net.ParseIP(host)
		if ip != nil {
			filter, err := geo.Open("GeoLite2-Country.mmdb", nil, nil, false)
			if err == nil && filter != nil && filter.Enabled() {
				fmt.Printf("[+] Country:          %s\n", filter.Country(ip))
			}
		}
	}
}
