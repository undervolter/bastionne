package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"krushitel/core/fwd"
	"krushitel/core/sdk"
)

func main() {
	serial := flag.String("serial", "", "серийник: туннель своим стеком fwd")
	host := flag.String("host", "127.0.0.1", "хост без туннеля")
	port := flag.Int("port", 37777, "SDK-порт камеры")
	user := flag.String("user", "krushitel", "логин")
	pass := flag.String("pass", "TancuiPantera1337", "пароль")
	flag.Parse()

	var dial func() (net.Conn, error)
	if *serial != "" {
		f, err := fwd.Start(*serial, []fwd.PortSpec{{Local: 0, Remote: *port}}, 0, "", "")
		if err != nil {
			fmt.Println("[-] туннель не встал:", err)
			os.Exit(1)
		}
		defer f.Stop()
		dial = func() (net.Conn, error) { return f.DialCamera(*port) }
		fmt.Println("[+] туннель ок")
	} else {
		h, p := *host, *port
		dial = func() (net.Conn, error) { return net.DialTimeout("tcp", fmt.Sprintf("%s:%d", h, p), 10*time.Second) }
	}

	c := sdk.NewOnDialer(dial, *user, *pass)
	users, raw, err := c.GetUsers(10 * time.Second)
	fmt.Printf("err=%v users=%d\n", err, len(users))
	fmt.Printf("raw: %q\n", raw)
	for _, u := range users {
		fmt.Printf("  index=%d name=%q pass=%q group=%q\n", u.Index, u.Name, u.Pass, u.Group)
	}
}
