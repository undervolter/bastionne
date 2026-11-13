package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"krushitel/core/fwd"
)

type dialer func() (net.Conn, error)

func clientOn(dial dialer, timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dial()
			},
		},
	}
}

func get(c *http.Client, path string) (int, string, error) {
	resp, err := c.Get("http://camera" + path)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	return resp.StatusCode, string(data), err
}

func main() {
	serial := flag.String("serial", "", "серийник: туннель своим стеком fwd")
	host := flag.String("host", "127.0.0.1", "хост без туннеля")
	port := flag.Int("port", 80, "веб-порт камеры")
	user := flag.String("user", "", "логин для HTTP RPC2-проверки")
	pass := flag.String("pass", "", "пароль для HTTP RPC2-проверки")
	write := flag.Bool("write", false, "проверить setConfig (LockLoginTimes тем же значением)")
	title := flag.String("title", "", "проверить запись ChannelTitle: поставить, прочитать, вернуть исходное")
	fixplus := flag.Bool("fixplus", false, "вернуть пробелы в ChannelTitle, если прошлая запись сделала из них '+'")
	osdtest := flag.Bool("osdtest", false, "проверить запись VideoWidget CustomTitle[0].Text, прочитать, вернуть исходное")
	fullPath := flag.String("path", "", "вывести полный ответ для одного CGI-пути")
	flag.Parse()

	var dial dialer
	if *serial != "" {
		fmt.Printf("== туннель по серийнику %s (HTTP %d)...\n", *serial, *port)
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
		dial = func() (net.Conn, error) {
			return net.DialTimeout("tcp", fmt.Sprintf("%s:%d", h, p), 10*time.Second)
		}
		fmt.Printf("== цель %s:%d\n", h, p)
	}

	c := clientOn(dial, 12*time.Second)

	if *fullPath != "" {
		code, body, err := get(c, *fullPath)
		if err != nil {
			fmt.Println("FAIL:", err)
			return
		}
		fmt.Printf("HTTP %d, %d bytes\n%s\n", code, len(body), body)
		return
	}

	reads := []string{
		"/cgi-bin/configManager.cgi?action=getConfig&name=General",
		"/cgi-bin/configManager.cgi?action=getConfig&name=Account",
		"/cgi-bin/configManager.cgi?action=getConfig&name=User",
		"/cgi-bin/configManager.cgi?action=getConfig&name=ChannelTitle",
		"/cgi-bin/configManager.cgi?action=getConfig&name=VideoWidget",
		"/cgi-bin/userManager.cgi?action=getUserInfoAll",
		"/cgi-bin/magicBox.cgi?action=getSystemInfo",
		"/cgi-bin/magicBox.cgi?action=getMachineName",
		"/cgi-bin/snapshot.cgi?channel=1",
	}

	for _, path := range reads {
		code, body, err := get(c, path)
		if err != nil {
			fmt.Printf("\n-- %s\n   FAIL %v\n", path, err)
			continue
		}
		kind := "text"
		snip := strings.ReplaceAll(strings.TrimSpace(body), "\r", "")
		if len(snip) > 300 {
			snip = snip[:300] + "..."
		}
		if strings.HasPrefix(body, "\xff\xd8") {
			kind = "JPEG"
			snip = fmt.Sprintf("%d bytes", len(body))
		}
		if strings.HasPrefix(body, "\x89PNG") {
			kind = "PNG"
			snip = fmt.Sprintf("%d bytes", len(body))
		}
		if strings.Contains(body, "<html") || strings.Contains(body, "<HTML") {
			kind = "html"
		}
		fmt.Printf("\n-- %s\n   HTTP %d [%s] %q\n", path, code, kind, snip)
	}

	if *write {
		fmt.Println("\n== setConfig LockLoginTimes=5 (no-op)")
		code, body, err := get(c, "/cgi-bin/configManager.cgi?action=setConfig&General.LockLoginTimes=5")
		if err != nil {
			fmt.Printf("   FAIL %v\n", err)
		} else {
			fmt.Printf("   HTTP %d %q\n", code, strings.TrimSpace(body))
		}
	}

	if *osdtest {
		fmt.Println("\n== VideoWidget CustomTitle[0].Text (write/read/restore)")
		const vw = "/cgi-bin/configManager.cgi?action=getConfig&name=VideoWidget"
		_, before, err := get(c, vw)
		orig := ""
		if err == nil {
			for _, line := range strings.Split(before, "\n") {
				if strings.HasPrefix(line, "table.VideoWidget[0].CustomTitle[0].Text=") {
					orig = strings.TrimRight(strings.TrimPrefix(line, "table.VideoWidget[0].CustomTitle[0].Text="), "\r")
				}
			}
			fmt.Printf("   before: %q\n", orig)
		}
		setURL := "/cgi-bin/configManager.cgi?action=setConfig" +
			"&VideoWidget[0].CustomTitle[0].Text=" + strings.ReplaceAll(url.QueryEscape("KRUSHITEL_CGI_OSD"), "+", "%20") +
			"&VideoWidget[0].CustomTitle[0].EncodeBlend=true" +
			"&VideoWidget[0].CustomTitle[0].PreviewBlend=true"
		code, body, err := get(c, setURL)
		if err != nil {
			fmt.Println("   set:", err)
		} else {
			fmt.Printf("   set: HTTP %d %q\n", code, strings.TrimSpace(body))
		}
		_, after, _ := get(c, vw)
		applied := strings.Contains(after, "KRUSHITEL_CGI_OSD")
		fmt.Printf("   after: applied=%v\n", applied)
		if orig != "" {
			restore := "/cgi-bin/configManager.cgi?action=setConfig" +
				"&VideoWidget[0].CustomTitle[0].Text=" + strings.ReplaceAll(url.QueryEscape(orig), "+", "%20")
			code, body, err := get(c, restore)
			if err != nil {
				fmt.Println("   restore:", err)
			} else {
				fmt.Printf("   restore: HTTP %d %q\n", code, strings.TrimSpace(body))
			}
		}
	}

	if *fixplus {
		fmt.Println("\n== ChannelTitle: '+' -> пробел")
		const path = "/cgi-bin/configManager.cgi?action=getConfig&name=ChannelTitle"
		_, cur, err := get(c, path)
		if err != nil {
			fmt.Println("   read:", err)
		} else {
			name := ""
			for _, line := range strings.Split(cur, "\n") {
				if strings.HasPrefix(line, "table.ChannelTitle[0].Name=") {
					name = strings.TrimPrefix(line, "table.ChannelTitle[0].Name=")
				}
			}
			fixed := strings.ReplaceAll(strings.TrimRight(name, "\r"), "+", " ")
			fmt.Printf("   current: %q\n   fixed:   %q\n", name, fixed)
			setURL := "/cgi-bin/configManager.cgi?action=setConfig&ChannelTitle[0].Name=" + strings.ReplaceAll(url.QueryEscape(fixed), "+", "%20")
			code, body, err := get(c, setURL)
			if err != nil {
				fmt.Println("   set:", err)
			} else {
				fmt.Printf("   set: HTTP %d %q\n", code, strings.TrimSpace(body))
			}
			_, after, _ := get(c, path)
			fmt.Printf("   after: %q\n", strings.ReplaceAll(strings.TrimSpace(after), "\n", " | "))
		}
	}

	if *title != "" {
		fmt.Println("\n== setConfig ChannelTitle (write/read/restore)")
		const path = "/cgi-bin/configManager.cgi?action=getConfig&name=ChannelTitle"
		_, before, err := get(c, path)
		if err != nil {
			fmt.Println("   read before:", err)
		} else {
			orig := ""
			for _, line := range strings.Split(before, "\n") {
				if strings.HasPrefix(line, "table.ChannelTitle[0].Name=") {
					orig = strings.TrimPrefix(line, "table.ChannelTitle[0].Name=")
				}
			}
			fmt.Printf("   before: %q\n", orig)
			setURL := "/cgi-bin/configManager.cgi?action=setConfig&ChannelTitle[0].Name=" + strings.ReplaceAll(url.QueryEscape(*title), "+", "%20")
			code, body, err := get(c, setURL)
			if err != nil {
				fmt.Println("   set:", err)
			} else {
				fmt.Printf("   set: HTTP %d %q\n", code, strings.TrimSpace(body))
			}
			_, after, err := get(c, path)
			if err != nil {
				fmt.Println("   read after:", err)
			} else {
				applied := strings.Contains(after, *title)
				fmt.Printf("   after: applied=%v %q\n", applied, strings.ReplaceAll(strings.TrimSpace(after), "\n", " | "))
			}
			if orig != "" {
				restore := "/cgi-bin/configManager.cgi?action=setConfig&ChannelTitle[0].Name=" + strings.ReplaceAll(url.QueryEscape(orig), "+", "%20")
				code, body, err := get(c, restore)
				if err != nil {
					fmt.Println("   restore:", err)
				} else {
					fmt.Printf("   restore: HTTP %d %q\n", code, strings.TrimSpace(body))
				}
			}
		}
	}

	if *user != "" && *pass != "" {
		fmt.Println("\n== HTTP RPC2_Login")
		body := fmt.Sprintf(`{"method":"global.login","params":{"userName":%q,"password":%q,"clientType":"Web3.0","loginType":"Direct"},"id":1,"session":0}`, *user, *pass)
		req, _ := http.NewRequest("POST", "http://camera/RPC2_Login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.Do(req)
		if err != nil {
			fmt.Println("   FAIL", err)
		} else {
			defer resp.Body.Close()
			data, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
			fmt.Printf("   HTTP %d %q\n", resp.StatusCode, strings.TrimSpace(string(data)))
		}
	}
}
