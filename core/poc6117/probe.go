package main

import (
	"encoding/binary"
	"net"
	"strings"
	"time"
)

func a4Packet(op byte) []byte {
	pkt := make([]byte, 32)
	pkt[0] = 0xa4
	pkt[8] = op
	return pkt
}

func readSDKReply(conn net.Conn, timeout time.Duration) ([]byte, error) {
	conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 0, 2048)
	tmp := make([]byte, 4096)
	for {
		n, err := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if len(buf) >= 32 {
				pl := int(binary.LittleEndian.Uint32(buf[4:8]))
				if pl > 0 && pl < 1<<20 && len(buf) >= 32+pl {
					return buf, nil
				}
			}
			conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		}
		if err != nil {
			if len(buf) > 0 {
				return buf, nil
			}
			return nil, err
		}
	}
}

func probeNoAuthSDK(dial func() (net.Conn, error), timeout time.Duration) (serial, model string, channels int, ok bool) {
	if dial == nil {
		return
	}
	cmd := func(op byte) string {
		conn, err := dial()
		if err != nil {
			return ""
		}
		defer conn.Close()
		conn.SetWriteDeadline(time.Now().Add(timeout))
		if _, err := conn.Write(a4Packet(op)); err != nil {
			return ""
		}
		resp, err := readSDKReply(conn, timeout)
		if err != nil || len(resp) <= 32 {
			return ""
		}
		return strings.TrimRight(string(resp[32:]), "\x00\r\n ")
	}

	serial = cmd(0x07)
	if serial == "" {
		return
	}
	model = cmd(0x0b)
	if body := cmd(0x01); body != "" {
		channels = strings.Count(body, "&&") + 1
	}
	if channels <= 0 {
		channels = 1
	}
	ok = true
	return
}
