//go:build !windows

package tui

import (
	"os"
	"syscall"
	"unsafe"
)

func enableConsole() func() {
	return func() {}
}

func termSize() (int, int) {
	type winsize struct {
		Row    uint16
		Col    uint16
		Xpixel uint16
		Ypixel uint16
	}
	ws := &winsize{}
	retCode, _, _ := syscall.Syscall(syscall.SYS_IOCTL,
		uintptr(syscall.Stdout),
		uintptr(syscall.TIOCGWINSZ),
		uintptr(unsafe.Pointer(ws)))
	if int(retCode) == -1 || ws.Col == 0 || ws.Row == 0 {
		return 100, 30
	}
	return int(ws.Col), int(ws.Row)
}

func IsTerminal() bool {
	fi, err := os.Stdout.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
