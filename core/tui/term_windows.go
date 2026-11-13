//go:build windows

package tui

import (
	"os"

	"golang.org/x/sys/windows"
)

const (
	enableVirtualTerminalProcessing = 0x0004
	enableLineInput                 = 0x0002
	enableEchoInput                 = 0x0004
	enableProcessedInput            = 0x0001
)

func enableConsole() func() {
	stdout := windows.Handle(os.Stdout.Fd())
	stdin := windows.Handle(os.Stdin.Fd())

	oldCP, _ := windows.GetConsoleOutputCP()

	var outMode uint32
	_ = windows.GetConsoleMode(stdout, &outMode)
	_ = windows.SetConsoleMode(stdout, outMode|enableVirtualTerminalProcessing)
	_ = windows.SetConsoleOutputCP(65001)

	var inMode uint32
	hasIn := false
	if err := windows.GetConsoleMode(stdin, &inMode); err == nil {
		hasIn = true
		rawInMode := (inMode &^ (enableLineInput | enableEchoInput)) | enableProcessedInput
		_ = windows.SetConsoleMode(stdin, rawInMode)
	}

	return func() {
		_ = windows.SetConsoleOutputCP(oldCP)
		_ = windows.SetConsoleMode(stdout, outMode)
		if hasIn {
			_ = windows.SetConsoleMode(stdin, inMode)
		}
	}
}

func termSize() (int, int) {

	h, err := windows.CreateFile(
		windows.StringToUTF16Ptr("CONOUT$"),
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		0,
		0,
	)
	if err == nil {
		defer windows.CloseHandle(h)
		var info windows.ConsoleScreenBufferInfo
		if err := windows.GetConsoleScreenBufferInfo(h, &info); err == nil {
			w := int(info.Window.Right - info.Window.Left + 1)
			h := int(info.Window.Bottom - info.Window.Top + 1)
			if w > 0 && h > 0 {
				return w, h
			}
		}
	}

	stdout := windows.Handle(os.Stdout.Fd())
	var info windows.ConsoleScreenBufferInfo
	if err := windows.GetConsoleScreenBufferInfo(stdout, &info); err == nil {
		w := int(info.Window.Right - info.Window.Left + 1)
		h := int(info.Window.Bottom - info.Window.Top + 1)
		if w > 0 && h > 0 {
			return w, h
		}
	}
	return 100, 30
}

func IsTerminal() bool {
	fi, err := os.Stdout.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
