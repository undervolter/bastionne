//go:build windows

package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32                  = windows.NewLazySystemDLL("kernel32.dll")
	procGetConsoleProcessList = kernel32.NewProc("GetConsoleProcessList")
)

func isLaunchedByExplorer() bool {

	pids := make([]uint32, 2)
	r1, _, _ := procGetConsoleProcessList.Call(uintptr(unsafe.Pointer(&pids[0])), 2)
	count := uint32(r1)
	if count <= 1 {
		return true
	}

	ppid := uint32(os.Getppid())
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(snap)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Process32First(snap, &entry); err != nil {
		return false
	}
	for {
		if entry.ProcessID == ppid {
			name := windows.UTF16ToString(entry.ExeFile[:])
			if strings.EqualFold(name, "explorer.exe") {
				return true
			}
			break
		}
		if err := windows.Process32Next(snap, &entry); err != nil {
			break
		}
	}
	return false
}

func waitExitIfExplorer() {
	if isLaunchedByExplorer() {
		fmt.Print("\nPress Enter to exit...")
		r := bufio.NewReader(os.Stdin)
		_, _ = r.ReadString('\n')
	}
}
