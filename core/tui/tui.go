package tui

import (
	"fmt"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"
)

var Active *State

func IsActive() bool {
	return Active != nil
}

func Counters(primary, secondary, tertiary int64) {
	if Active != nil {
		Active.SetCounters(primary, secondary, tertiary)
	}
}

func ReportOutcome(serial string, pwned, defaced bool, method string) {

	_, _, _, _ = serial, pwned, defaced, method
}

func Log(msg string) {
	if Active != nil {
		Active.AddLog(msg)
	}
}

func Run(s *State, plain bool) int {
	Active = s
	defer func() {
		Active = nil
	}()

	initPalette(plain)
	restoreConsole := enableConsole()
	defer restoreConsole()

	fmt.Print(altOn + cursorHide + "\x1b]0;bastionne\x07")
	defer fmt.Print(cursorShow + altOff)

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	keyCh := make(chan byte, 32)
	go func() {
		buf := make([]byte, 16)
		for {
			n, err := os.Stdin.Read(buf)
			if err != nil {
				return
			}
			for i := 0; i < n; i++ {
				keyCh <- buf[i]
			}
		}
	}()

	renderer := NewRenderer()
	fpsTicker := time.NewTicker(50 * time.Millisecond)
	defer fpsTicker.Stop()

	lastTime := time.Now()

	for {
		select {
		case sig := <-sigCh:
			count := atomic.AddInt32(&s.ctrlCCount, 1)
			if count == 1 {
				s.AddLog("[!] Ctrl+C detected, shutting down cleanly...")
				s.Cancel()
			} else {
				fmt.Print(cursorShow + altOff)
				fmt.Println("\n[!!!] Double ctrl +c, force exit")
				_ = sig
				os.Exit(130)
			}

		case k := <-keyCh:
			switch k {
			case ' ', 'p', 'P':
				s.TogglePause()
			case 0x03:
				count := atomic.AddInt32(&s.ctrlCCount, 1)
				if count == 1 {
					s.AddLog("[!] Ctrl+C detected, shutting down cleanly...")
					s.Cancel()
				} else {
					fmt.Print(cursorShow + altOff)
					fmt.Println("\n[!!!] Double ctrl +c, force exit")
					os.Exit(130)
				}
			case 'q', 'Q':

			}

		case now := <-fpsTicker.C:
			dt := now.Sub(lastTime).Seconds()
			if dt < 0 {
				dt = 0
			}
			if dt > 0.2 {
				dt = 0.2
			}
			lastTime = now

			renderer.Render(s, dt)

			finished, exitCode := s.IsFinished()
			if finished {

				renderer.Render(s, 0.05)
				return exitCode
			}
		}
	}
}
