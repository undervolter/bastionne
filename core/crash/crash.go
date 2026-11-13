package crash

import (
	"fmt"
	"os"
	"strings"
	"time"

	"krushitel/core/update"
)

var StopTerminalHook func() *os.File

func truncateRunesCrash(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

const crashWrapW = 150

func wrapRunesCrash(s string, n int) []string {
	r := []rune(strings.TrimRight(s, "\r"))
	var out []string
	for len(r) > n {
		cut := n
		for i := n; i > n/2 && i < len(r); i-- {
			if r[i] == ' ' {
				cut = i
				break
			}
		}
		out = append(out, strings.TrimRight(string(r[:cut]), " "))
		if cut < len(r) && r[cut] == ' ' {
			r = r[cut+1:]
		} else {
			r = r[cut:]
		}
	}
	out = append(out, string(r))
	return out
}

func Splash(reason string, stack string) string {
	title := " stacktrace "
	inner := 0
	var rows []string
	for _, ln := range strings.Split(strings.TrimRight(stack, "\n"), "\n") {
		for _, chunk := range wrapRunesCrash(strings.TrimSpace(ln), crashWrapW) {
			rows = append(rows, chunk)
			if w := len([]rune(chunk)); w > inner {
				inner = w
			}
		}
	}
	if inner < len([]rune(title)) {
		inner = len([]rune(title))
	}
	bar := strings.Repeat("─", inner+2)
	boxW := inner + 4

	info := []string{
		"bastionne crashed :(",
		"reason - " + truncateRunesCrash(reason, 100),
		"version v" + update.FullVersion(),
		"stacktrace in crash.log",
		"dev - t.me/bastionne",
	}
	infoMax := 0
	for _, ln := range info {
		if w := len([]rune(ln)); w > infoMax {
			infoMax = w
		}
	}
	contentW := boxW
	if infoMax > contentW {
		contentW = infoMax
	}

	if termW := TermWidth(); termW > 0 && contentW > termW {
		var flat strings.Builder
		for _, ln := range info {
			flat.WriteString(ln + "\n")
		}
		return flat.String()
	}

	termPad := ""
	if termW := TermWidth(); termW > contentW {
		termPad = strings.Repeat(" ", (termW-contentW)/2)
	}
	center := func(s string, w int) string {
		if w >= contentW {
			return s
		}
		return strings.Repeat(" ", (contentW-w)/2) + s
	}
	var out strings.Builder
	out.WriteString("\x1b[?1049l\x1b[?25h\r\n")
	for _, ln := range info {
		out.WriteString(termPad + center(ln, len([]rune(ln))) + "\n")
	}
	out.WriteString("\n")
	out.WriteString(termPad + center("╭"+bar+"╮", boxW) + "\n")
	out.WriteString(termPad + center("│ "+title+strings.Repeat(" ", inner-len([]rune(title)))+" │", boxW) + "\n")
	for _, ln := range rows {
		out.WriteString(termPad + center("│ "+ln+strings.Repeat(" ", inner-len([]rune(ln)))+" │", boxW) + "\n")
	}
	out.WriteString(termPad + center("╰"+bar+"╯", boxW) + "\n")
	return out.String()
}

func WaitForKey(out *os.File) {
	defer func() { _ = recover() }()
	if out == nil {
		return
	}
	fmt.Fprintln(out, "press any key to exit...")
	waitKey()
}

func Fatal(reason string, stack []byte) {
	Dump(reason, stack)
	term := os.Stdout
	if StopTerminalHook != nil {
		if t := StopTerminalHook(); t != nil {
			term = t
		}
	}
	if reason == "" {
		reason = "unknown (see crash.log)"
	}
	fmt.Fprint(term, Splash(reason, string(stack)))
	if isTTYFile(term) {
		WaitForKey(term)
	}
	os.Exit(1)
}

func Dump(reason string, stack []byte) {
	f, err := os.OpenFile("crash.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "=== PANIC %s ===\n%s\n%s\n",
		time.Now().Format("02.01.2006 15:04:05"), reason, string(stack))
	_ = f.Sync()
}

func isTTYFile(f *os.File) bool {
	if f == nil {
		return false
	}
	st, err := f.Stat()
	if err != nil {
		return false
	}
	return st.Mode()&os.ModeCharDevice != 0
}
