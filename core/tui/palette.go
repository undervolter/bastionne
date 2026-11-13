package tui

import (
	"fmt"
	"math"
	"strings"
	"unicode/utf8"
)

const (
	altOn      = "\x1b[?1049h"
	altOff     = "\x1b[?1049l"
	cursorHide = "\x1b[?25l"
	cursorShow = "\x1b[?25h"
	clearLine  = "\x1b[K"
	clearAll   = "\x1b[2J"
	moveHome   = "\x1b[H"
)

type palette struct {
	plain bool

	reset string
	bold  string
	dim   string

	accent  string
	accent2 string
	ok      string
	fail    string
	warn    string
	info    string
	muted   string
}

var pal = &palette{}

func rgb(r, g, b int) string {
	return fmt.Sprintf("\x1b[38;2;%d;%d;%dm", r, g, b)
}

func initPalette(plain bool) {
	pal = &palette{plain: plain}
	if plain {
		return
	}
	pal.reset = "\x1b[0m"
	pal.bold = "\x1b[1m"
	pal.dim = "\x1b[2m"

	pal.accent = rgb(255, 46, 62)
	pal.accent2 = rgb(255, 128, 56)
	pal.ok = rgb(96, 220, 120)
	pal.fail = rgb(255, 76, 93)
	pal.warn = rgb(255, 198, 84)
	pal.info = rgb(196, 202, 216)
	pal.muted = rgb(122, 128, 142)
}

var logoPlain = []string{
	"          :::::::::",
	"         :+:    :+:",
	"        +:+    +:+",
	"       +#++:++#+",
	"      +#+    +#+",
	"     #+#    #+#",
	"    #########",
}

const bannerTextCol = 26

func sinf(v float64) float64 { return math.Sin(v) }
func absf(v float64) float64 {
	if v < 0 {
		return -v
	}
	return v
}
func modf(a, b float64) float64 {
	for a >= b {
		a -= b
	}
	for a < 0 {
		a += b
	}
	return a
}

func hsv(h, s, v float64) (int, int, int) {
	for h < 0 {
		h += 360
	}
	for h >= 360 {
		h -= 360
	}
	c := v * s
	x := c * (1 - absf(modf(h/60, 2)-1))
	m := v - c
	var r, g, b float64
	switch {
	case h < 60:
		r, g, b = c, x, 0
	case h < 120:
		r, g, b = x, c, 0
	case h < 180:
		r, g, b = 0, c, x
	case h < 240:
		r, g, b = 0, x, c
	case h < 300:
		r, g, b = x, 0, c
	default:
		r, g, b = c, 0, x
	}
	return int((r + m) * 255), int((g + m) * 255), int((b + m) * 255)
}

func renderLogo(phase float64) []string {
	out := make([]string, len(logoPlain))
	rows := float64(len(logoPlain))

	for y, raw := range logoPlain {
		pad := imax(0, bannerTextCol-len(raw))
		if pal.plain {
			out[y] = raw + strings.Repeat(" ", pad)
			continue
		}

		var b strings.Builder
		for x, r := range raw {
			if r == ' ' {
				b.WriteRune(r)
				continue
			}
			hue := 350 + 38*(float64(x)/bannerTextCol) + 5*sinf(phase*0.9)
			val := 0.58 + 0.42*(1-float64(y)/rows)
			val *= 0.93 + 0.07*sinf(phase*1.7+float64(y)*0.6)
			cr, cg, cb := hsv(hue, 0.86, val)
			fmt.Fprintf(&b, "\x1b[38;2;%d;%d;%dm%c", cr, cg, cb, r)
		}
		b.WriteString(strings.Repeat(" ", pad))
		b.WriteString(pal.reset)
		out[y] = b.String()
	}
	return out
}

func clip(s string, max int) string {
	if max <= 0 {
		return ""
	}
	var b strings.Builder
	n := 0
	for i := 0; i < len(s); {
		if s[i] == 0x1b {
			j := i + 1
			if j < len(s) && s[j] == '[' {
				j++
				for j < len(s) && (s[j] < 0x40 || s[j] > 0x7e) {
					j++
				}
				if j < len(s) {
					j++
				}
			}
			b.WriteString(s[i:j])
			i = j
			continue
		}
		if n >= max {
			break
		}
		_, size := utf8.DecodeRuneInString(s[i:])
		b.WriteString(s[i : i+size])
		i += size
		n++
	}
	b.WriteString(pal.reset)
	return b.String()
}

func visibleWidth(s string) int {
	n := 0
	for i := 0; i < len(s); {
		if s[i] == 0x1b {
			j := i + 1
			if j < len(s) && s[j] == '[' {
				j++
				for j < len(s) && (s[j] < 0x40 || s[j] > 0x7e) {
					j++
				}
				if j < len(s) {
					j++
				}
			}
			i = j
			continue
		}
		_, size := utf8.DecodeRuneInString(s[i:])
		i += size
		n++
	}
	return n
}

func imax(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func imin(a, b int) int {
	if a < b {
		return a
	}
	return b
}
