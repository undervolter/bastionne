package tui

import (
	"fmt"
	"os"
	"strings"
	"time"

	"krushitel/core/update"
)

type Renderer struct {
	prev         []string
	phase        float64
	w, h         int
	lastW, lastH int
}

func NewRenderer() *Renderer {
	return &Renderer{}
}

func center(s string, w int) string {
	vw := visibleWidth(s)
	if vw >= w {
		return s
	}
	pad := (w - vw) / 2
	return strings.Repeat(" ", pad) + s
}

func (r *Renderer) Render(s *State, dt float64) {
	w, h := termSize()
	if w < 30 {
		w = 30
	}
	if h < 8 {
		h = 8
	}

	if w != r.lastW || h != r.lastH {
		r.lastW = w
		r.lastH = h
		r.prev = nil
	}

	r.w, r.h = w, h
	r.phase += dt

	frame := make([]string, h)
	row := 1

	if h >= 20 && w >= 60 {
		for _, line := range r.headerBlock(s, w) {
			if row >= h-5 {
				break
			}
			frame[row] = line
			row++
		}
		row++
	}

	if row < h-3 {
		frame[row] = clip(center(r.statusLine(s, w-1), w-1), w-1)
		row++
		row++
	}

	logTop := row
	logBottom := h - 1
	if logTop < logBottom {
		n := logBottom - logTop
		s.mu.Lock()
		numLogs := len(s.logs)
		startIdx := 0
		if numLogs > n {
			startIdx = numLogs - n
		}
		visible := make([]*LogLine, numLogs-startIdx)
		copy(visible, s.logs[startIdx:])
		s.mu.Unlock()

		for i, ln := range visible {
			currRow := logTop + i
			if currRow >= logBottom {
				break
			}
			isLast := (i == len(visible)-1)
			frame[currRow] = " " + r.renderLogLine(ln, w-4, isLast)
		}
	}

	frame[h-1] = clip(r.progressLine(s, w-1), w-1)

	r.blit(frame)
}

func (r *Renderer) blit(frame []string) {
	var b strings.Builder

	if len(r.prev) != len(frame) {
		r.prev = make([]string, len(frame))
		for i := range r.prev {
			r.prev[i] = "\x00"
		}
		b.WriteString(clearAll + moveHome)
	}

	for i, s := range frame {
		if r.prev[i] == s {
			continue
		}
		r.prev[i] = s
		fmt.Fprintf(&b, "\x1b[%d;1H", i+1)
		b.WriteString(s)
		b.WriteString(clearLine)
	}

	if b.Len() == 0 {
		return
	}
	os.Stdout.WriteString(b.String())
}

func formatCountryList(cc []string, maxShow int) string {
	if len(cc) == 0 {
		return "none"
	}
	if len(cc) <= maxShow {
		return strings.Join(cc, ", ")
	}
	shown := strings.Join(cc[:maxShow], ", ")
	remaining := len(cc) - maxShow
	return fmt.Sprintf("%s, and %d others", shown, remaining)
}

func shortenPath(p string, maxLen int) string {
	p = strings.ReplaceAll(p, "\\", "/")
	if len(p) <= maxLen {
		return p
	}
	if maxLen < 15 {
		return p
	}
	keep := maxLen - 4
	return ".../" + strings.TrimLeft(p[len(p)-keep:], "/")
}

func (r *Renderer) headerBlock(s *State, w int) []string {
	logo := renderLogo(r.phase)
	ver := update.FullVersion()
	if ver == "" {
		ver = "0.1"
	}

	rs := s.GetRunSettings()

	mid := map[int]string{
		2: "  " + pal.bold + pal.accent2 + "bastionne" + pal.reset + pal.dim + "  v" + ver + pal.reset,
		3: "  " + pal.dim + "made by " + pal.reset + pal.info + "undervolter" + pal.reset,
		4: "  " + pal.dim + "t.me/" + pal.muted + "bastionne" + pal.reset,
	}

	updateStr := s.UpdateLine()

	leftColW := 56
	if w >= 115 {
		leftColW = 58
	}

	renderTwoCol := (w >= 85)

	var rightLines map[int]string
	if renderTwoCol {
		rightLines = make(map[int]string)

		cfgDisplay := rs.CfgPath
		if cfgDisplay == "" {
			cfgDisplay = "config.toml"
		}
		maxPathW := w - leftColW - 28
		if maxPathW < 20 {
			maxPathW = 20
		}
		cfgDisplay = shortenPath(cfgDisplay, maxPathW)
		rightLines[2] = pal.dim + "Using " + pal.reset + pal.info + "config.toml" + pal.reset +
			pal.dim + " at " + pal.reset + pal.muted + cfgDisplay + pal.reset

		if len(rs.Tags) > 0 {
			var tagStrs []string
			for _, t := range rs.Tags {
				color := pal.fail
				if t.Enabled {
					color = pal.ok
				}
				tagStrs = append(tagStrs, color+t.Name+pal.reset)
			}
			rightLines[3] = pal.dim + "settings: " + pal.reset + strings.Join(tagStrs, " ")
		}

		if len(rs.GeoAllow) > 0 {
			rightLines[4] = pal.dim + "geofencing: " + pal.reset + pal.info + formatCountryList(rs.GeoAllow, 8) + pal.reset
		} else {
			rightLines[4] = pal.dim + "geofencing: " + pal.reset + pal.muted + "none (all countries)" + pal.reset
		}

		if len(rs.GeoDeny) > 0 {
			rightLines[5] = pal.dim + "excluded: " + pal.reset + pal.warn + formatCountryList(rs.GeoDeny, 8) + pal.reset
		} else {
			rightLines[5] = pal.dim + "excluded: " + pal.reset + pal.muted + "none" + pal.reset
		}

		outDir := rs.OutDir
		if outDir == "" {
			outDir = "results"
		}
		rightLines[6] = pal.dim + "storing results at " + pal.reset + pal.accent2 + outDir + pal.reset
	}

	divider := "  " + pal.dim + "|" + pal.reset + "  "

	out := make([]string, len(logo))
	for i := range logo {
		left := logo[i]
		if m, ok := mid[i]; ok {
			left += m
		}

		if !renderTwoCol {
			out[i] = left
			continue
		}

		vw := visibleWidth(left)
		if vw < leftColW {
			left += strings.Repeat(" ", leftColW-vw)
		}

		if rText, ok := rightLines[i]; ok {
			out[i] = clip(left+divider+rText, w-1)
		} else if i >= 2 && i <= 6 {
			out[i] = clip(left+divider, w-1)
		} else {
			out[i] = clip(left, w-1)
		}
	}

	maxW := 0
	for _, ln := range out {
		if vw := visibleWidth(ln); vw > maxW {
			maxW = vw
		}
	}
	if w > maxW {
		pad := (w - maxW) / 2
		prefix := strings.Repeat(" ", pad)
		for i := range out {
			out[i] = prefix + out[i]
		}
	}

	if updateStr != "" {
		out = append(out, "", clip(center(pal.bold+pal.info+updateStr+pal.reset, w-1), w-1))
	}
	return out
}

func (r *Renderer) statusLine(s *State, w int) string {
	cnt := s.Counters()
	sep := " " + pal.dim + "|" + pal.reset + " "

	kv := func(label, val, color string) string {
		return pal.dim + label + pal.reset + " " + color + val + pal.reset
	}

	pausedPrefix := ""
	if s.IsPaused() {
		pausedPrefix = pal.bold + pal.warn + "[PAUSED] " + pal.reset
	}

	l1, l2, l3 := cnt.LabelPrimary, cnt.LabelSecondary, cnt.LabelTertiary
	if l1 == "" {
		l1 = "bastionned:"
	}
	if l2 == "" {
		l2 = "offline:"
	}
	if l3 == "" {
		l3 = "online:"
	}

	head := pausedPrefix +
		kv(l1, fmtInt(cnt.Primary), pal.accent2) + sep +
		kv(l2, fmtInt(cnt.Secondary), pal.muted) + sep +
		kv(l3, fmtInt(cnt.Tertiary), pal.ok) + sep

	return head
}

func (r *Renderer) progressLine(s *State, w int) string {
	s.mu.Lock()
	done := s.done
	total := s.total
	speed := s.speed
	eta := s.eta
	isPaused := (s.paused == 1)
	s.mu.Unlock()

	pct := 0.0
	if total > 0 {
		pct = float64(done) / float64(total) * 100
	}
	if pct > 100 {
		pct = 100
	}

	pausedTag := ""
	if isPaused {
		pausedTag = " " + pal.bold + pal.warn + "[PAUSED]" + pal.reset
	}

	prefix := " " + pal.bold + fmt.Sprintf("%d%%", int(pct)) + pal.reset + " " + pal.dim + "| [" + pal.reset
	suffix := pal.dim + "] | " + pal.reset + fmt.Sprintf("%d p/s", int(speed)) + " " + pal.dim + "| " + pal.reset + pal.muted + eta + pal.reset + pausedTag

	fixedW := visibleWidth(prefix) + visibleWidth(suffix)
	barW := (w - 2) - fixedW
	if barW < 4 {
		barW = 4
	}

	filled := int(pct / 100 * float64(barW))
	if filled > barW {
		filled = barW
	}

	var bar strings.Builder
	for i := 0; i < barW; i++ {
		switch {
		case i == filled-1 && filled > 0 && filled < barW:
			if pal.plain {
				bar.WriteByte('>')
			} else {
				bar.WriteString(pal.bold + pal.accent2 + ">" + pal.reset)
			}
		case i < filled:
			if pal.plain {
				bar.WriteByte('=')
			} else {
				hue := 14 + 26*(float64(i)/float64(barW))
				val := 0.70 + 0.30*(float64(i)/float64(barW))
				cr, cg, cb := hsv(hue, 0.92, val)
				fmt.Fprintf(&bar, "\x1b[38;2;%d;%d;%dm=", cr, cg, cb)
				bar.WriteString(pal.reset)
			}
		default:
			bar.WriteByte(' ')
		}
	}

	return prefix + bar.String() + suffix
}

func (r *Renderer) renderLogLine(l *LogLine, max int, cursor bool) string {
	var b strings.Builder
	left := max

	for _, seg := range l.Segs {
		if left <= 0 {
			break
		}
		rs := []rune(seg.Text)
		if len(rs) <= left {
			b.WriteString(seg.Style)
			b.WriteString(seg.Text)
			b.WriteString(pal.reset)
			left -= len(rs)
		} else {
			b.WriteString(seg.Style)
			b.WriteString(string(rs[:left]))
			b.WriteString(pal.reset)
			left = 0
		}
	}

	if cursor {
		blinkOn := (time.Now().UnixMilli()/450)%2 == 0
		if blinkOn {
			b.WriteString(pal.accent2 + "▊" + pal.reset)
		}
	}
	return b.String()
}
