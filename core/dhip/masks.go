package dhip

import (
	"fmt"
	"net"
	"time"
)

// Dahua cover rectangles live in an 8192x8192 coordinate space.
const (
	videoCoordSpace = 8191
	frameBarHeight  = 1024 // 12.5% top and bottom
	colorLow        = 30
	colorHigh       = 70
	colorNeutral    = 50
)

// MaskCover is one VideoWidget Covers entry.
type MaskCover struct {
	Rect         [4]int
	Front        [4]int
	Back         [4]int
	EncodeBlend  bool
	PreviewBlend bool
}

// AntiWhiteResult reports what was repaired on one camera.
type AntiWhiteResult struct {
	Colors int // Brightness/Contrast/Gamma values reset to neutral
	Covers int // white Covers removed
}

// CleanResult is the outcome of one maintenance pass over a camera. Errors
// holds per-operation failures; the session itself either logs in or not.
type CleanResult struct {
	OSDOK    bool
	OSD      int
	Colors   int
	Covers   int
	Unmasked int
	Errors   []string
}

// BlackBars returns the letterbox cover set: opaque bars on top and bottom.
func BlackBars() []MaskCover {
	return []MaskCover{
		{
			Rect:         [4]int{0, 0, videoCoordSpace, frameBarHeight},
			Front:        [4]int{0, 0, 0, 255},
			Back:         [4]int{0, 0, 0, 0},
			EncodeBlend:  true,
			PreviewBlend: true,
		},
		{
			Rect:         [4]int{0, videoCoordSpace - frameBarHeight, videoCoordSpace, videoCoordSpace},
			Front:        [4]int{0, 0, 0, 255},
			Back:         [4]int{0, 0, 0, 0},
			EncodeBlend:  true,
			PreviewBlend: true,
		},
	}
}

// SetMasksDial writes the same Covers set to every channel and returns the
// number of channel entries patched.
func SetMasksDial(dial Dialer, user, pass string, covers []MaskCover) (int, error) {
	if len(covers) == 0 {
		return ClearMasksDial(dial, user, pass)
	}

	patched := 0
	err := withSession(dial, user, pass, func(conn net.Conn, sess int) error {
		n, err := setMasksSession(conn, sess, covers)
		patched = n
		return err
	})
	return patched, err
}

// ClearMasksDial drops every Covers entry. If the firmware refuses an empty
// array, a degenerate 1x1 disabled cover is left in its place.
func ClearMasksDial(dial Dialer, user, pass string) (int, error) {
	patched := 0
	err := withSession(dial, user, pass, func(conn net.Conn, sess int) error {
		n, err := clearMasksSession(conn, sess)
		patched = n
		return err
	})
	return patched, err
}

// AntiWhiteDial restores video colors that were driven out of range and
// removes white covers left by other people's defacement.
func AntiWhiteDial(dial Dialer, user, pass string) (AntiWhiteResult, error) {
	var res AntiWhiteResult
	err := withSession(dial, user, pass, func(conn net.Conn, sess int) error {
		out, err := antiWhiteSession(conn, sess)
		res = out
		return err
	})
	return res, err
}

// CleanDial clears OSD text, repairs colors and/or drops covers in a single
// DHIP session, so a bad run does not burn three logins per camera.
func CleanDial(dial Dialer, user, pass string, antiwhite, unmask bool) (CleanResult, error) {
	var res CleanResult

	err := withSession(dial, user, pass, func(conn net.Conn, sess int) error {
		var osdErr error
		for attempt := 0; attempt < 3; attempt++ {
			if attempt > 0 {
				time.Sleep(2 * time.Second)
			}
			n, err := clearOSDPass(conn, sess)
			if err == nil {
				res.OSDOK = true
				res.OSD = n
				osdErr = nil
				break
			}
			osdErr = err
		}
		if osdErr != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("osd: %v", osdErr))
		}

		if antiwhite {
			aw, aerr := antiWhiteSession(conn, sess)
			if aerr != nil {
				res.Errors = append(res.Errors, fmt.Sprintf("antiwhite: %v", aerr))
			} else {
				res.Colors = aw.Colors
				res.Covers = aw.Covers
			}
		}
		if unmask {
			n, uerr := clearMasksSession(conn, sess)
			if uerr != nil {
				res.Errors = append(res.Errors, fmt.Sprintf("masks: %v", uerr))
			} else {
				res.Unmasked = n
			}
		}
		return nil
	})
	return res, err
}

func withSession(dial Dialer, user, pass string, fn func(net.Conn, int) error) error {
	conn, err := dial()
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()

	sess, err := dhipLoginAs(conn, nil, user, pass)
	if err != nil {
		return fmt.Errorf("login: %w", err)
	}
	return fn(conn, sess)
}

func setMasksSession(conn net.Conn, sess int, covers []MaskCover) (int, error) {
	table, err := configGetTable(conn, sess, 60, "VideoWidget")
	if err != nil {
		return 0, err
	}
	val := coversToAny(covers)
	patched := eachWidgetEntry(table, func(m map[string]any) {
		m["Covers"] = val
	})
	if patched == 0 {
		return 0, fmt.Errorf("VideoWidget: no channels")
	}
	return patched, setVideoWidget(conn, sess, table)
}

func clearMasksSession(conn net.Conn, sess int) (int, error) {
	table, err := configGetTable(conn, sess, 62, "VideoWidget")
	if err != nil {
		return 0, err
	}
	patched := eachWidgetEntry(table, func(m map[string]any) {
		m["Covers"] = []any{}
	})
	if patched == 0 {
		return 0, fmt.Errorf("VideoWidget: no channels")
	}
	stub := coversToAny([]MaskCover{{
		Rect:         [4]int{0, 0, 1, 1},
		Front:        [4]int{0, 0, 0, 0},
		Back:         [4]int{0, 0, 0, 0},
		EncodeBlend:  false,
		PreviewBlend: false,
	}})

	if err := setVideoWidget(conn, sess, table); err != nil {
		eachWidgetEntry(table, func(m map[string]any) {
			m["Covers"] = stub
		})
		if serr := setVideoWidget(conn, sess, table); serr != nil {
			return 0, err
		}
		return patched, nil
	}

	check, err := configGetTable(conn, sess, 64, "VideoWidget")
	if err != nil {
		return patched, nil
	}
	left := 0
	eachWidgetEntry(check, func(m map[string]any) {
		if covs, ok := m["Covers"].([]any); ok {
			left += len(covs)
		}
	})
	if left == 0 {
		return patched, nil
	}

	eachWidgetEntry(table, func(m map[string]any) {
		m["Covers"] = stub
	})
	if err := setVideoWidget(conn, sess, table); err != nil {
		return 0, err
	}
	return patched, nil
}

func antiWhiteSession(conn net.Conn, sess int) (AntiWhiteResult, error) {
	var (
		res      AntiWhiteResult
		firstErr error
	)

	widget, werr := configGetTable(conn, sess, 66, "VideoWidget")
	if werr != nil {
		firstErr = werr
	} else {
		removed := stripWhiteCovers(widget)
		if removed > 0 {
			if serr := setVideoWidget(conn, sess, widget); serr != nil {
				if firstErr == nil {
					firstErr = serr
				}
			} else {
				res.Covers = removed
			}
		}
	}

	colors, cerr := configGetTable(conn, sess, 68, "VideoColor")
	if cerr != nil {
		if firstErr == nil {
			firstErr = cerr
		}
	} else {
		fixed := clampVideoColors(colors)
		if fixed > 0 {
			ok, serr := configSetTable(conn, sess, 69, "VideoColor", colors)
			if serr != nil || !ok {
				if serr == nil {
					serr = fmt.Errorf("setConfig VideoColor: result=false")
				}
				if firstErr == nil {
					firstErr = serr
				}
			} else {
				res.Colors = fixed
			}
		}
	}

	if res.Covers == 0 && res.Colors == 0 && firstErr != nil {
		return res, firstErr
	}
	return res, nil
}

func setVideoWidget(conn net.Conn, sess int, table []any) error {
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			time.Sleep(1500 * time.Millisecond)
		}
		ok, err := configSetTable(conn, sess, 70+attempt, "VideoWidget", table)
		if err == nil && ok {
			return nil
		}
		if err != nil {
			lastErr = err
		} else {
			lastErr = fmt.Errorf("setConfig VideoWidget: result=false")
		}
	}
	return lastErr
}

// eachWidgetEntry walks the flat and nested shapes a config table can take.
func eachWidgetEntry(table []any, fn func(map[string]any)) int {
	n := 0
	for _, raw := range table {
		switch x := raw.(type) {
		case map[string]any:
			fn(x)
			n++
		case []any:
			for _, item := range x {
				if m, ok := item.(map[string]any); ok {
					fn(m)
					n++
				}
			}
		}
	}
	return n
}

func stripWhiteCovers(table []any) int {
	removed := 0
	eachWidgetEntry(table, func(m map[string]any) {
		covs, ok := m["Covers"].([]any)
		if !ok {
			return
		}
		kept := make([]any, 0, len(covs))
		for _, raw := range covs {
			cm, ok := raw.(map[string]any)
			if ok && coverIsWhite(cm) {
				removed++
				continue
			}
			kept = append(kept, raw)
		}
		m["Covers"] = kept
	})
	return removed
}

func coverIsWhite(m map[string]any) bool {
	r, g, b, ok := colorRGB(m["FrontColor"])
	if !ok {
		return false
	}
	return r >= 200 && g >= 200 && b >= 200
}

func clampVideoColors(table []any) int {
	fixed := 0
	eachWidgetEntry(table, func(m map[string]any) {
		for _, key := range []string{"Brightness", "Contrast", "Gamma"} {
			val, ok := toFloat(m[key])
			if !ok {
				continue
			}
			if val < colorLow || val > colorHigh {
				m[key] = colorNeutral
				fixed++
			}
		}
	})
	return fixed
}

func colorRGB(v any) (r, g, b int, ok bool) {
	var vals []float64
	switch x := v.(type) {
	case []any:
		for _, item := range x {
			f, ok := toFloat(item)
			if !ok {
				return 0, 0, 0, false
			}
			vals = append(vals, f)
		}
	case []int:
		for _, n := range x {
			vals = append(vals, float64(n))
		}
	case []float64:
		vals = x
	default:
		return 0, 0, 0, false
	}
	if len(vals) < 3 {
		return 0, 0, 0, false
	}
	return int(vals[0]), int(vals[1]), int(vals[2]), true
}

func coversToAny(covers []MaskCover) []any {
	out := make([]any, 0, len(covers))
	for _, c := range covers {
		out = append(out, map[string]any{
			"Rect":         []any{c.Rect[0], c.Rect[1], c.Rect[2], c.Rect[3]},
			"FrontColor":   []any{c.Front[0], c.Front[1], c.Front[2], c.Front[3]},
			"BackColor":    []any{c.Back[0], c.Back[1], c.Back[2], c.Back[3]},
			"EncodeBlend":  c.EncodeBlend,
			"PreviewBlend": c.PreviewBlend,
		})
	}
	return out
}
