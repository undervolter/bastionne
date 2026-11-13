package tui

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Seg struct {
	Text  string
	Style string
}

type LogLine struct {
	Segs []Seg
	Raw  string
	Time time.Time
}

type CountersData struct {
	Primary   int64
	Secondary int64
	Tertiary  int64

	LabelPrimary   string
	LabelSecondary string
	LabelTertiary  string
}

type FeatureTag struct {
	Name    string
	Enabled bool
}

type RunSettings struct {
	CfgPath  string
	OutDir   string
	Tags     []FeatureTag
	GeoAllow []string
	GeoDeny  []string
}

type State struct {
	mu sync.Mutex

	cfgPath     string
	outDir      string
	runSettings RunSettings

	done  int64
	total int64
	speed float64
	eta   string
	hits  string

	counters CountersData

	logs []*LogLine

	paused   int32
	cancelFn func()

	finished bool
	exitCode int

	ctrlCCount int32

	updateLine string
}

func NewState(cfgPath string, cancelFn func()) *State {
	return &State{
		cfgPath:  cfgPath,
		cancelFn: cancelFn,
		logs:     make([]*LogLine, 0, 512),
		eta:      "00:00",
	}
}

func (s *State) SetOutDir(dir string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.outDir = dir
	s.runSettings.OutDir = dir
}

func (s *State) SetRunSettings(rs RunSettings) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.runSettings = rs
	if rs.CfgPath != "" {
		s.cfgPath = rs.CfgPath
	}
	if rs.OutDir != "" {
		s.outDir = rs.OutDir
	}
}

func (s *State) GetRunSettings() RunSettings {
	s.mu.Lock()
	defer s.mu.Unlock()
	rs := s.runSettings
	if rs.CfgPath == "" {
		rs.CfgPath = s.cfgPath
	}
	if rs.OutDir == "" {
		rs.OutDir = s.outDir
	}
	return rs
}

func (s *State) SetUpdateLine(line string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.updateLine = line
}

func (s *State) UpdateLine() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.updateLine
}

func (s *State) UpdateProgress(done, total int64, speed float64, eta, hits string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.done = done
	s.total = total
	s.speed = speed
	if eta != "" {
		s.eta = eta
	}
	s.hits = hits
}

func (s *State) Hits() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits
}

func (s *State) SetCounters(primary, secondary, tertiary int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.counters.Primary = primary
	s.counters.Secondary = secondary
	s.counters.Tertiary = tertiary
}

func (s *State) SetCounterLabels(primary, secondary, tertiary string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.counters.LabelPrimary = primary
	s.counters.LabelSecondary = secondary
	s.counters.LabelTertiary = tertiary
}

func (s *State) Counters() CountersData {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.counters
}

func (s *State) SetFinished(code int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.finished = true
	s.exitCode = code
}

func (s *State) IsFinished() (bool, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.finished, s.exitCode
}

func (s *State) TogglePause() bool {
	for {
		cur := atomic.LoadInt32(&s.paused)
		next := int32(0)
		if cur == 0 {
			next = 1
		}
		if atomic.CompareAndSwapInt32(&s.paused, cur, next) {
			if next == 1 {
				s.AddLog("[!] PAUSED (press Space to resume)")
			} else {
				s.AddLog("[+] RESUMED")
			}
			return next == 1
		}
	}
}

func (s *State) IsPaused() bool {
	return atomic.LoadInt32(&s.paused) == 1
}

func (s *State) Cancel() {
	if s.cancelFn != nil {
		s.cancelFn()
	}
}

func (s *State) AddLog(raw string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	line := &LogLine{
		Raw:  raw,
		Time: time.Now(),
		Segs: parseLogSegs(raw),
	}
	s.logs = append(s.logs, line)
	if len(s.logs) > 1000 {
		s.logs = s.logs[len(s.logs)-1000:]
	}
}

func parseLogSegs(raw string) []Seg {
	rawTrim := strings.TrimSpace(raw)

	switch {
	case strings.HasPrefix(rawTrim, "[!]"):
		return []Seg{
			{Text: "[!] ", Style: pal.bold + pal.fail},
			{Text: strings.TrimPrefix(rawTrim, "[!] "), Style: pal.warn},
		}
	case strings.HasPrefix(rawTrim, "[+]"):
		return []Seg{
			{Text: "[+] ", Style: pal.bold + pal.ok},
			{Text: strings.TrimPrefix(rawTrim, "[+] "), Style: pal.info},
		}
	case strings.HasPrefix(rawTrim, "[SYS]"):
		return []Seg{
			{Text: "[SYS] ", Style: pal.bold + pal.muted},
			{Text: strings.TrimPrefix(rawTrim, "[SYS] "), Style: pal.info},
		}
	case strings.HasPrefix(rawTrim, "Loaded "):
		return []Seg{
			{Text: "Loaded ", Style: pal.dim},
			{Text: strings.TrimPrefix(rawTrim, "Loaded "), Style: pal.info},
		}
	case strings.HasPrefix(rawTrim, "Created "):
		return []Seg{
			{Text: "Created ", Style: pal.dim},
			{Text: strings.TrimPrefix(rawTrim, "Created "), Style: pal.info},
		}
	case strings.Contains(rawTrim, "pwned:") || strings.Contains(rawTrim, "PWNED"):

		return colorizePwned(rawTrim)
	case strings.Contains(rawTrim, "blocked!"):
		return []Seg{{Text: rawTrim, Style: pal.bold + pal.fail}}
	case strings.Contains(rawTrim, "owned") || strings.Contains(rawTrim, "defaced"):
		style := pal.ok
		if strings.Contains(rawTrim, "not owned") || strings.Contains(rawTrim, "not defaced") {
			style = pal.fail
		}
		return []Seg{{Text: rawTrim, Style: style}}
	case strings.Contains(rawTrim, "failed") || strings.Contains(rawTrim, "FAIL"):
		return []Seg{
			{Text: rawTrim, Style: pal.fail},
		}
	default:
		return []Seg{
			{Text: rawTrim, Style: pal.info},
		}
	}
}

func colorizePwned(s string) []Seg {
	parts := strings.Split(s, " ")
	segs := make([]Seg, 0, len(parts)*2)
	for i, p := range parts {
		if i > 0 {
			segs = append(segs, Seg{Text: " ", Style: ""})
		}
		switch {
		case strings.HasPrefix(p, "pwned:"):
			segs = append(segs, Seg{Text: "pwned: ", Style: pal.dim})
			val := strings.TrimPrefix(p, "pwned:")
			if strings.HasPrefix(val, "true") {
				segs = append(segs, Seg{Text: val, Style: pal.ok})
			} else {
				segs = append(segs, Seg{Text: val, Style: pal.fail})
			}
		case strings.HasPrefix(p, "defaced:"):
			segs = append(segs, Seg{Text: "defaced: ", Style: pal.dim})
			val := strings.TrimPrefix(p, "defaced:")
			if strings.HasPrefix(val, "true") {
				segs = append(segs, Seg{Text: val, Style: pal.ok})
			} else {
				segs = append(segs, Seg{Text: val, Style: pal.fail})
			}
		case strings.Contains(p, "PWNED"):
			segs = append(segs, Seg{Text: p, Style: pal.bold + pal.ok})
		case strings.HasPrefix(p, "(") && strings.HasSuffix(p, ")"):
			segs = append(segs, Seg{Text: p, Style: pal.warn})
		default:
			segs = append(segs, Seg{Text: p, Style: pal.info})
		}
	}
	return segs
}

func fmtInt(n int64) string {
	if n < 1000 {
		return fmt.Sprintf("%d", n)
	}
	if n < 1000000 {
		return fmt.Sprintf("%d,%03d", n/1000, n%1000)
	}
	return fmt.Sprintf("%d,%03d,%03d", n/1000000, (n%1000000)/1000, n%1000)
}
