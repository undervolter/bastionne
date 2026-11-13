package geo

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/oschwald/geoip2-golang"
)

const cacheLimit = 1 << 16

type ipRange struct {
	start uint32
	end   uint32
	cc    string
}

type Filter struct {
	db          *geoip2.Reader
	ranges      []ipRange
	allow       map[string]struct{}
	deny        map[string]struct{}
	denyUnknown bool

	mu    sync.RWMutex
	cache map[string]string
}

func Open(path string, allow, deny []string, denyUnknown bool) (*Filter, error) {
	f := &Filter{
		allow:       normSet(allow),
		deny:        normSet(deny),
		denyUnknown: denyUnknown,
		cache:       make(map[string]string),
	}
	if strings.TrimSpace(path) == "" {
		return f, nil
	}
	if strings.HasSuffix(strings.ToLower(path), ".mmdb") {
		db, err := geoip2.Open(path)
		if err != nil {
			return nil, fmt.Errorf("geo: открыть %s: %w", path, err)
		}
		f.db = db
		return f, nil
	}
	if err := f.loadRanges(path); err != nil {
		return nil, err
	}
	return f, nil
}

func (f *Filter) Close() error {
	if f == nil || f.db == nil {
		return nil
	}
	return f.db.Close()
}

func (f *Filter) Enabled() bool {
	return f != nil && (f.db != nil || len(f.ranges) > 0)
}

func (f *Filter) Country(ip net.IP) string {
	if f == nil {
		return ""
	}
	v4 := ip.To4()
	if v4 == nil {
		return ""
	}
	key := v4.String()
	f.mu.RLock()
	cc, ok := f.cache[key]
	f.mu.RUnlock()
	if ok {
		return cc
	}
	cc = f.lookup(v4)
	f.mu.Lock()
	if len(f.cache) >= cacheLimit {
		f.cache = make(map[string]string)
	}
	f.cache[key] = cc
	f.mu.Unlock()
	return cc
}

func (f *Filter) lookup(v4 net.IP) string {
	if f.db != nil {
		rec, err := f.db.Country(v4)
		if err == nil && rec != nil {
			if cc := strings.ToUpper(strings.TrimSpace(rec.Country.IsoCode)); cc != "" {
				return cc
			}
			if cc := strings.ToUpper(strings.TrimSpace(rec.RegisteredCountry.IsoCode)); cc != "" {
				return cc
			}
		}
		return ""
	}
	if len(f.ranges) == 0 {
		return ""
	}
	v := binary.BigEndian.Uint32(v4)
	i := sort.Search(len(f.ranges), func(i int) bool { return f.ranges[i].end >= v })
	if i < len(f.ranges) && f.ranges[i].start <= v {
		return f.ranges[i].cc
	}
	return ""
}

func (f *Filter) Allow(ip net.IP) (bool, string) {
	if f == nil || (len(f.allow) == 0 && len(f.deny) == 0 && !f.denyUnknown) {
		return true, ""
	}
	cc := f.Country(ip)
	if cc == "" {

		if f.denyUnknown || len(f.allow) > 0 {
			return false, ""
		}
		return true, ""
	}
	if len(f.allow) > 0 {
		if _, ok := f.allow[cc]; !ok {
			return false, cc
		}
	}
	if _, ok := f.deny[cc]; ok {
		return false, cc
	}
	return true, cc
}

func (f *Filter) loadRanges(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("geo: открыть %s: %w", path, err)
	}
	defer file.Close()

	sc := bufio.NewScanner(file)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		fields := strings.FieldsFunc(line, func(r rune) bool {
			return r == ',' || r == ';' || r == '\t' || r == ' '
		})
		if len(fields) < 2 {
			continue
		}
		cc := normCC(fields[len(fields)-1])
		if cc == "" {
			continue
		}
		target := fields[0]
		if strings.Contains(target, "-") {
			parts := strings.SplitN(target, "-", 2)
			start := net.ParseIP(strings.TrimSpace(parts[0])).To4()
			end := net.ParseIP(strings.TrimSpace(parts[1])).To4()
			if start == nil || end == nil {
				continue
			}
			f.ranges = append(f.ranges, ipRange{
				start: binary.BigEndian.Uint32(start),
				end:   binary.BigEndian.Uint32(end),
				cc:    cc,
			})
			continue
		}
		_, ipnet, nerr := net.ParseCIDR(target)
		if nerr != nil || ipnet.IP.To4() == nil {
			continue
		}
		start := binary.BigEndian.Uint32(ipnet.IP.To4())
		mask := binary.BigEndian.Uint32(ipnet.Mask)
		f.ranges = append(f.ranges, ipRange{start: start, end: start | ^mask, cc: cc})
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("geo: чтение %s: %w", path, err)
	}
	if len(f.ranges) == 0 {
		return fmt.Errorf("geo: %s не содержит ни одного CIDR,CC", path)
	}
	sort.Slice(f.ranges, func(i, j int) bool { return f.ranges[i].start < f.ranges[j].start })
	return nil
}

func normSet(in []string) map[string]struct{} {
	out := make(map[string]struct{}, len(in))
	for _, s := range in {
		if cc := normCC(s); cc != "" {
			out[cc] = struct{}{}
		}
	}
	return out
}

func normCC(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	if len(s) != 2 {
		return ""
	}
	for _, r := range s {
		if r < 'A' || r > 'Z' {
			return ""
		}
	}
	return s
}
