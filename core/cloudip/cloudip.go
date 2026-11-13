package cloudip

import (
	"context"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	Server = "www.easy4ipcloud.com"

	Port = 8800
)

var FallbackIPs = []string{
	"165.154.165.8",
	"165.154.165.15",
	"165.154.165.19",
	"165.154.165.21",
	"165.154.165.27",
	"165.154.165.33",
	"165.154.165.35",
	"165.154.165.37",
	"165.154.165.40",
	"165.154.165.41",
	"165.154.165.42",
	"165.154.165.43",
	"165.154.165.47",
	"165.154.165.48",
	"165.154.165.53",
	"165.154.165.79",
	"165.154.165.110",
	"165.154.165.154",
	"165.154.165.231",
	"165.154.165.252",
	"165.154.198.11",
}

const (
	dnsTimeout   = 3 * time.Second
	cacheTTL     = 10 * time.Minute
	fallbackKeep = time.Hour
)

type pool struct {
	host    string
	port    int
	addrs   []*net.UDPAddr
	expires time.Time
}

var (
	mu      sync.Mutex
	cached  *pool
	rr      atomic.Uint64
	fromDNS atomic.Bool
)

func Addrs(host string, port int) []*net.UDPAddr {
	host = trimPort(host)
	if port <= 0 {
		port = Port
	}

	mu.Lock()
	defer mu.Unlock()

	if cached != nil && cached.host == host && cached.port == port {
		if time.Now().Before(cached.expires) {
			return cached.addrs
		}

		if fromDNS.Load() && time.Now().Before(cached.expires.Add(fallbackKeep)) {
			cached.expires = time.Now().Add(cacheTTL)
			if rehydrateInFlight.CompareAndSwap(false, true) {
				go rehydrate(host, port)
			}
			return cached.addrs
		}
	}

	if addrs := dnsAddrs(host, port); len(addrs) > 0 {
		fromDNS.Store(true)
		cached = &pool{host: host, port: port, addrs: addrs, expires: time.Now().Add(cacheTTL)}
		return addrs
	}

	fallback := staticAddrs(port)
	if !isCloudHost(host) {
		fallback = nil
	}

	fromDNS.Store(len(fallback) == 0)
	cached = &pool{host: host, port: port, addrs: fallback, expires: time.Now().Add(cacheTTL)}
	return cached.addrs
}

func isCloudHost(host string) bool {
	h := strings.ToLower(trimPort(host))
	return h == Server || h == "easy4ipcloud.com"
}

var rehydrateInFlight atomic.Bool

func rehydrate(host string, port int) {
	defer rehydrateInFlight.Store(false)
	if addrs := dnsAddrs(host, port); len(addrs) > 0 {
		mu.Lock()
		cached = &pool{host: host, port: port, addrs: addrs, expires: time.Now().Add(cacheTTL)}
		fromDNS.Store(true)
		mu.Unlock()
	}
}

func Next(host string, port int) *net.UDPAddr {
	addrs := Addrs(host, port)
	if len(addrs) == 0 {
		return nil
	}
	return addrs[int(rr.Add(1))%len(addrs)]
}

func NextN(host string, port int, n int) []*net.UDPAddr {
	addrs := Addrs(host, port)
	if len(addrs) == 0 || n <= 0 {
		return nil
	}
	out := make([]*net.UDPAddr, 0, n)
	base := int(rr.Add(1))
	for i := 0; i < n; i++ {
		out = append(out, addrs[(base+i)%len(addrs)])
	}
	return out
}

func Alive(host string) bool {
	return len(Addrs(host, Port)) > 0
}

func Static() bool {
	mu.Lock()
	defer mu.Unlock()
	if cached == nil || !isCloudHost(cached.host) {
		return false
	}
	return !fromDNS.Load()
}

func IPs(host string) []net.IP {
	addrs := Addrs(host, Port)
	out := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		if a.IP != nil {
			out = append(out, a.IP)
		}
	}
	return out
}

func Reset() {
	mu.Lock()
	cached = nil
	fromDNS.Store(false)
	mu.Unlock()
	rehydrateInFlight.Store(false)
}

var dnsLookup = func(ctx context.Context, host string) ([]net.IP, error) {
	return net.DefaultResolver.LookupIP(ctx, "ip4", host)
}

func SetDNSForTest(fn func(context.Context, string) ([]net.IP, error)) func(context.Context, string) ([]net.IP, error) {
	prev := dnsLookup
	if fn == nil {
		fn = func(ctx context.Context, host string) ([]net.IP, error) {
			return net.DefaultResolver.LookupIP(ctx, "ip4", host)
		}
	}
	dnsLookup = fn
	Reset()
	return prev
}

func dnsAddrs(host string, port int) []*net.UDPAddr {
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return []*net.UDPAddr{{IP: v4, Port: port}}
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), dnsTimeout)
	defer cancel()
	ips, err := dnsLookup(ctx, host)
	if err != nil || len(ips) == 0 {
		return nil
	}
	out := make([]*net.UDPAddr, 0, len(ips))
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			out = append(out, &net.UDPAddr{IP: v4, Port: port})
		}
	}
	return out
}

func staticAddrs(port int) []*net.UDPAddr {
	out := make([]*net.UDPAddr, 0, len(FallbackIPs))
	for _, s := range FallbackIPs {
		if ip := net.ParseIP(s).To4(); ip != nil {
			out = append(out, &net.UDPAddr{IP: ip, Port: port})
		}
	}
	return out
}

func trimPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}
