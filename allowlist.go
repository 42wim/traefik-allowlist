package traefik_allowlist //nolint:stylecheck

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	XFF = "X-Forwarded-For"
)

type Config struct {
	Allow []string `json:"allow,omitempty" toml:"allow,omitempty" yaml:"allow,omitempty"`
}

// CreateConfig creates and initializes the plugin configuration.
func CreateConfig() *Config {
	return &Config{Allow: make([]string, 0)}
}

// AllowList holds the necessary components of a Traefik plugin
type AllowList struct {
	next                 http.Handler
	name                 string
	authorizedIPs        []*net.IP
	authorizedIPsNet     []*net.IPNet
	authorizedIPsDynamic []*net.IP
	allowedhosts         []string
	lastCheck            time.Time
	sync.RWMutex
}

// New instantiates and returns the required components used to handle a HTTP request
func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	u := &AllowList{
		next: next,
		name: name,
	}

	u.parseConfig(config)
	go u.parseDNSthread()

	return u, nil
}

func (u *AllowList) parseDNSthread() {
	var (
		dynips  []*net.IP
		wg      sync.WaitGroup
		syncMap sync.Map
	)

	for idx, entry := range u.allowedhosts {
		wg.Add(1)

		go func(idx int, entry string) {
			defer wg.Done()

			r := &net.Resolver{}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)

			defer cancel()

			addrs, err := r.LookupHost(ctx, entry)
			if err != nil {
				if errors.Is(err, context.DeadlineExceeded) {
					return
				}
			}

			// put the addresses in dynip list
			for idx2, addr := range addrs {
				if ipAddr := net.ParseIP(addr); ipAddr != nil {
					syncMap.Store((idx*100)+idx2, &ipAddr)
				}
			}
		}(idx, entry)
	}

	wg.Wait()

	syncMap.Range(func(_, value any) bool {
		if v, ok := value.(*net.IP); ok {
			dynips = append(dynips, v)
		}

		return true
	})

	// swap our dynamic array
	u.Lock()
	u.authorizedIPsDynamic = dynips
	u.lastCheck = time.Now()
	u.Unlock()
}

// parseConfig parses config on startup
func (u *AllowList) parseConfig(config *Config) {
	for _, entry := range config.Allow {
		// check for subnet
		if strings.Contains(entry, "/") {
			_, ipAddr, err := net.ParseCIDR(entry)
			if err == nil {
				u.authorizedIPsNet = append(u.authorizedIPsNet, ipAddr)
				continue
			}
		}

		// we failed above err != nil so check if it's an ip
		if ipAddr := net.ParseIP(entry); ipAddr != nil {
			u.authorizedIPs = append(u.authorizedIPs, &ipAddr)
			continue
		}

		// no subnet and ip, so now do a DNS lookup
		addrs, err := net.LookupHost(entry)
		if err == nil {
			// if we can actually look this up, add it to the array that will be checked in the background
			u.allowedhosts = append(u.allowedhosts, entry)

			for _, addr := range addrs {
				if ipAddr := net.ParseIP(addr); ipAddr != nil {
					// add it to the dynamic array
					u.authorizedIPsDynamic = append(u.authorizedIPsDynamic, &ipAddr)
					continue
				}
			}
		}
	}

	u.lastCheck = time.Now()
}

func parseIP(addr string) (net.IP, error) {
	addr = strings.ReplaceAll(addr, "[", "")
	addr = strings.ReplaceAll(addr, "]", "")

	userIP := net.ParseIP(addr)
	if userIP == nil {
		return nil, fmt.Errorf("can't parse IP from address %s", addr)
	}

	return userIP, nil
}

func (u *AllowList) allowIP(addr string) (bool, error) {
	if time.Since(u.lastCheck) > time.Second*3 {
		go u.parseDNSthread()
	}

	if addr == "" {
		return false, errors.New("empty IP address")
	}

	ipAddr, err := parseIP(addr)
	if err != nil {
		return false, fmt.Errorf("unable to parse address: %s: %w", addr, err)
	}

	for _, authorizedIP := range u.authorizedIPs {
		if authorizedIP.Equal(ipAddr) {
			return true, nil
		}
	}

	for _, authorizedIP := range u.authorizedIPsDynamic {
		if authorizedIP.Equal(ipAddr) {
			return true, nil
		}
	}

	for _, authorizedNet := range u.authorizedIPsNet {
		if authorizedNet.Contains(ipAddr) {
			return true, nil
		}
	}

	return false, nil
}

// ServeHTTP checks the leftmost ip in the XFF header to see if this ip is allowed
func (u *AllowList) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	header := req.Header.Get(XFF)
	xffs := strings.Split(header, ",")

	if len(xffs) < 1 {
		rw.WriteHeader(http.StatusForbidden)
		return
	}

	ip := strings.TrimSpace(xffs[len(xffs)-1])

	if ok, err := u.allowIP(ip); err == nil && ok {
		u.next.ServeHTTP(rw, req)
	} else {
		rw.WriteHeader(http.StatusForbidden)
	}
}
