// Package allowlist implements IP allowlisting for various types
// of connections. Two types of access control lists (ACLs) are
// supported: host-based and network-based.
package allowlist

import (
	"errors"
	"log"
	"net"
	"sort"
	"strings"
	"sync"
)

// An ACL stores a list of permitted IP addresses, and handles
// concurrency as needed.
type ACL interface {
	// Permitted takes an IP address, and returns true if the
	// IP address is allowlisted (e.g. permitted access).
	Permitted(net.IP) bool
}

// A HostACL stores a list of permitted hosts.
type HostACL interface {
	ACL

	// Add takes an IP address and adds it to the allowlist so
	// that it is now permitted.
	Add(net.IP)

	// Remove takes an IP address and drops it from the allowlist
	// so that it is no longer permitted.
	Remove(net.IP)
}

// validIP takes an IP address (which is implemented as a byte slice)
// and ensures that it is a possible address. Right now, this means
// just doing length checks.
func validIP(ip net.IP) bool {
	if len(ip) == 4 {
		return true
	}

	if len(ip) == 16 {
		return true
	}

	return false
}

// Basic implements a basic map-backed allowlister that uses an
// RWMutex for conccurency. IPv4 addresses are treated differently
// than an IPv6 address; namely, the IPv4 localhost will not match
// the IPv6 localhost.
type Basic struct {
	lock      *sync.Mutex
	allowlist map[string]bool
}

// Permitted returns true if the IP has been allowlisted.
func (wl *Basic) Permitted(ip net.IP) bool {
	if !validIP(ip) {
		return false
	}

	wl.lock.Lock()
	permitted := wl.allowlist[ip.String()]
	wl.lock.Unlock()
	return permitted
}

// Add allowlists an IP.
func (wl *Basic) Add(ip net.IP) {
	if !validIP(ip) {
		return
	}

	wl.lock.Lock()
	defer wl.lock.Unlock()
	wl.allowlist[ip.String()] = true
}

// Remove clears the IP from the allowlist.
func (wl *Basic) Remove(ip net.IP) {
	if !validIP(ip) {
		return
	}

	wl.lock.Lock()
	defer wl.lock.Unlock()
	delete(wl.allowlist, ip.String())
}

// NewBasic returns a new initialised basic allowlist.
func NewBasic() *Basic {
	return &Basic{
		lock:      new(sync.Mutex),
		allowlist: map[string]bool{},
	}
}

// MarshalJSON serialises a host allowlist to a comma-separated list of
// hosts, implementing the json.Marshaler interface.
func (wl *Basic) MarshalJSON() ([]byte, error) {
	wl.lock.Lock()
	defer wl.lock.Unlock()
	var ss = make([]string, 0, len(wl.allowlist))
	for ip := range wl.allowlist {
		ss = append(ss, ip)
	}

	out := []byte(`"` + strings.Join(ss, ",") + `"`)
	return out, nil
}

// UnmarshalJSON implements the json.Unmarshaler interface for host
// allowlists, taking a comma-separated string of hosts.
func (wl *Basic) UnmarshalJSON(in []byte) error {
	if in[0] != '"' || in[len(in)-1] != '"' {
		return errors.New("allowlist: invalid allowlist")
	}

	if wl.lock == nil {
		wl.lock = new(sync.Mutex)
	}

	wl.lock.Lock()
	defer wl.lock.Unlock()

	netString := strings.TrimSpace(string(in[1 : len(in)-1]))
	nets := strings.Split(netString, ",")

	wl.allowlist = map[string]bool{}
	for i := range nets {
		addr := strings.TrimSpace(nets[i])
		if addr == "" {
			continue
		}

		ip := net.ParseIP(addr)
		if ip == nil {
			wl.allowlist = nil
			return errors.New("allowlist: invalid IP address " + addr)
		}
		wl.allowlist[addr] = true
	}

	return nil
}

// DumpBasic returns a allowlist as a byte slice where each IP is on
// its own line.
func DumpBasic(wl *Basic) []byte {
	wl.lock.Lock()
	defer wl.lock.Unlock()

	var addrs = make([]string, 0, len(wl.allowlist))
	for ip := range wl.allowlist {
		addrs = append(addrs, ip)
	}

	sort.Strings(addrs)

	addrList := strings.Join(addrs, "\n")
	return []byte(addrList)
}

// LoadBasic loads a allowlist from a byteslice.
func LoadBasic(in []byte) (*Basic, error) {
	wl := NewBasic()
	addrs := strings.Split(string(in), "\n")

	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			return nil, errors.New("allowlist: invalid address")
		}
		wl.Add(ip)
	}
	return wl, nil
}

// HostStub allows host allowlisting to be added into a system's flow
// without doing anything yet. All operations result in warning log
// messages being printed to stderr. There is no mechanism for
// squelching these messages short of modifying the log package's
// default logger.
type HostStub struct{}

// Permitted always returns true, but prints a warning message alerting
// that allowlisting is stubbed.
func (wl HostStub) Permitted(ip net.IP) bool {
	log.Printf("WARNING: allowlist check for %s but allowlisting is stubbed", ip)
	return true
}

// Add prints a warning message about allowlisting being stubbed.
func (wl HostStub) Add(ip net.IP) {
	log.Printf("WARNING: IP %s added to allowlist but allowlisting is stubbed", ip)
}

// Remove prints a warning message about allowlisting being stubbed.
func (wl HostStub) Remove(ip net.IP) {
	log.Printf("WARNING: IP %s removed from allowlist but allowlisting is stubbed", ip)
}

// NewHostStub returns a new stubbed host allowlister.
func NewHostStub() HostStub {
	log.Println("WARNING: allowlisting is being stubbed")
	return HostStub{}
}
