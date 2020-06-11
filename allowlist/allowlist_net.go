package allowlist

// This file contains a variant of the ACL that operates on
// netblocks. It will mimic as much of the code in allowlist.go
// that is needed to support network allowlists.

import (
	"errors"
	"log"
	"net"
	"strings"
	"sync"
)

// A NetACL stores a list of permitted IP networks.
type NetACL interface {
	ACL

	// Add takes an IP network and adds it to the allowlist so
	// that it is now permitted.
	Add(*net.IPNet)

	// Remove takes an IP network and drops it from the allowlist
	// so that it is no longer permitted.
	Remove(*net.IPNet)
}

// BasicNet implements a basic map-backed network allowlist using
// locks for concurrency. It must be initialised with one of the
// constructor functions. This particular implementation is
// unoptimised and will not scale.
type BasicNet struct {
	lock      *sync.Mutex
	allowlist []*net.IPNet
}

// Permitted returns true if the IP has been allowlisted.
func (wl *BasicNet) Permitted(ip net.IP) bool {
	if !validIP(ip) { // see allowlist.go for this function
		return false
	}

	wl.lock.Lock()
	defer wl.lock.Unlock()
	for i := range wl.allowlist {
		if wl.allowlist[i].Contains(ip) {
			return true
		}
	}
	return false
}

// BUG(kyle): overlapping networks aren't detected.

// Add adds a new network to the allowlist. Caveat: overlapping
// networks won't be detected.
func (wl *BasicNet) Add(n *net.IPNet) {
	if n == nil {
		return
	}

	wl.lock.Lock()
	defer wl.lock.Unlock()
	wl.allowlist = append(wl.allowlist, n)
}

// Remove removes a network from the allowlist.
func (wl *BasicNet) Remove(n *net.IPNet) {
	if n == nil {
		return
	}

	index := -1
	wl.lock.Lock()
	defer wl.lock.Unlock()
	for i := range wl.allowlist {
		if wl.allowlist[i].String() == n.String() {
			index = i
			break
		}
	}

	if index == -1 {
		return
	}

	wl.allowlist = append(wl.allowlist[:index], wl.allowlist[index+1:]...)
}

// NewBasicNet constructs a new basic network-based allowlist.
func NewBasicNet() *BasicNet {
	return &BasicNet{
		lock: new(sync.Mutex),
	}
}

// MarshalJSON serialises a network allowlist to a comma-separated
// list of networks.
func (wl *BasicNet) MarshalJSON() ([]byte, error) {
	var ss = make([]string, 0, len(wl.allowlist))
	for i := range wl.allowlist {
		ss = append(ss, wl.allowlist[i].String())
	}

	out := []byte(`"` + strings.Join(ss, ",") + `"`)
	return out, nil
}

// UnmarshalJSON implements the json.Unmarshaler interface for network
// allowlists, taking a comma-separated string of networks.
func (wl *BasicNet) UnmarshalJSON(in []byte) error {
	if in[0] != '"' || in[len(in)-1] != '"' {
		return errors.New("allowlist: invalid allowlist")
	}

	if wl.lock == nil {
		wl.lock = new(sync.Mutex)
	}

	wl.lock.Lock()
	defer wl.lock.Unlock()

	var err error
	netString := strings.TrimSpace(string(in[1 : len(in)-1]))
	nets := strings.Split(netString, ",")
	wl.allowlist = make([]*net.IPNet, len(nets))
	for i := range nets {
		addr := strings.TrimSpace(nets[i])
		if addr == "" {
			continue
		}
		_, wl.allowlist[i], err = net.ParseCIDR(addr)
		if err != nil {
			wl.allowlist = nil
			return err
		}
	}

	return nil
}

// NetStub allows network allowlisting to be added into a system's
// flow without doing anything yet. All operations result in warning
// log messages being printed to stderr. There is no mechanism for
// squelching these messages short of modifying the log package's
// default logger.
type NetStub struct{}

// Permitted always returns true, but prints a warning message alerting
// that allowlisting is stubbed.
func (wl NetStub) Permitted(ip net.IP) bool {
	log.Printf("WARNING: allowlist check for %s but allowlisting is stubbed", ip)
	return true
}

// Add prints a warning message about allowlisting being stubbed.
func (wl NetStub) Add(ip *net.IPNet) {
	log.Printf("WARNING: IP network %s added to allowlist but allowlisting is stubbed", ip)
}

// Remove prints a warning message about allowlisting being stubbed.
func (wl NetStub) Remove(ip *net.IPNet) {
	log.Printf("WARNING: IP network %s removed from allowlist but allowlisting is stubbed", ip)
}

// NewNetStub returns a new stubbed network allowlister.
func NewNetStub() NetStub {
	log.Println("WARNING: allowlisting is being stubbed")
	return NetStub{}
}
