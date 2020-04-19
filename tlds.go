package main

import (
	"strings"
	"sync"
)

var (
	effectiveTLDsNames []string
)

const (
	tldsURL               = `http://data.iana.org/TLD/tlds-alpha-by-domain.txt`
	effectiveTLDsNamesURL = `https://publicsuffix.org/list/effective_tld_names.dat`
)

// TLDs unique tlds container
type TLDs struct {
	sync.Mutex
	tlds map[string]struct{}
}

// NewTLDs returns a TLDs object
func NewTLDs() *TLDs {
	return &TLDs{tlds: make(map[string]struct{})}
}

func (tlds *TLDs) match(domain string) bool {
	dd := strings.Split(domain, ".")
	lastSection := dd[len(dd)-1]
	if _, ok := tlds.tlds[lastSection]; ok {
		return true
	}

	for _, v := range effectiveTLDsNames {
		if strings.HasSuffix(domain, v) {
			return true
		}
	}

	return false
}

func (tlds *TLDs) insert(domain string) {
	tlds.Lock()
	tlds.tlds[domain] = struct{}{}
	tlds.Unlock()
}
