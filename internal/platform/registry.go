package platform

import (
	"fmt"
	"sort"
	"sync"
)

var (
	regMu     sync.RWMutex
	providers = map[ID]Provider{}
)

// Register adds a provider. Called from provider packages' init().
func Register(p Provider) {
	regMu.Lock()
	defer regMu.Unlock()
	if _, dup := providers[p.ID()]; dup {
		panic(fmt.Sprintf("platform %q registered twice", p.ID()))
	}
	providers[p.ID()] = p
}

// Override replaces (or adds) a provider and returns a function restoring
// the previous state. Intended for tests.
func Override(p Provider) (restore func()) {
	regMu.Lock()
	defer regMu.Unlock()
	prev, had := providers[p.ID()]
	providers[p.ID()] = p
	return func() {
		regMu.Lock()
		defer regMu.Unlock()
		if had {
			providers[p.ID()] = prev
		} else {
			delete(providers, p.ID())
		}
	}
}

// Get returns the provider for a platform.
func Get(id ID) (Provider, error) {
	regMu.RLock()
	defer regMu.RUnlock()
	p, ok := providers[id]
	if !ok {
		return nil, fmt.Errorf("platform %q is not available in this build", id)
	}
	return p, nil
}

// Providers returns all registered providers in stable order.
func Providers() []Provider {
	regMu.RLock()
	defer regMu.RUnlock()
	out := make([]Provider, 0, len(providers))
	for _, p := range providers {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return order(out[i].ID()) < order(out[j].ID()) })
	return out
}

func order(id ID) int {
	for i, x := range All {
		if x == id {
			return i
		}
	}
	return len(All)
}

// Supports reports whether provider p can sync resource type rt.
func Supports(p Provider, rt ResourceType) bool {
	for _, x := range p.ResourceTypes() {
		if x == rt {
			return true
		}
	}
	return false
}
