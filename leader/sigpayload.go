package main

import (
	"crypto/sha256"
	"fmt"
	"log"
	"os"
	"strconv"
	"sync"
	"time"
)

func votePayload(view int64, mid int64, phase int, digest string, cfg string) []byte {
	h := sha256.Sum256([]byte("tailor|" + strconv.FormatInt(view, 10) + "|" + strconv.FormatInt(mid, 10) + "|" +
		strconv.Itoa(phase) + "|" + digest + "|" + cfg))
	return h[:]
}

func cfgOf(m *Message) string {
	if m == nil {
		return ""
	}
	out := make([]byte, 0, 3)
	for i := 1; i <= 3; i++ {
		switch m.PhaseConfig[fmt.Sprintf("phase%d", i)] {
		case "RSA":
			out = append(out, 'R')
		case "BLS":
			out = append(out, 'B')
		}
	}
	return string(out)
}

func validConfig(m *Message) bool {
	n := len(cfgOf(m))
	for i := 1; i <= n; i++ {
		if m.PhaseConfig[fmt.Sprintf("phase%d", i)] == "" {
			return false
		}
	}
	if isChainBlock(m) {
		return n == 1
	}
	return n == 2 || n == 3
}

func chainDigest(batchDigest, parent string, parentView int64) string {
	if parent == "" {
		return batchDigest
	}
	h := sha256.Sum256([]byte("tailor-chain|" + batchDigest + "|" + parent + "|" + strconv.FormatInt(parentView, 10)))
	return fmt.Sprintf("%x", h[:])
}

func msgPayload(m *Message, phase int, digest string) []byte {
	return votePayload(m.GetView(), m.MessageId, phase, digest, cfgOf(m))
}

func tupleKey(view int64, digest string, cfg string) string {
	return digest + "|" + strconv.FormatInt(view, 10) + "|" + cfg
}

func msgKey(m *Message, digest string) string {
	return tupleKey(m.GetView(), digest, cfgOf(m))
}

func declaredPattern(m *Message, n int, pattern string) bool {
	return m != nil && m.PhaseConfig[fmt.Sprintf("phase%d", n)] == pattern
}

func phaseCountOf(m *Message) int {
	n := 0
	for i := 1; i <= 3; i++ {
		if m.PhaseConfig[fmt.Sprintf("phase%d", i)] != "" {
			n++
		}
	}
	return n
}

type voteRecord struct {
	view  int64
	tuple string
}

var voteMu sync.Mutex
var voted = map[string]voteRecord{}

func voteGuard(node string, view int64, mid int64, phase int, tuple string) bool {
	if view < viewFloor.Load() {
		return false
	}
	k := node + "|" + strconv.FormatInt(mid, 10) + "/" + strconv.Itoa(phase)
	voteMu.Lock()
	defer voteMu.Unlock()
	if r, ok := voted[k]; ok {
		if view < r.view || (view == r.view && r.tuple != tuple) {
			log.Printf("[%s] voteGuard: mid=%d phase=%d view=%d already voted for another tuple, rejecting", node, mid, phase, view)
			return false
		}
	}
	voted[k] = voteRecord{view: view, tuple: tuple}
	return true
}

func voteForget(node string, mid int64) {
	voteMu.Lock()
	for i := 1; i <= 3; i++ {
		delete(voted, node+"|"+strconv.FormatInt(mid, 10)+"/"+strconv.Itoa(i))
	}
	voteMu.Unlock()
}

var chainTrace = os.Getenv("CHAIN_TRACE") == "1"
var chainT sync.Map

func chainSinceMs(mid int64) int64 {
	if v, ok := chainT.Load(mid); ok {
		return time.Since(v.(time.Time)).Milliseconds()
	}
	return -1
}
