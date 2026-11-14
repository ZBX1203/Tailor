package main

import (
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var protoVal atomic.Value

func currentProtocol() string {
	if v := protoVal.Load(); v != nil {
		return v.(string)
	}
	return protocolConfig
}

func setProtocol(s string) bool {
	s = strings.ToUpper(s)
	if !isValidProtocol(s) {
		return false
	}
	protoVal.Store(s)
	return true
}

type switchStep struct {
	at     time.Duration
	proto  string
	window int
	chain  string
}

var (
	switchSteps  []switchStep
	switchIdx    int
	switchMode   = "seamless"
	switchT0     time.Time
	switchLogMu  sync.Mutex
	switchLastLg string
)

var (
	chainLastPackedMid int64 = -1
	chainFlushMid      int64 = -1
	chainFlushT0       time.Time
	chainFlushBlocks   int
	chainFlushIn       int
)

var (
	switchOrdered = os.Getenv("SWITCH_ORDERED") == "1"
	orderedStage  int
	orderedT0     time.Time
	orderedIn     int
)

func (p *Consensus) chainFlushDone() bool {
	return chainFlushMid < 0 || atomic.LoadInt64(&p.chainLastMid) >= chainFlushMid+chainDepth-1
}

func parseSwitchItem(item string) (switchStep, bool) {
	parts := strings.SplitN(item, "@", 2)
	if len(parts) != 2 {
		return switchStep{}, false
	}
	sec, err := strconv.ParseFloat(parts[1], 64)
	if err != nil || sec < 0 {
		return switchStep{}, false
	}
	st := switchStep{at: time.Duration(sec * float64(time.Second))}
	spec := parts[0]
	if len(spec) > 6 && strings.EqualFold(spec[:6], "chain:") {
		t := strings.ToUpper(spec[6:])
		if strings.Trim(t, "RB") != "" {
			return switchStep{}, false
		}
		st.chain = t
		return st, true
	}
	if k := strings.Index(spec, "/"); k >= 0 {
		w, err := strconv.Atoi(spec[k+1:])
		if err != nil || w < 1 {
			return switchStep{}, false
		}
		st.window = w
		spec = spec[:k]
	}
	if spec != "" {
		if !isValidProtocol(strings.ToUpper(spec)) {
			return switchStep{}, false
		}
		st.proto = strings.ToUpper(spec)
	}
	if st.proto == "" && st.window == 0 {
		return switchStep{}, false
	}
	return st, true
}

func initSwitchSchedule() {
	if m := strings.ToLower(os.Getenv("SWITCH_MODE")); m == "barrier" {
		switchMode = "barrier"
	}
	s := os.Getenv("SWITCH_SCHEDULE")
	if s == "" {
		return
	}
	for _, item := range strings.Split(s, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		step, ok := parseSwitchItem(item)
		if !ok {
			log.Printf("[%s] invalid SWITCH_SCHEDULE entry, ignoring: %q", nodeID, item)
			continue
		}
		switchSteps = append(switchSteps, step)
	}
	if len(switchSteps) > 0 {
		log.Printf("[%s] SWITCH_SCHEDULE loaded %d steps, mode=%s ordered=%v", nodeID, len(switchSteps), switchMode, switchOrdered)
	}
}

func (p *Consensus) maybeSwitch() {
	if switchIdx >= len(switchSteps) {
		return
	}
	if switchT0.IsZero() {
		return
	}
	step := switchSteps[switchIdx]
	if time.Since(switchT0) < step.at {
		return
	}
	from := structLabel()
	fromIn, fromW := p.window.snapshot()
	drainMs := int64(0)
	flushN := -1
	if switchMode == "barrier" && chainOn && step.chain != "" {
		if chainFlushMid < 0 && chainFlushT0.IsZero() {
			chainFlushMid, chainFlushT0, chainFlushBlocks, chainFlushIn = chainLastPackedMid, time.Now(), 0, fromIn
			if switchOrdered {
				chainFlushMid = chainLastPackedMid + 1
			}
		}
		if !p.chainFlushDone() && time.Since(chainFlushT0) < 10*time.Second {
			return
		}
		drainMs, flushN, fromIn = time.Since(chainFlushT0).Milliseconds(), chainFlushBlocks, chainFlushIn
		chainFlushMid, chainFlushT0 = -1, time.Time{}
	} else if switchMode == "barrier" {
		if switchOrdered && orderedStage == 0 {
			orderedT0, orderedIn = time.Now(), fromIn
			for time.Since(orderedT0) < 10*time.Second {
				if in, _ := p.window.snapshot(); in == 0 {
					break
				}
				time.Sleep(2 * time.Millisecond)
			}
			orderedStage = 1
			return
		}
		if switchOrdered && orderedStage == 1 {
			return
		}
		t := time.Now()
		for time.Since(t) < 10*time.Second {
			if in, _ := p.window.snapshot(); in == 0 {
				break
			}
			time.Sleep(2 * time.Millisecond)
		}
		drainMs = time.Since(t).Milliseconds()
		if switchOrdered {
			drainMs, fromIn, orderedStage = time.Since(orderedT0).Milliseconds(), orderedIn, 0
			flushN = 1
		}
	}
	toW := fromW
	switch {
	case step.chain != "" && chainTypes == "":
		log.Printf("[SWITCH] ignoring chain:%s: requires CHAINED_B=1 and a non-empty CHAIN_TYPES on all nodes", step.chain)
	case step.chain != "":
		if !chainOn {
			chainOn, chainSegNew, chainFirst = true, true, true
			if _, w := p.window.snapshot(); w < 2 {
				p.window.setLimit(2)
				log.Printf("[SWITCH] entering chained: window %d → 2 (chained needs at least 2 in-flight slots)", w)
			}
		}
		chainCurTypes = step.chain
	case step.proto != "" && chainOn:
		log.Printf("[SWITCH] ignoring %s: chained → window/sequential not supported yet", step.proto)
	case step.proto != "":
		setProtocol(step.proto)
	}
	to := structLabel()
	if step.window > 0 {
		p.window.setLimit(step.window)
		toW = step.window
	}
	switchIdx++
	log.Printf("[SWITCH] t=%.3fs mode=%s from=%s/%d to=%s/%d drain_ms=%d inflight_at_switch=%d",
		time.Since(switchT0).Seconds(), switchMode, from, fromW, to, toW, drainMs, fromIn)
	if flushN >= 0 && chainOn {
		log.Printf("[SWITCH] chain barrier: flush_blocks=%d", flushN)
	} else if flushN >= 0 {
		log.Printf("[SWITCH] ordered barrier: switch_instance=%d", flushN)
	}
}

func structLabel() string {
	if !chainOn {
		return currentProtocol()
	}
	if chainCurTypes != "" {
		return "chain:" + chainCurTypes
	}
	return "chain:" + chainTypes
}

func logFirstBatchUnder(proto string, mid uint64) {
	switchLogMu.Lock()
	defer switchLogMu.Unlock()
	if switchT0.IsZero() {
		switchT0 = time.Now()
	}
	if proto != switchLastLg {
		if switchLastLg != "" {
			log.Printf("[SWITCH] first batch mid=%d under %s", mid, proto)
		}
		switchLastLg = proto
	}
}
