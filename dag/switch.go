package tusk

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"merge_consensus/dag/certsign"
)

type switchStep struct {
	at    time.Duration
	types string
}

func parseSwitchSchedule(s string) ([]switchStep, error) {
	var plan []switchStep
	for _, item := range strings.Split(s, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		at := strings.LastIndex(item, "@")
		if at <= 0 {
			return nil, fmt.Errorf("DAG_SWITCH_SCHEDULE entry %q should be <type string>@<seconds>", item)
		}
		types := strings.ToUpper(item[:at])
		for i := 0; i < len(types); i++ {
			if types[i] != 'R' && types[i] != 'B' {
				return nil, fmt.Errorf("DAG_SWITCH_SCHEDULE entry %q type string may only contain R/B", item)
			}
		}
		sec, err := strconv.ParseFloat(item[at+1:], 64)
		if err != nil || sec < 0 {
			return nil, fmt.Errorf("DAG_SWITCH_SCHEDULE entry %q has invalid seconds", item)
		}
		plan = append(plan, switchStep{at: time.Duration(sec * float64(time.Second)), types: types})
	}
	sort.SliceStable(plan, func(i, j int) bool { return plan[i].at < plan[j].at })
	return plan, nil
}

func (n *Node) proposeType(round uint64) byte {
	if n.certTypes == "" {
		return 'B'
	}
	types := n.certTypes
	if t0 := n.switchT0.Load(); t0 != 0 && len(n.switchPlan) > 0 {
		elapsed := time.Duration(time.Now().UnixNano() - t0)
		idx := 0
		for _, st := range n.switchPlan {
			if (n.switchByRound && uint64(st.at/time.Second) <= round) || (!n.switchByRound && st.at <= elapsed) {
				types = st.types
				idx++
			}
		}
		n.switchMu.Lock()
		if n.switchCur == "" {
			n.switchCur = n.certTypes
			n.switchDone = idx
		}

		if types != n.switchCur || (n.switchBarrier && idx > n.switchDone) {
			if n.switchBarrier {
				if n.barrierRound.Load() == 0 {
					n.barrierRound.Store(round)
					n.barrierT0 = time.Now()
					fmt.Printf("[SWITCH] barrier start t=%.3fs round=%d from=%s to=%s\n", elapsed.Seconds(), round, n.switchCur, types)
				}
				if n.lastAnchor.Load() < n.barrierRound.Load() {
					old := n.switchCur
					n.switchMu.Unlock()
					return typeForRound(old, round)
				}
				fmt.Printf("[SWITCH] t=%.3fs round=%d from=%s to=%s mode=barrier drain_ms=%d barrier_round=%d\n",
					elapsed.Seconds(), round, n.switchCur, types, time.Since(n.barrierT0).Milliseconds(), n.barrierRound.Load())
				n.barrierRound.Store(0)
			} else {
				fmt.Printf("[SWITCH] t=%.3fs round=%d from=%s to=%s\n", elapsed.Seconds(), round, n.switchCur, types)
			}
			n.switchCur = types
			n.switchDone = idx
		}
		n.switchMu.Unlock()
	}
	return typeForRound(types, round)
}

func typeForRound(types string, round uint64) byte {
	if round == 0 {
		return types[0]
	}
	return types[int((round-1)%uint64(len(types)))]
}

func (n *Node) inBarrier() bool {
	br := n.barrierRound.Load()
	return br != 0 && n.lastAnchor.Load() < br
}

func (n *Node) voteAllToAll(m *ProposeMsg) bool {
	return n.certTypes != "" && m.CertType == 'R'
}

func (n *Node) schemeFor(allToAll bool) certsign.Scheme {
	if n.certTypes == "" {
		return n.certScheme
	}
	if allToAll {
		return n.schemeR
	}
	return n.schemeB
}
