package main

import (
	"crypto/sha256"
	"encoding/hex"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	pb "merge_consensus/merge_proto"

	"google.golang.org/protobuf/proto"
)

var curView atomic.Int64
var viewFloor atomic.Int64

var nodeOrderOnce sync.Once
var nodeOrderCache []string

func nodeOrder() []string {
	nodeOrderOnce.Do(func() {
		for id := range NodeTable {
			if strings.HasPrefix(id, "N") {
				nodeOrderCache = append(nodeOrderCache, id)
			}
		}
		sort.Slice(nodeOrderCache, func(i, j int) bool {
			a, _ := strconv.Atoi(nodeOrderCache[i][1:])
			b, _ := strconv.Atoi(nodeOrderCache[j][1:])
			return a < b
		})
	})
	return nodeOrderCache
}

func leaderOf(v int64) string {
	ns := nodeOrder()
	if len(ns) == 0 {
		return "N0"
	}
	return ns[int(v%int64(len(ns)))]
}

func (p *Consensus) isViewLeader() bool { return p.node.nodeID == leaderOf(curView.Load()) }

func senderIsLeader(r *Message) bool { return r != nil && r.NodeId == leaderOf(r.GetView()) }

func (p *Consensus) VerifyQC(q *pb.QCProof) bool {
	if q == nil || q.Phase < 1 || int(q.Phase) > len(q.Cfg) || q.Digest == "" {
		return false
	}
	payload := votePayload(q.View, q.Mid, int(q.Phase), q.Digest, q.Cfg)
	switch q.Cfg[q.Phase-1] {
	case 'R':
		if q.BlsAggregation != nil && len(q.BlsAggregation.AggregatedSig) > 0 {
			return false
		}
		valid := map[string]bool{}
		for _, s := range q.RsaSignatures {
			if s == nil || valid[s.NodeId] {
				continue
			}
			if _, known := NodeTable[s.NodeId]; !known {
				continue
			}
			if p.RsaVerifyCached(payload, s.Signature, s.NodeId) {
				valid[s.NodeId] = true
			}
		}
		return len(valid) >= Threshold
	case 'B':
		if len(q.RsaSignatures) > 0 || q.BlsAggregation == nil || len(q.BlsAggregation.Participants) < Threshold {
			return false
		}
		return VerifyWithPreAggregatedKey(q.BlsAggregation.Participants, payload, q.BlsAggregation.AggregatedSig)
	}
	return false
}

func qcOf(r *Message, phase int, digest string) *pb.QCProof {
	return &pb.QCProof{View: r.GetView(), Mid: r.MessageId, Phase: int32(phase), Digest: digest, Cfg: cfgOf(r)}
}

func qcFromRsa(r *Message, phase int, digest string, sigs []*pb.SigEntry) *pb.QCProof {
	q := qcOf(r, phase, digest)
	q.RsaSignatures = sigs
	return q
}

func qcFromBls(r *Message, phase int, digest string, agg *pb.BLSAggregation) *pb.QCProof {
	q := qcOf(r, phase, digest)
	q.BlsAggregation = &pb.BLSAggregation{AggregatedSig: agg.AggregatedSig, Participants: append([]string(nil), agg.Participants...)}
	return q
}

type vcInstance struct {
	prop *Message
	qc   map[int32]*pb.QCProof
}

type bufferedMsg struct {
	cmd     string
	content []byte
}

type viewState struct {
	mu            sync.Mutex
	inst          map[int64]*vcInstance
	chainQC       map[int64]*pb.QCProof
	delivered     map[int64]bool
	committedUpto int64
	maxMid        int64
	changing      atomic.Bool
	vcStart       time.Time
	attempt       int
	lastProgress  atomic.Int64
	reports       map[int64]map[string]*pb.ViewChange
	newViewSent   map[int64]bool
	buffered      []bufferedMsg
	allowed       map[int64]string
	refuse        map[int64]bool
	reproposeMax  int64
}

func newViewState() *viewState {
	vs := &viewState{
		inst:          map[int64]*vcInstance{},
		chainQC:       map[int64]*pb.QCProof{},
		delivered:     map[int64]bool{},
		committedUpto: -1,
		maxMid:        -1,
		reports:       map[int64]map[string]*pb.ViewChange{},
		newViewSent:   map[int64]bool{},
		allowed:       map[int64]string{},
		refuse:        map[int64]bool{},
		reproposeMax:  -1,
	}
	vs.lastProgress.Store(time.Now().UnixNano())
	return vs
}

const vcRetain = 4096

var vcTimeout = func() time.Duration {
	if v, err := strconv.Atoi(os.Getenv("VC_TIMEOUT_MS")); err == nil && v >= 0 {
		return time.Duration(v) * time.Millisecond
	}
	return 3 * time.Second
}()

func (p *Consensus) vcProgress() { p.vc.lastProgress.Store(time.Now().UnixNano()) }

func (p *Consensus) vcRecordProposal(r *Message) {
	if p.vc == nil || r == nil || isChainBlock(r) {
		return
	}
	c := proto.Clone(r).(*Message)
	c.Proof = nil
	c.BatchInfo.Requests = nil
	p.vc.mu.Lock()
	in := p.vc.inst[r.MessageId]
	if in == nil {
		in = &vcInstance{qc: map[int32]*pb.QCProof{}}
		p.vc.inst[r.MessageId] = in
	}
	if in.prop == nil || in.prop.GetView() <= c.GetView() {
		in.prop = c
	}
	if r.MessageId > p.vc.maxMid {
		p.vc.maxMid = r.MessageId
	}
	p.vc.mu.Unlock()
	p.vcProgress()
}

func (p *Consensus) vcRecordQC(q *pb.QCProof) {
	if p.vc == nil || q == nil {
		return
	}
	p.vc.mu.Lock()
	defer p.vc.mu.Unlock()
	if len(q.Cfg) == 1 {
		if old := p.vc.chainQC[q.Mid]; old == nil || old.View < q.View {
			p.vc.chainQC[q.Mid] = q
		}
		return
	}
	in := p.vc.inst[q.Mid]
	if in == nil {
		in = &vcInstance{qc: map[int32]*pb.QCProof{}}
		p.vc.inst[q.Mid] = in
	}
	if old := in.qc[q.Phase]; old == nil || old.View < q.View {
		in.qc[q.Phase] = q
	}
}

func (p *Consensus) acceptedDigest(mid int64) (string, bool) {
	if p.vc == nil {
		return "", false
	}
	p.vc.mu.Lock()
	defer p.vc.mu.Unlock()
	if in := p.vc.inst[mid]; in != nil && in.prop != nil && in.prop.BatchInfo != nil {
		return in.prop.BatchInfo.BatchDigest, true
	}
	return "", false
}

func (p *Consensus) matchesAccepted(r *Message) bool {
	d, ok := p.acceptedDigest(r.MessageId)
	return !ok || d == r.BatchInfo.BatchDigest
}

func (p *Consensus) vcFirstDelivery(mid int64) bool {
	if p.vc == nil {
		return true
	}
	p.vc.mu.Lock()
	defer p.vc.mu.Unlock()
	if p.vc.delivered[mid] {
		return false
	}
	p.vc.delivered[mid] = true
	for p.vc.delivered[p.vc.committedUpto+1] {
		p.vc.committedUpto++
		old := p.vc.committedUpto - vcRetain
		delete(p.vc.inst, old)
		delete(p.vc.delivered, old)
	}
	p.vc.lastProgress.Store(time.Now().UnixNano())
	return true
}

func noopDigest(mid int64) string {
	h := sha256.Sum256([]byte("tailor-noop|" + strconv.FormatInt(mid, 10)))
	return hex.EncodeToString(h[:])
}

func isNoop(r *Message) bool {
	return r != nil && r.PhaseConfig["noop"] == "1" && r.BatchInfo != nil && r.BatchInfo.BatchDigest == noopDigest(r.MessageId)
}

func (p *Consensus) admitView(r *Message, cmd string, content []byte) bool {
	v := r.GetView()
	if v < viewFloor.Load() {
		return false
	}
	if v > curView.Load() || (p.vc != nil && p.vc.changing.Load() && v >= viewFloor.Load()) {
		if p.vc != nil {
			p.vc.mu.Lock()
			if len(p.vc.buffered) < 1<<16 {
				p.vc.buffered = append(p.vc.buffered, bufferedMsg{cmd: cmd, content: content})
			}
			p.vc.mu.Unlock()
		}
		return false
	}
	return true
}

func (p *Consensus) admitReproposal(r *Message) bool {
	if p.vc == nil {
		return true
	}
	p.vc.mu.Lock()
	defer p.vc.mu.Unlock()
	if r.GetView() != curView.Load() || r.MessageId > p.vc.reproposeMax {
		return true
	}
	if p.vc.refuse[r.MessageId] {
		return false
	}
	want, ok := p.vc.allowed[r.MessageId]
	return ok && want == msgKey(r, r.BatchInfo.BatchDigest)
}

func (p *Consensus) startViewMonitor() {
	if vcTimeout == 0 {
		return
	}
	go func() {
		t := time.NewTicker(100 * time.Millisecond)
		defer t.Stop()
		for range t.C {
			now := time.Now()
			if p.vc.changing.Load() {
				p.vc.mu.Lock()
				wait := vcTimeout << uint(p.vc.attempt)
				expired := now.Sub(p.vc.vcStart) > wait
				p.vc.mu.Unlock()
				if expired {
					p.startViewChange(viewFloor.Load() + 1)
				}
				continue
			}
			if !p.pendingWork() {
				p.vcProgress()
				continue
			}
			idle := now.Sub(time.Unix(0, p.vc.lastProgress.Load()))
			if idle > vcTimeout {
				log.Printf("[%s] VIEWCHANGE: no progress for %v in view %d", p.node.nodeID, idle.Round(time.Millisecond), curView.Load())
				p.startViewChange(curView.Load() + 1)
			}
		}
	}()
}

func (p *Consensus) pendingWork() bool {
	if p.mempool != nil && p.mempool.totalPending() >= p.batchSize {
		return true
	}
	p.vc.mu.Lock()
	defer p.vc.mu.Unlock()
	for mid, in := range p.vc.inst {
		if in.prop != nil && !p.vc.delivered[mid] {
			return true
		}
	}
	return false
}

func reportPayload(vc *pb.ViewChange) []byte {
	c := proto.Clone(vc).(*pb.ViewChange)
	c.Sig = nil
	b, _ := proto.MarshalOptions{Deterministic: true}.Marshal(c)
	h := sha256.Sum256(append([]byte("tailor-viewchange|"), b...))
	return h[:]
}

func newViewPayload(nv *pb.NewView) []byte {
	c := proto.Clone(nv).(*pb.NewView)
	c.Sig = nil
	b, _ := proto.MarshalOptions{Deterministic: true}.Marshal(c)
	h := sha256.Sum256(append([]byte("tailor-newview|"), b...))
	return h[:]
}

func (p *Consensus) startViewChange(target int64) {
	p.vc.mu.Lock()
	if target <= curView.Load() || target < viewFloor.Load() || (p.vc.changing.Load() && target == viewFloor.Load()) {
		p.vc.mu.Unlock()
		return
	}
	if p.vc.changing.Load() {
		p.vc.attempt++
	} else {
		p.vc.attempt = 0
	}
	viewFloor.Store(target)
	p.vc.changing.Store(true)
	p.vc.vcStart = time.Now()
	report := &pb.ViewChange{NewView: target, NodeId: p.node.nodeID, CommittedUpto: p.vc.committedUpto}
	mids := make([]int64, 0, len(p.vc.inst))
	for mid := range p.vc.inst {
		mids = append(mids, mid)
	}
	sort.Slice(mids, func(i, j int) bool { return mids[i] < mids[j] })
	for _, mid := range mids {
		in := p.vc.inst[mid]
		if in.prop == nil && in.qc[1] == nil {
			continue
		}
		ir := &pb.InstanceReport{Proposal: in.prop, FirstQc: in.qc[1]}
		if in.prop != nil && len(cfgOf(in.prop)) == 3 {
			ir.LockQc = in.qc[2]
		}
		report.Instances = append(report.Instances, ir)
	}
	p.vc.mu.Unlock()
	report.Chain = p.chainReport()
	report.Sig = p.RsaSignWithSha256(reportPayload(report), p.node.rsaPrivKey)
	log.Printf("[%s] VIEWCHANGE: reporting %d instances for view %d to %s", p.node.nodeID, len(report.Instances), target, leaderOf(target))
	b, err := proto.Marshal(report)
	if err != nil {
		return
	}
	if leaderOf(target) == p.node.nodeID {
		go p.handleViewChange(b)
		return
	}
	p.sendToNode(leaderOf(target), "ViewChange", b)
}

func (p *Consensus) sendToNode(id string, cmd string, b []byte) {
	if ps, err := getPeerStream(NodeTable[id]); err == nil {
		ps.SendAsync(&pb.ConsensusMessage{Command: cmd, Content: b})
		return
	}
	go grpcSendMessage(NodeTable[id], cmd, b)
}

func (p *Consensus) validReport(vc *pb.ViewChange) bool {
	if vc == nil {
		return false
	}
	if _, known := NodeTable[vc.NodeId]; !known || !strings.HasPrefix(vc.NodeId, "N") {
		return false
	}
	if !p.RsaVerifyCached(reportPayload(vc), vc.Sig, vc.NodeId) {
		return false
	}
	for _, ir := range vc.Instances {
		if ir.FirstQc != nil && (ir.FirstQc.Phase != 1 || ir.FirstQc.View >= vc.NewView || !p.VerifyQC(ir.FirstQc)) {
			return false
		}
		if ir.LockQc != nil && (ir.LockQc.Phase != 2 || ir.LockQc.View >= vc.NewView || !p.VerifyQC(ir.LockQc)) {
			return false
		}
		if ir.Proposal != nil && !proposalDigestOK(ir.Proposal) {
			return false
		}
	}
	if vc.Chain != nil && vc.Chain.HighQc != nil && !p.VerifyQC(vc.Chain.HighQc) {
		return false
	}
	return true
}

func proposalDigestOK(m *Message) bool {
	if m.BatchInfo == nil {
		return false
	}
	if isNoop(m) {
		return true
	}
	ds := make([][32]byte, len(m.BatchInfo.Refs))
	for i, r := range m.BatchInfo.Refs {
		copy(ds[i][:], r.Digest)
	}
	return len(ds) > 0 && aggregateDigests(ds) == m.BatchInfo.BatchDigest
}

func (p *Consensus) handleViewChange(content []byte) {
	vc := new(pb.ViewChange)
	if err := proto.Unmarshal(content, vc); err != nil || !p.validReport(vc) {
		return
	}
	v := vc.NewView
	if leaderOf(v) != p.node.nodeID || v <= curView.Load() {
		return
	}
	p.vc.mu.Lock()
	if p.vc.reports[v] == nil {
		p.vc.reports[v] = map[string]*pb.ViewChange{}
	}
	p.vc.reports[v][vc.NodeId] = vc
	n := len(p.vc.reports[v])
	sent := p.vc.newViewSent[v]
	p.vc.mu.Unlock()
	if sent || n < Threshold {
		return
	}
	if viewFloor.Load() < v {
		p.startViewChange(v)
		return
	}
	p.vc.mu.Lock()
	if p.vc.newViewSent[v] || len(p.vc.reports[v]) < Threshold {
		p.vc.mu.Unlock()
		return
	}
	p.vc.newViewSent[v] = true
	reports := make([]*pb.ViewChange, 0, len(p.vc.reports[v]))
	for _, r := range p.vc.reports[v] {
		reports = append(reports, r)
	}
	p.vc.mu.Unlock()
	sort.Slice(reports, func(i, j int) bool { return reports[i].NodeId < reports[j].NodeId })
	reports = reports[:Threshold]
	nv := &pb.NewView{View: v, Leader: p.node.nodeID, Reports: reports}
	sel, ok := p.selectReproposals(reports, v)
	if !ok {
		log.Printf("[%s] VIEWCHANGE: reports for view %d do not determine all re-proposals", p.node.nodeID, v)
		return
	}
	for _, it := range sel.items {
		nv.Proposals = append(nv.Proposals, it.prop)
	}
	nv.Sig = p.RsaSignWithSha256(newViewPayload(nv), p.node.rsaPrivKey)
	b, err := proto.Marshal(nv)
	if err != nil {
		return
	}
	log.Printf("[%s] VIEWCHANGE: view %d with %d reports, re-proposing %d instances", p.node.nodeID, v, len(reports), len(nv.Proposals))
	p.broadcast("NewView", b)
	p.applyNewView(nv, sel)
}

type selItem struct {
	prop    *Message
	qcView  int64
	fixedBy bool
}

type selection struct {
	lo, hi int64
	items  []*selItem
	chain  *pb.ChainReport
}

func (p *Consensus) selectReproposals(reports []*pb.ViewChange, v int64) (*selection, bool) {
	ups := make([]int64, 0, len(reports))
	for _, r := range reports {
		ups = append(ups, r.CommittedUpto)
	}
	sort.Slice(ups, func(i, j int) bool { return ups[i] > ups[j] })

	f := (len(nodeOrder()) - 1) / 3
	if f >= len(ups) {
		f = len(ups) - 1
	}
	lo := ups[f]
	hi := lo
	bestQC := map[int64]*pb.QCProof{}
	props := map[int64]map[string]*Message{}
	for _, r := range reports {
		for _, ir := range r.Instances {
			mid := int64(-1)
			if ir.Proposal != nil {
				mid = ir.Proposal.MessageId
				if props[mid] == nil {
					props[mid] = map[string]*Message{}
				}
				props[mid][ir.Proposal.BatchInfo.BatchDigest] = ir.Proposal
			}
			if q := ir.FirstQc; q != nil {
				mid = q.Mid
				if b := bestQC[mid]; b == nil || b.View < q.View {
					bestQC[mid] = q
				}
			}
			if mid > hi {
				hi = mid
			}
		}
	}
	sel := &selection{lo: lo, hi: hi}
	for mid := lo + 1; mid <= hi; mid++ {
		it := &selItem{qcView: -1}
		if q := bestQC[mid]; q != nil {
			src := props[mid][q.Digest]
			if src == nil {
				return nil, false
			}
			m := proto.Clone(src).(*Message)
			m.PhaseConfig = phaseConfigFromCfg(q.Cfg)
			it.prop, it.qcView, it.fixedBy = m, q.View, true
		} else if cands := props[mid]; len(cands) > 0 {
			var src *Message
			for _, c := range cands {
				if src == nil || c.GetView() > src.GetView() || (c.GetView() == src.GetView() && c.BatchInfo.BatchDigest < src.BatchInfo.BatchDigest) {
					src = c
				}
			}
			m := proto.Clone(src).(*Message)
			m.PhaseConfig = buildPhaseConfig()
			it.prop = m
		} else {
			it.prop = &Message{MessageId: mid, PhaseConfig: buildPhaseConfig(), BatchInfo: &pb.BatchInfo{BatchDigest: noopDigest(mid)}}
			it.prop.PhaseConfig["noop"] = "1"
		}
		it.prop.View = v
		it.prop.NodeId = leaderOf(v)
		it.prop.Proof = nil
		sel.items = append(sel.items, it)
	}
	sel.chain = selectChainHigh(reports)
	return sel, true
}

func phaseConfigFromCfg(cfg string) map[string]string {
	out := map[string]string{}
	for i, c := range cfg {
		k := "phase" + strconv.Itoa(i+1)
		if c == 'R' {
			out[k] = "RSA"
		} else {
			out[k] = "BLS"
		}
	}
	return out
}

func (p *Consensus) handleNewView(content []byte) {
	nv := new(pb.NewView)
	if err := proto.Unmarshal(content, nv); err != nil {
		return
	}
	v := nv.View
	if v <= curView.Load() || nv.Leader != leaderOf(v) || len(nv.Reports) < Threshold {
		return
	}
	if !p.RsaVerifyCached(newViewPayload(nv), nv.Sig, nv.Leader) {
		log.Printf("[%s] VIEWCHANGE: invalid NewView signature for view %d", p.node.nodeID, v)
		return
	}
	seen := map[string]bool{}
	for _, r := range nv.Reports {
		if r.NewView != v || seen[r.NodeId] || !p.validReport(r) {
			log.Printf("[%s] VIEWCHANGE: NewView %d carries an invalid report", p.node.nodeID, v)
			return
		}
		seen[r.NodeId] = true
	}
	want, ok := p.selectReproposals(nv.Reports, v)
	if !ok || len(want.items) != len(nv.Proposals) {
		log.Printf("[%s] VIEWCHANGE: NewView %d re-proposals do not follow the reports", p.node.nodeID, v)
		return
	}

	for i, it := range want.items {
		got := nv.Proposals[i]
		if got.MessageId != it.prop.MessageId || got.GetView() != v {
			return
		}
		if it.fixedBy && (got.BatchInfo.BatchDigest != it.prop.BatchInfo.BatchDigest || cfgOf(got) != cfgOf(it.prop)) {
			log.Printf("[%s] VIEWCHANGE: NewView %d changes instance %d fixed by a QC", p.node.nodeID, v, got.MessageId)
			return
		}
		if !isNoop(got) && !proposalDigestOK(got) {
			return
		}
		it.prop = got
	}
	p.applyNewView(nv, want)
}

func (p *Consensus) applyNewView(nv *pb.NewView, sel *selection) {
	v := nv.View
	p.vc.mu.Lock()
	if v <= curView.Load() {
		p.vc.mu.Unlock()
		return
	}
	p.vc.allowed = map[int64]string{}
	p.vc.refuse = map[int64]bool{}
	for _, it := range sel.items {
		mid := it.prop.MessageId
		p.vc.allowed[mid] = msgKey(it.prop, it.prop.BatchInfo.BatchDigest)
		if in := p.vc.inst[mid]; in != nil {
			if lock := in.qc[2]; lock != nil && in.prop != nil && len(cfgOf(in.prop)) == 3 {
				if lock.Digest != it.prop.BatchInfo.BatchDigest && it.qcView <= lock.View {
					p.vc.refuse[mid] = true
				}
			}
		}
	}
	p.vc.reproposeMax = sel.hi
	if sel.hi > p.vc.maxMid {
		p.vc.maxMid = sel.hi
	}
	curView.Store(v)
	if viewFloor.Load() < v {
		viewFloor.Store(v)
	}
	p.vc.changing.Store(false)
	p.vc.attempt = 0
	buf := p.vc.buffered
	p.vc.buffered = nil
	p.vc.lastProgress.Store(time.Now().UnixNano())
	p.vc.mu.Unlock()
	log.Printf("[%s] VIEWCHANGE: entered view %d (leader %s), re-proposals %d..%d", p.node.nodeID, v, leaderOf(v), sel.lo+1, sel.hi)

	for _, rep := range nv.Reports {
		for _, ir := range rep.Instances {
			if ir.Proposal != nil && ir.Proposal.BatchInfo != nil {
				for _, r := range ir.Proposal.BatchInfo.Refs {
					p.mempool.advance(r.ClientId, r.Hi)
				}
			}
		}
	}
	for _, it := range sel.items {
		if it.prop.BatchInfo != nil {
			for _, r := range it.prop.BatchInfo.Refs {
				p.mempool.advance(r.ClientId, r.Hi)
			}
		}
	}
	chainNext := p.chainEnterView(nv, sel.chain)
	if leaderOf(v) == p.node.nodeID {
		p.leadNewView(v, sel, chainNext)
	}
	for _, b := range buf {
		p.assignPhase(b.cmd, b.content)
	}
}

func (p *Consensus) leadNewView(v int64, sel *selection, chainNext int64) {
	next := sel.hi + 1
	p.vc.mu.Lock()
	if p.vc.maxMid+1 > next {
		next = p.vc.maxMid + 1
	}
	p.vc.mu.Unlock()
	if chainNext >= 0 {
		next = chainNext
	}
	atomic.StoreInt64(&p.messageIDCounter, next)
	for _, it := range sel.items {
		m := proto.Clone(it.prop).(*Message)
		m.Proof = &pb.Proof{}
		if !isNoop(m) {
			reqs, d, ok := p.verifyBatchRefs(m.BatchInfo)
			if !ok || d != m.BatchInfo.BatchDigest {
				log.Printf("[%s] VIEWCHANGE: cannot re-propose instance %d: references unavailable", p.node.nodeID, m.MessageId)
				continue
			}
			p.RequestsCache.Set(m.MessageId, reqs)
			p.RefsCache.Set(m.MessageId, append([]*pb.ClientRange(nil), m.BatchInfo.Refs...))
		} else {
			p.RefsCache.Set(m.MessageId, []*pb.ClientRange{})
		}
		p.semReleased.Store(m.BatchInfo.BatchDigest, struct{}{})
		p.vcRecordProposal(m)
		p.startConsensusForRequest(m)
	}
	p.leaderWake()
}

func (p *Consensus) awaitLeadership() {
	for !p.isViewLeader() || p.vc.changing.Load() {
		select {
		case <-p.leaderCh:
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func (p *Consensus) leaderWake() {
	select {
	case p.leaderCh <- struct{}{}:
	default:
	}
}

func (p *Consensus) acceptNoop(r *Message) {
	p.RefsCache.Set(r.MessageId, []*pb.ClientRange{})
	p.vcRecordProposal(r)
}

func (p *Consensus) finishNoop(r *Message) {
	batchID := r.BatchInfo.BatchDigest
	p.deliverBatch(r.MessageId, nil)
	p.RefsCache.Delete(r.MessageId)
	p.completed.add(batchID)
	p.completed.add(msgKey(r, batchID))
	p.deletePrevProofGates(msgKey(r, batchID))
	go p.cleanupGenericState(msgKey(r, batchID), batchID, r.MessageId)
}
