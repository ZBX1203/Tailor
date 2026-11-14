package main

import (
	"sort"
	"strconv"
	"sync/atomic"

	pb "merge_consensus/merge_proto"

	"google.golang.org/protobuf/proto"
)

func qcRankLess(a, b *pb.QCProof) bool {
	if a.View != b.View {
		return a.View < b.View
	}
	return a.Mid < b.Mid
}

func (p *Consensus) chainHighQCLocked() *pb.QCProof {
	var best *pb.QCProof
	for _, q := range p.vc.chainQC {
		if best == nil || qcRankLess(best, q) {
			best = q
		}
	}
	return best
}

func (p *Consensus) chainReport() *pb.ChainReport {
	if !chainedB {
		return nil
	}
	p.vc.mu.Lock()
	high := p.chainHighQCLocked()
	p.vc.mu.Unlock()
	if high == nil {
		return nil
	}
	rep := &pb.ChainReport{HighQc: high}
	p.chainMu.Lock()
	rep.LockQc = p.chainLock
	mids := make([]int64, 0, len(p.chainMsgs))
	for mid := range p.chainMsgs {
		if mid <= high.Mid {
			mids = append(mids, mid)
		}
	}
	sort.Slice(mids, func(i, j int) bool { return mids[i] < mids[j] })
	for _, mid := range mids {
		b := p.chainBlockWithRefs(p.chainMsgs[mid])
		if b == nil {
			continue
		}
		rep.Blocks = append(rep.Blocks, b)
		if mid == high.Mid {
			rep.HighBlock = b
		}
	}
	p.chainMu.Unlock()
	return rep
}

func (p *Consensus) chainBlockWithRefs(m *Message) *Message {
	if m == nil || m.BatchInfo == nil {
		return nil
	}
	c := proto.Clone(m).(*Message)
	c.Proof = nil
	c.Justify = nil
	if refs, ok := p.RefsCache.Get(m.MessageId); ok && len(refs) > 0 {
		c.BatchInfo.Refs = refs
	}
	return c
}

func selectChainHigh(reports []*pb.ViewChange) *pb.ChainReport {
	var best *pb.ChainReport
	for _, r := range reports {
		if r.Chain == nil || r.Chain.HighQc == nil {
			continue
		}
		if best == nil || qcRankLess(best.HighQc, r.Chain.HighQc) {
			best = r.Chain
		}
	}
	return best
}

func (p *Consensus) chainEnterView(nv *pb.NewView, high *pb.ChainReport) int64 {
	if !chainedB {
		return -1
	}
	wm := map[uint32]uint64{}
	raise := func(m *Message, limit int64) {
		if m == nil || m.BatchInfo == nil || m.MessageId > limit {
			return
		}
		for _, r := range m.BatchInfo.Refs {
			if r.Hi > wm[r.ClientId] {
				wm[r.ClientId] = r.Hi
			}
		}
	}
	limit := int64(-1)
	if high != nil {
		limit = high.HighQc.Mid
	}
	for _, rep := range nv.Reports {
		if rep.Chain != nil {
			for _, b := range rep.Chain.Blocks {
				raise(b, limit)
			}
		}
	}
	p.chainMu.Lock()
	for mid, m := range p.chainMsgs {
		if mid > limit {
			delete(p.chainMsgs, mid)
			continue
		}
		if refs, ok := p.RefsCache.Get(mid); ok {
			for _, r := range refs {
				if r.Hi > wm[r.ClientId] {
					wm[r.ClientId] = r.Hi
				}
			}
		}
		_ = m
	}
	for mid := range p.chainCertAt {
		if mid > limit {
			delete(p.chainCertAt, mid)
		}
	}
	for cid, hi := range p.committedWM {
		if hi > wm[cid] {
			wm[cid] = hi
		}
	}
	if high != nil {
		q := high.HighQc
		p.chainLastDig = q.Digest
		p.chainLastView = q.View
		atomic.StoreInt64(&p.chainLastMid, q.Mid)
		atomic.StoreInt64(&p.chainPendingMid, q.Mid)
		p.chainLastQC = nil
		if q.Cfg == "B" && q.BlsAggregation != nil {
			p.chainLastQC = &pb.BLSAggregation{AggregatedSig: q.BlsAggregation.AggregatedSig, Participants: q.BlsAggregation.Participants}
		}
		if q.Mid > p.chainMaxCert {
			p.chainMaxCert = q.Mid
		}
		p.chainCertAt[q.Mid] = q.Digest
		p.chainJustify = q
		if hb := high.HighBlock; hb != nil {
			if _, have := p.chainMsgs[hb.MessageId]; !have && hb.BatchInfo != nil && len(hb.BatchInfo.Refs) > 0 {
				if reqs, d, ok := p.verifyBatchRefs(hb.BatchInfo); ok && chainDigest(d, hb.PhaseConfig["parent"], chainParentView(hb)) == hb.BatchInfo.BatchDigest && hb.BatchInfo.BatchDigest == q.Digest {
					p.RequestsCache.Set(hb.MessageId, reqs)
					p.RefsCache.Set(hb.MessageId, append([]*pb.ClientRange(nil), hb.BatchInfo.Refs...))
					reg := proto.Clone(hb).(*Message)
					reg.BatchInfo.Refs = nil
					p.chainMsgs[hb.MessageId] = reg
				}
			}
		}
	} else {
		p.chainLastDig = ""
		p.chainLastQC = nil
		p.chainJustify = nil
	}
	p.chainMu.Unlock()
	for cid, hi := range wm {
		p.mempool.setWatermark(cid, hi)
	}
	if leaderOf(nv.View) == p.node.nodeID {
		chainFirst = high == nil
		select {
		case p.chainReady <- struct{}{}:
		default:
		}
	}
	if high == nil {
		return -1
	}
	return high.HighQc.Mid + 1
}

func (p *Consensus) chainAbsorbJustify(r *Message) bool {
	j := r.Justify
	if j == nil {
		return true
	}
	pm, err := strconv.ParseInt(r.PhaseConfig["parent_mid"], 10, 64)
	if err != nil || j.Mid != pm || j.Digest != r.PhaseConfig["parent"] || j.View > r.GetView() || !p.VerifyQC(j) {
		return false
	}
	p.vcRecordQC(j)
	if j.Cfg == "R" {
		p.chainMu.Lock()
		have := p.chainCertAt[j.Mid] == j.Digest
		p.chainMu.Unlock()
		if !have {
			p.injectRsaQC(j)
		}
	}
	return true
}

func chainParentView(r *Message) int64 {
	if v, err := strconv.ParseInt(r.PhaseConfig["parent_view"], 10, 64); err == nil {
		return v
	}
	if r.Justify != nil {
		return r.Justify.View
	}
	return r.GetView()
}

func (p *Consensus) chainSafeToVote(r *Message) bool {
	if p.chainLock == nil {
		return true
	}
	pm, err := strconv.ParseInt(r.PhaseConfig["parent_mid"], 10, 64)
	if err != nil {
		return false
	}
	return !qcRankLess(&pb.QCProof{View: chainParentView(r), Mid: pm}, p.chainLock)
}

func (p *Consensus) chainUpdateLock(q *pb.QCProof) {
	cand := q
	if chainDepth == 3 {
		m := p.chainMsgs[q.Mid]
		if m == nil {
			return
		}
		pm, err := strconv.ParseInt(m.PhaseConfig["parent_mid"], 10, 64)
		if err != nil {
			return
		}
		cand = &pb.QCProof{View: chainParentView(m), Mid: pm, Digest: m.PhaseConfig["parent"]}
	}
	if p.chainLock == nil || qcRankLess(p.chainLock, cand) {
		p.chainLock = cand
	}
}

func (p *Consensus) injectRsaQC(q *pb.QCProof) {
	r := &Message{
		View:        q.View,
		MessageId:   q.Mid,
		NodeId:      p.node.nodeID,
		PhaseConfig: phaseConfigFromCfg(q.Cfg),
		BatchInfo:   &pb.BatchInfo{BatchDigest: q.Digest},
		Proof:       &pb.Proof{RsaSignatures: q.RsaSignatures},
	}
	p.vc.mu.Lock()
	if in := p.vc.inst[q.Mid]; in != nil && in.prop != nil && in.prop.BatchInfo.BatchDigest == q.Digest {
		r.PhaseConfig = in.prop.PhaseConfig
	}
	p.vc.mu.Unlock()
	if len(q.Cfg) == 1 {
		p.chainMu.Lock()
		if m := p.chainMsgs[q.Mid]; m != nil && m.BatchInfo != nil && m.BatchInfo.BatchDigest == q.Digest {
			r.PhaseConfig = m.PhaseConfig
		}
		p.chainMu.Unlock()
	}
	p.processRsaPhase(int(q.Phase), r)
}

func (p *Consensus) noteDelivered(refs []*pb.ClientRange) {
	p.chainMu.Lock()
	if p.committedWM == nil {
		p.committedWM = map[uint32]uint64{}
	}
	for _, r := range refs {
		if r.Hi > p.committedWM[r.ClientId] {
			p.committedWM[r.ClientId] = r.Hi
		}
	}
	p.chainMu.Unlock()
}

func (p *Consensus) acceptedForVote(r *Message, digest string) bool {
	if isChainBlock(r) {
		p.chainMu.Lock()
		m := p.chainMsgs[r.MessageId]
		ok := m != nil && m.BatchInfo != nil && m.BatchInfo.BatchDigest == digest && m.GetView() == r.GetView()
		p.chainMu.Unlock()
		return ok && p.chainParentReady(r)
	}
	return p.acceptedFor(r, digest)
}
