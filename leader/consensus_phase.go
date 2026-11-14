package main

import (
	"encoding/hex"
	"fmt"
	"log"
	pb "merge_consensus/merge_proto"
	"os"
	"strconv"
	"sync"
	"time"
)

func (p *Consensus) phaseTimeLog(msgID int64, tag string) {
	if p.isViewLeader() && msgID < 8 {
		log.Printf("[PHASETIME] node=%s mid=%d tag=%s t=%d", p.node.nodeID, msgID, tag, time.Now().UnixNano())
	}
}

type completedSet struct {
	m    sync.Map
	mu   sync.Mutex
	ring []string
	idx  int
	cap  int
}

func newCompletedSet(c int) *completedSet {
	return &completedSet{ring: make([]string, c), cap: c}
}

func (s *completedSet) has(id string) bool {
	_, ok := s.m.Load(id)
	return ok
}

func (s *completedSet) add(id string) {
	if _, dup := s.m.LoadOrStore(id, struct{}{}); dup {
		return
	}
	s.mu.Lock()
	old := s.ring[s.idx]
	s.ring[s.idx] = id
	s.idx = (s.idx + 1) % s.cap
	s.mu.Unlock()
	if old != "" {
		s.m.Delete(old)
	}
}

func (p *Consensus) getRsaPhaseState(phase int, batchID string) *RsaPhaseState {
	var m *sync.Map
	switch phase {
	case 1:
		m = &p.phase1RsaStates
	case 2:
		m = &p.phase2RsaStates
	case 3:
		m = &p.phase3RsaStates
	default:
		return nil
	}
	if v, ok := m.Load(batchID); ok {
		return v.(*RsaPhaseState)
	}
	v, _ := m.LoadOrStore(batchID, &RsaPhaseState{})
	return v.(*RsaPhaseState)
}

func (p *Consensus) getBlsPhaseState(phase int, batchID string) *BlsPhaseState {
	var m *sync.Map
	switch phase {
	case 1:
		m = &p.phase1BlsStates
	case 2:
		m = &p.phase2BlsStates
	case 3:
		m = &p.phase3BlsStates
	default:
		return nil
	}
	if v, ok := m.Load(batchID); ok {
		return v.(*BlsPhaseState)
	}
	v, _ := m.LoadOrStore(batchID, &BlsPhaseState{})
	return v.(*BlsPhaseState)
}

func prevProofGateKey(batchID string, phaseN int) string {
	return fmt.Sprintf("%s|%d", batchID, phaseN)
}

func (p *Consensus) getPrevProofGate(batchID string, phaseN int) *PrevProofGate {
	key := prevProofGateKey(batchID, phaseN)
	if v, ok := p.prevProofGates.Load(key); ok {
		return v.(*PrevProofGate)
	}
	v, _ := p.prevProofGates.LoadOrStore(key, &PrevProofGate{})
	return v.(*PrevProofGate)
}

func (p *Consensus) bufferEarlyRsaVote(gate *PrevProofGate, vote pendingRsaVote) *pendingRsaVote {
	if gate.verified.Load() {
		return &vote
	}
	vote.signature = append([]byte(nil), vote.signature...)
	_, loaded := gate.pending.LoadOrStore(vote.nodeID, vote)
	if !loaded {
		p.earlyRsaEchoBuffered.Add(1)
	}
	if !gate.verified.Load() {
		return nil
	}
	owned, ok := gate.pending.LoadAndDelete(vote.nodeID)
	if !ok {
		return nil
	}
	p.earlyRsaEchoReplayed.Add(1)
	result := owned.(pendingRsaVote)
	return &result
}

func (p *Consensus) drainEarlyRsaVotes(gate *PrevProofGate) []pendingRsaVote {
	var votes []pendingRsaVote
	gate.pending.Range(func(key, _ interface{}) bool {
		if owned, ok := gate.pending.LoadAndDelete(key); ok {
			votes = append(votes, owned.(pendingRsaVote))
			p.earlyRsaEchoReplayed.Add(1)
		}
		return true
	})
	return votes
}

func (p *Consensus) deletePrevProofGates(batchID string) {
	p.prevProofGates.Delete(prevProofGateKey(batchID, 2))
	p.prevProofGates.Delete(prevProofGateKey(batchID, 3))
}

func phaseCmd(n int, sigType string) string {
	switch n {
	case 1:
		if sigType == "BLS" {
			return "Prepare"
		}
		return "Phase1_RSA"
	case 2:
		if sigType == "BLS" {
			return "Commit_BLS"
		}
		return "Commit_RSA"
	case 3:
		if sigType == "BLS" {
			return "Decide_BLS"
		}
		return "Decide_RSA"
	}
	return ""
}

func blsAggCmd(n int) string {
	return fmt.Sprintf("phase%dBlsAggregation", n)
}

var proposalPadBytes = func() int {
	if v, err := strconv.Atoi(os.Getenv("PROPOSAL_PAD_BYTES")); err == nil && v > 0 {
		return v
	}
	return 0
}()
var proposalPad = func() []byte {
	if proposalPadBytes == 0 {
		return nil
	}
	b := make([]byte, proposalPadBytes)
	for i := range b {
		b[i] = byte(i*131 + 7)
	}
	return b
}()

func (p *Consensus) transitionToNextPhase(n int, msg *Message) {
	if msg.GetView() < viewFloor.Load() {
		return
	}
	if n >= phaseCountOf(msg) {

		p.finalReply(msg)
		return
	}
	nextN := n + 1
	phaseKey := fmt.Sprintf("phase%d", nextN)
	nextSig := msg.PhaseConfig[phaseKey]
	batchID := msg.BatchInfo.BatchDigest

	if nextN > 1 {
		p.getPrevProofGate(msgKey(msg, batchID), nextN).verified.Store(true)
	}

	if p.isViewLeader() {
		p.latencyTrackerLock.Lock()
		if tracker, exists := p.latencyTrackers[msg.MessageId]; exists {
			switch nextN {
			case 1:
				if tracker.T1_PreparePhase.IsZero() {
					tracker.T1_PreparePhase = time.Now()
					tracker.HasT1 = true
					tracker.BatchDigest = msg.BatchInfo.BatchDigest
				}
			case 2:
				if tracker.T2_CommitPhase.IsZero() {
					tracker.T2_CommitPhase = time.Now()
					tracker.HasT2 = true
				}
			case 3:
				if tracker.T3_DecidePhase.IsZero() {
					tracker.T3_DecidePhase = time.Now()
					tracker.HasT3 = true
				}
			}
		}
		p.latencyTrackerLock.Unlock()
	}

	switch nextN {
	case 1:
		msg.MessageType = "prepare"
	case 2:
		msg.MessageType = "commit"
	case 3:
		msg.MessageType = "decide"
	}
	msg.NodeId = p.node.nodeID

	if nextSig == "BLS" {

		leaderSig := p.node.blsKey.Sign(msgPayload(msg, nextN, batchID))
		msg.Proof.BlsSignatures = []*pb.SigEntry{
			{NodeId: p.node.nodeID, Signature: leaderSig},
		}

		state := p.getBlsPhaseState(nextN, msgKey(msg, batchID))
		if pt, err := DecodeBLSPoint(leaderSig); err == nil {
			if _, existed := state.sigs.LoadOrStore(p.node.nodeID, blsSignature{NodeID: p.node.nodeID, Sig: pt}); !existed {
				state.count.Add(1)
			}
		}
	} else {

		digestByte, err := hex.DecodeString(batchID)
		if err != nil {
			log.Printf("[%s] transitionToNextPhase: batchID decode failed: %v", p.node.nodeID, err)
			return
		}
		leaderSig := p.RsaSignWithSha256(msgPayload(msg, nextN, batchID), p.node.rsaPrivKey)

		_ = digestByte
		msg.Proof.RsaSignatures = []*pb.SigEntry{
			{NodeId: p.node.nodeID, Signature: leaderSig},
		}

		msg.Proof.BlsSignatures = nil

		state := p.getRsaPhaseState(nextN, msgKey(msg, batchID))
		if _, existed := state.sigs.LoadOrStore(p.node.nodeID, leaderSig); !existed {
			state.count.Add(1)
		}
		state.echoed.Store(true)
	}

	cmd := phaseCmd(nextN, nextSig)
	if proposalPadBytes > 0 && nextN == 1 && p.isViewLeader() {

		msg.BatchInfo.Requests = []*pb.Request{{Sign: proposalPad}}
	}
	b, err := GobEncode(msg)
	if nextN == 1 {
		msg.BatchInfo.Requests = nil
	}
	if err != nil {
		log.Printf("[%s] transitionToNextPhase serialization failed: %v", p.node.nodeID, err)
		return
	}
	if nextN == 1 && byzLeaderActive(p.node.nodeID) && len(msg.BatchInfo.Refs) > 0 {

		r0 := msg.BatchInfo.Refs[0]
		orig := r0.Digest
		tampered := append([]byte(nil), orig...)
		if len(tampered) == 0 {
			tampered = []byte{0}
		}
		tampered[0] ^= 0xff
		r0.Digest = tampered
		evil, _ := GobEncode(msg)
		r0.Digest = orig
		p.broadcastSplit(command(cmd), b, evil, byzVictims)
	} else {
		p.broadcast(command(cmd), b)
	}
	p.phaseTimeLog(msg.MessageId, fmt.Sprintf("p%d_bcast", nextN))
	if msg.MessageId < 8 {
		log.Printf("[MSGSIZE] node=%s mid=%d phase=%d sig=%s kind=leader_bcast bytes=%d refs=%d", p.node.nodeID, msg.MessageId, nextN, nextSig, len(b), len(msg.BatchInfo.Refs))
	}
}

func (p *Consensus) ingestBatchRefs(r *Message) bool {
	if len(r.BatchInfo.Refs) == 0 {
		return false
	}
	allReqs, localDigest, ok := p.verifyBatchRefs(r.BatchInfo)
	if !ok {
		return false
	}
	if isChainBlock(r) {
		localDigest = chainDigest(localDigest, r.PhaseConfig["parent"], chainParentView(r))
	} else if !p.vcCanAccept(r.GetView(), r.MessageId, localDigest) {
		log.Printf("[%s] instance %d: a different proposal was already accepted in view %d, ignoring", p.node.nodeID, r.MessageId, r.GetView())
		return false
	}
	r.BatchInfo.BatchDigest = localDigest
	p.RequestsCache.Set(r.MessageId, allReqs)
	refsCopy := make([]*pb.ClientRange, len(r.BatchInfo.Refs))
	copy(refsCopy, r.BatchInfo.Refs)
	p.RefsCache.Set(r.MessageId, refsCopy)
	for _, ref := range refsCopy {
		p.mempool.advance(ref.ClientId, ref.Hi)
	}
	p.vcRecordProposal(r)
	r.BatchInfo.Refs = nil
	if late, ok := p.takeLateReply(r.MessageId); ok {
		go p.handleReply(late)
	}
	p.lateReplyMu.Lock()
	lf, okf := p.lateFinals[r.MessageId]
	if okf {
		delete(p.lateFinals, r.MessageId)
	}
	p.lateReplyMu.Unlock()
	if okf {
		go p.finalizeLocal(lf)
	}
	return true
}

func (p *Consensus) finalizeLocal(r *Message) {
	batchID := r.BatchInfo.BatchDigest
	if !isChainBlock(r) && !p.matchesAccepted(r) {
		log.Printf("[%s] instance %d: certified digest differs from the accepted proposal, not committing local content", p.node.nodeID, r.MessageId)
		return
	}
	if isNoop(r) {
		p.finishNoop(r)
		return
	}

	if p.isViewLeader() {
		p.latencyTrackerLock.Lock()
		if tracker, exists := p.latencyTrackers[r.MessageId]; exists && !tracker.Completed {
			if tracker.T4_Completed.IsZero() {
				tracker.T4_Completed = time.Now()
				tracker.Completed = true
				trackerCopy := *tracker
				p.latencyTrackerLock.Unlock()
				go p.outputLatencyBreakdown(&trackerCopy)
			} else {
				p.latencyTrackerLock.Unlock()
			}
		} else {
			p.latencyTrackerLock.Unlock()
		}
	}

	refs, ok := p.RefsCache.Get(r.MessageId)
	if !ok || len(refs) == 0 {

		p.lateReplyMu.Lock()
		p.lateFinals[r.MessageId] = r
		p.lateReplyMu.Unlock()
		if refs2, ok2 := p.RefsCache.Get(r.MessageId); ok2 && len(refs2) > 0 {
			p.lateReplyMu.Lock()
			_, still := p.lateFinals[r.MessageId]
			delete(p.lateFinals, r.MessageId)
			p.lateReplyMu.Unlock()
			if !still {
				return
			}
			refs = refs2
		} else {
			return
		}
	}
	p.commitOrder.wait(r.MessageId)
	p.deliverBatch(r.MessageId, refs)
	p.RefsCache.Delete(r.MessageId)
	p.RequestsCache.Delete(r.MessageId)

	if p.isViewLeader() {
		p.releaseSemOnce(batchID)
		p.markDecideCompleted(r.MessageId)
	}

	p.completed.add(batchID)
	p.completed.add(msgKey(r, batchID))
	p.deletePrevProofGates(msgKey(r, batchID))
	go p.cleanupGenericState(msgKey(r, batchID), batchID, r.MessageId)
}

func (p *Consensus) authorizeBlsToRsa(r *Message, currentPhaseN int, digest []byte) (bool, []pendingRsaVote) {
	gate := p.getPrevProofGate(msgKey(r, r.BatchInfo.BatchDigest), currentPhaseN)
	if gate.verified.Load() {
		return true, nil
	}
	if senderIsLeader(r) {
		if !p.verifyBlsAggregation(r, currentPhaseN-1) {
			return false, nil
		}
		p.vcRecordQC(qcFromBls(r, currentPhaseN-1, r.BatchInfo.BatchDigest, r.Proof.BlsAggregation))
		gate.verified.Store(true)
		return true, p.drainEarlyRsaVotes(gate)
	}

	if r.Proof == nil || len(r.Proof.RsaSignatures) != 1 {
		return false, nil
	}
	sigInfo := r.Proof.RsaSignatures[0]
	if sigInfo == nil || sigInfo.NodeId != r.NodeId || sigInfo.NodeId == leaderOf(r.GetView()) {
		return false, nil
	}
	if _, known := NodeTable[sigInfo.NodeId]; !known {
		return false, nil
	}
	if !p.RsaVerifyCached(msgPayload(r, currentPhaseN, r.BatchInfo.BatchDigest), sigInfo.Signature, sigInfo.NodeId) {
		log.Printf("[%s] phase%d RSA: early echo signature from %s failed verification",
			p.node.nodeID, currentPhaseN, sigInfo.NodeId)
		return false, nil
	}
	owned := p.bufferEarlyRsaVote(gate, pendingRsaVote{
		nodeID:    sigInfo.NodeId,
		signature: sigInfo.Signature,
	})
	if owned == nil {
		return false, nil
	}
	return true, []pendingRsaVote{*owned}
}

func (p *Consensus) verifyPrevPhaseProof(r *Message, currentPhaseN int) bool {
	if currentPhaseN <= 1 {
		return true
	}
	prevKey := fmt.Sprintf("phase%d", currentPhaseN-1)
	prevSig := r.PhaseConfig[prevKey]
	batchID := r.BatchInfo.BatchDigest

	if prevSig == "BLS" {
		gate := p.getPrevProofGate(msgKey(r, batchID), currentPhaseN)
		if gate.verified.Load() {
			return true
		}

		if !senderIsLeader(r) || !p.verifyBlsAggregation(r, currentPhaseN-1) {
			return false
		}
		p.vcRecordQC(qcFromBls(r, currentPhaseN-1, batchID, r.Proof.BlsAggregation))
		gate.verified.Store(true)
		return true
	}

	_ = batchID
	return true
}

func (p *Consensus) finalReply(r *Message) {
	batchID := r.BatchInfo.BatchDigest

	if p.isViewLeader() {
		p.latencyTrackerLock.Lock()
		if tracker, exists := p.latencyTrackers[r.MessageId]; exists && !tracker.Completed {
			if tracker.T4_Completed.IsZero() {
				tracker.T4_Completed = time.Now()
				tracker.Completed = true
				trackerCopy := *tracker
				p.latencyTrackerLock.Unlock()
				go p.outputLatencyBreakdown(&trackerCopy)
			} else {
				p.latencyTrackerLock.Unlock()
			}
		} else {
			p.latencyTrackerLock.Unlock()
		}
	}

	refs, ok := p.RefsCache.Get(r.MessageId)
	if isNoop(r) {
		p.deliverBatch(r.MessageId, nil)
	} else if !ok || len(refs) == 0 {
		log.Printf("[%s] finalReply: cannot get MessageId=%d from RefsCache", p.node.nodeID, r.MessageId)
		return
	} else {
		p.commitOrder.wait(r.MessageId)
		p.deliverBatch(r.MessageId, refs)
	}
	p.RefsCache.Delete(r.MessageId)
	p.RequestsCache.Delete(r.MessageId)

	if p.isViewLeader() {
		p.releaseSemOnce(batchID)
		p.markDecideCompleted(r.MessageId)
	}

	r.MessageType = "reply"
	b, err := GobEncode(r)
	if err != nil {
		log.Printf("[%s] finalReply serialization failed: %v", p.node.nodeID, err)
		return
	}
	if r.MessageId < 8 {
		log.Printf("[MSGSIZE] node=%s mid=%d phase=%d sig=%s kind=decide bytes=%d", p.node.nodeID, r.MessageId, 0, "QC", len(b))
	}
	p.broadcast("Reply", b)

	p.completed.add(batchID)
	p.completed.add(msgKey(r, batchID))
	p.deletePrevProofGates(msgKey(r, batchID))
	go p.cleanupGenericState(msgKey(r, batchID), batchID, r.MessageId)
}

func (p *Consensus) cleanupGenericState(key string, batchID string, messageId int64) {
	p.phase1RsaStates.Delete(key)
	p.phase2RsaStates.Delete(key)
	p.phase3RsaStates.Delete(key)
	p.phase1BlsStates.Delete(key)
	p.phase2BlsStates.Delete(key)
	p.phase3BlsStates.Delete(key)
	p.cleanupConsensusState(batchID, messageId)
}
