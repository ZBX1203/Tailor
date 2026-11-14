package main

import (
	"fmt"
	"log"
	pb "merge_consensus/merge_proto"
	"os"
)

var blsOptimistic = os.Getenv("BLS_VERIFY_MODE") == "optimistic"

func (p *Consensus) handleBlsPhase(n int, content []byte) {
	r := new(Message)
	if err := GobDecode(content, r); err != nil {
		log.Printf("[%s] handleBlsPhase(%d) decode failed: %v", p.node.nodeID, n, err)
		return
	}
	if p.completed.has(msgKey(r, r.BatchInfo.BatchDigest)) {
		return
	}
	if !p.admitView(r, phaseCmd(n, "BLS"), content) {
		return
	}
	if !validConfig(r) {
		return
	}
	if !declaredPattern(r, n, "BLS") {
		log.Printf("[%s] phase%d BLS: pattern not declared by configuration %q, rejecting", p.node.nodeID, n, cfgOf(r))
		return
	}
	if n == 1 {
		if isChainBlock(r) && len(r.BatchInfo.Refs) > 0 {
			if !p.chainLinear(r) || !p.chainAbsorbJustify(r) {
				return
			}
			if !p.chainParentReady(r) {
				p.chainStash(r, content)
				return
			}
			if !p.chainOnProposal(r) {
				return
			}
		}
		if !p.admitReproposal(r) {
			return
		}

		if isNoop(r) {
			p.acceptNoop(r)
		} else if !p.ingestBatchRefs(r) {
			return
		}
	} else if !p.verifyPrevPhaseProof(r, n) {
		log.Printf("[%s] phase%d BLS: previous-phase proof verification failed", p.node.nodeID, n)
		return
	} else if declaredPattern(r, n-1, "RSA") && !p.getRsaPhaseState(n-1, msgKey(r, r.BatchInfo.BatchDigest)).transitioned.Load() {

		log.Printf("[%s] phase%d BLS: phase %d all-to-all QC not formed locally, not voting", p.node.nodeID, n, n-1)
		if p.vc != nil {
			prev := p.getRsaPhaseState(n-1, msgKey(r, r.BatchInfo.BatchDigest))
			p.requestQCLater(qcOf(r, n-1, r.BatchInfo.BatchDigest), func() bool { return prev.transitioned.Load() })
		}
		return
	}
	batchID := r.BatchInfo.BatchDigest
	if len(r.Proof.BlsSignatures) == 0 {
		return
	}
	leaderSig := r.Proof.BlsSignatures[0]
	leaderKey, ok := blsKeys[leaderSig.NodeId]
	if !ok {
		log.Printf("[%s] phase%d BLS: BLS public key of leader %s not found", p.node.nodeID, n, leaderSig.NodeId)
		return
	}
	if !leaderKey.Verify(msgPayload(r, n, batchID), leaderSig.Signature) {
		log.Printf("[%s] phase%d BLS: leader partial verification failed", p.node.nodeID, n)
		return
	}
	if r.MessageId < 8 {
		p.phaseTimeLog(r.MessageId, fmt.Sprintf("p%d_verified", n))
	}
	if p.node.nodeID == leaderOf(r.GetView()) {
		return
	}
	r.NodeId = p.node.nodeID
	r.BatchInfo.Requests = nil
	if !voteGuard(p.node.nodeID, r.GetView(), r.MessageId, n, msgKey(r, batchID)) {
		return
	}
	voteID := batchID
	if byzVoteActive(p.node.nodeID) {
		voteID = tamperDigest(batchID)
	}
	blsSig := p.node.blsKey.Sign(msgPayload(r, n, voteID))
	r.Sigrsa = nil
	r.Proof.BlsSignatures = []*pb.SigEntry{
		{NodeId: p.node.nodeID, Signature: blsSig},
	}
	if r.MessageId < 8 {
		p.phaseTimeLog(r.MessageId, fmt.Sprintf("p%d_signed", n))
	}
	b, err := GobEncode(r)
	if err == nil && r.MessageId < 8 {
		log.Printf("[MSGSIZE] node=%s mid=%d phase=%d sig=BLS kind=vote bytes=%d", p.node.nodeID, r.MessageId, n, len(b))
	}
	if err != nil {
		log.Printf("[%s] handleBlsPhase(%d) serialization failed: %v", p.node.nodeID, n, err)
		return
	}
	cmd := blsAggCmd(n)
	p.sendToNode(leaderOf(r.GetView()), cmd, b)
	if r.MessageId < 8 {
		p.phaseTimeLog(r.MessageId, fmt.Sprintf("p%d_sent", n))
	}
}

func (p *Consensus) handleBlsAgg(n int, content []byte) {
	r := new(Message)
	if err := GobDecode(content, r); err != nil {
		log.Printf("[%s] handleBlsAgg(%d) decode failed: %v", p.node.nodeID, n, err)
		return
	}
	if !p.admitView(r, blsAggCmd(n), content) {
		return
	}
	p.processBlsAgg(n, r)
}

func (p *Consensus) processBlsAgg(phaseN int, r *Message) {
	batchID := r.BatchInfo.BatchDigest
	if !validConfig(r) || !declaredPattern(r, phaseN, "BLS") {
		return
	}
	pl := msgPayload(r, phaseN, batchID)
	if len(r.Proof.BlsSignatures) == 0 {
		return
	}
	replicaSig := r.Proof.BlsSignatures[0]
	if p.completed.has(msgKey(r, batchID)) {
		return
	}
	if r.MessageId < 8 {
		p.phaseTimeLog(r.MessageId, fmt.Sprintf("p%d_partial_from_%s", phaseN, replicaSig.NodeId))
	}

	state := p.getBlsPhaseState(phaseN, msgKey(r, batchID))
	if state.done.Load() {
		return
	}
	if _, dup := state.sigs.Load(replicaSig.NodeId); dup {
		return
	}

	pt, err := DecodeBLSPoint(replicaSig.Signature)
	if err != nil {
		log.Printf("[%s] phase%d BLS agg: failed to decode signature of %s: %v", p.node.nodeID, phaseN, replicaSig.NodeId, err)
		return
	}
	replicaKey, ok := blsKeys[replicaSig.NodeId]
	if !ok {
		log.Printf("[%s] phase%d BLS agg: public key of %s not found", p.node.nodeID, phaseN, replicaSig.NodeId)
		return
	}

	if !blsOptimistic && !replicaKey.VerifyPoint(pl, pt) {
		log.Printf("[%s] phase%d BLS agg: %s partial verification failed", p.node.nodeID, phaseN, replicaSig.NodeId)
		return
	}
	if _, existed := state.sigs.LoadOrStore(replicaSig.NodeId, blsSignature{NodeID: replicaSig.NodeId, Sig: pt}); !existed {
		state.count.Add(1)
	}
	count := int(state.count.Load())
	if r.MessageId < 8 {
		p.phaseTimeLog(r.MessageId, fmt.Sprintf("p%d_pstored_%s", phaseN, replicaSig.NodeId))
		if count == 1 {
			p.phaseTimeLog(r.MessageId, fmt.Sprintf("p%d_first", phaseN))
		}
	}
	if count < Threshold {
		return
	}
	if !state.aggregated.CompareAndSwap(false, true) {
		return
	}
	if r.MessageId < 8 {
		p.phaseTimeLog(r.MessageId, fmt.Sprintf("p%d_quorum", phaseN))
	}

	var participants []string
	var sigStructs []blsSignature
	state.sigs.Range(func(k, v interface{}) bool {
		participants = append(participants, k.(string))
		sigStructs = append(sigStructs, v.(blsSignature))
		return true
	})
	aggSig := p.node.blsKey.AggregateSigs(sigStructs)
	if blsOptimistic && !VerifyWithPreAggregatedKey(participants, pl, aggSig) {

		var good []blsSignature
		var goodIDs []string
		for _, sg := range sigStructs {
			if k, ok := blsKeys[sg.NodeID]; ok && k.VerifyPoint(pl, sg.Sig) {
				good = append(good, sg)
				goodIDs = append(goodIDs, sg.NodeID)
			} else {
				log.Printf("[%s] phase%d BLS agg (optimistic fallback): %s partial invalid, removed", p.node.nodeID, phaseN, sg.NodeID)
				state.sigs.Delete(sg.NodeID)
				state.count.Add(-1)
			}
		}
		if len(good) < Threshold {
			state.aggregated.Store(false)

			if int(state.count.Load()) >= Threshold && state.aggregated.CompareAndSwap(false, true) {
				participants, sigStructs = nil, nil
				state.sigs.Range(func(k, v interface{}) bool {
					participants = append(participants, k.(string))
					sigStructs = append(sigStructs, v.(blsSignature))
					return true
				})
				aggSig = p.node.blsKey.AggregateSigs(sigStructs)
				if !VerifyWithPreAggregatedKey(participants, pl, aggSig) {
					state.aggregated.Store(false)
					return
				}
			} else {
				return
			}
		} else {
			participants, sigStructs = goodIDs, good
			aggSig = p.node.blsKey.AggregateSigs(sigStructs)
		}
	}
	state.done.Store(true)
	p.vcRecordQC(qcFromBls(r, phaseN, batchID, &pb.BLSAggregation{AggregatedSig: aggSig, Participants: participants}))
	if r.MessageId < 8 {
		p.phaseTimeLog(r.MessageId, fmt.Sprintf("p%d_aggdone", phaseN))
	}
	r.Proof.BlsSignatures = nil
	r.Proof.RsaSignatures = nil
	if r.Proof.BlsAggregation == nil {
		r.Proof.BlsAggregation = &pb.BLSAggregation{}
	}
	r.Proof.BlsAggregation.AggregatedSig = aggSig
	r.Proof.BlsAggregation.Participants = participants

	if phaseN == 1 && isChainBlock(r) {
		p.chainOnQC(r, aggSig, participants)
		return
	}
	p.transitionToNextPhase(phaseN, r)
}

func (p *Consensus) verifyBlsAggregation(r *Message, phase int) bool {
	if !declaredPattern(r, phase, "BLS") {
		return false
	}
	if r == nil || r.BatchInfo == nil || r.Proof == nil || r.Proof.BlsAggregation == nil ||
		len(r.Proof.BlsAggregation.AggregatedSig) == 0 ||
		len(r.Proof.BlsAggregation.Participants) < Threshold {
		return false
	}
	aggSig, err := NewSignatureFromBytes(r.Proof.BlsAggregation.AggregatedSig)
	if err != nil {
		return false
	}
	return VerifyWithPreAggregatedKey(
		r.Proof.BlsAggregation.Participants,
		msgPayload(r, phase, r.BatchInfo.BatchDigest),
		aggSig,
	)
}
