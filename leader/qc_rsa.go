package main

import (
	"encoding/hex"
	"fmt"
	"log"
	pb "merge_consensus/merge_proto"
	"time"

	"google.golang.org/protobuf/proto"
)

func (p *Consensus) handleRsaPhase(n int, content []byte) {
	r := new(Message)
	if err := GobDecode(content, r); err != nil {
		log.Printf("[%s] handleRsaPhase(%d) decode failed: %v", p.node.nodeID, n, err)
		return
	}
	if !declaredPattern(r, n, "RSA") {
		log.Printf("[%s] phase%d RSA: pattern not declared by configuration %q, rejecting", p.node.nodeID, n, cfgOf(r))
		return
	}
	if !p.admitView(r, phaseCmd(n, "RSA"), content) {
		return
	}
	if !validConfig(r) {
		return
	}
	if n == 1 && isNoop(r) && senderIsLeader(r) {
		if !p.admitReproposal(r) {
			return
		}
		p.acceptNoop(r)
	}
	if n == 1 && len(r.BatchInfo.Refs) > 0 {
		if !p.admitReproposal(r) {
			return
		}
		if isChainBlock(r) {
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
		if !p.ingestBatchRefs(r) {
			return
		}
	}
	p.processRsaPhase(n, r)
}

func (p *Consensus) processRsaPhase(phaseN int, r *Message) {
	batchID := r.BatchInfo.BatchDigest

	if p.completed.has(msgKey(r, batchID)) {
		return
	}

	key := msgKey(r, batchID)
	state := p.getRsaPhaseState(phaseN, key)
	if state.transitioned.Load() {
		return
	}

	digestByte, err := hex.DecodeString(batchID)
	if err != nil {
		log.Printf("[%s] processRsaPhase: batchID decode failed: %v", p.node.nodeID, err)
		return
	}

	var replayed []pendingRsaVote
	if phaseN > 1 {
		prevSig := r.PhaseConfig[fmt.Sprintf("phase%d", phaseN-1)]
		if prevSig == "BLS" {
			ready, votes := p.authorizeBlsToRsa(r, phaseN, digestByte)
			if !ready {
				if senderIsLeader(r) {
					log.Printf("[%s] phase%d RSA: leader previous-phase BLS QC verification failed",
						p.node.nodeID, phaseN)
				}
				return
			}
			replayed = votes
		} else if !p.verifyPrevPhaseProof(r, phaseN) {
			log.Printf("[%s] phase%d RSA: previous-phase proof verification failed", p.node.nodeID, phaseN)
			return
		}
	}

	for _, vote := range replayed {
		if _, existed := state.sigs.LoadOrStore(vote.nodeID, vote.signature); !existed {
			state.count.Add(1)
		}
	}

	if r.Proof != nil {
		for _, sigInfo := range r.Proof.RsaSignatures {
			if sigInfo == nil {
				continue
			}
			if _, existed := state.sigs.Load(sigInfo.NodeId); existed {
				continue
			}
			if !p.RsaVerifyCached(msgPayload(r, phaseN, batchID), sigInfo.Signature, sigInfo.NodeId) {
				log.Printf("[%s] phase%d RSA: signature from %s failed verification", p.node.nodeID, phaseN, sigInfo.NodeId)
				continue
			}
			if _, existed := state.sigs.LoadOrStore(sigInfo.NodeId, sigInfo.Signature); !existed {
				state.count.Add(1)
			}
		}
	}

	if phaseN > 1 && r.PhaseConfig[fmt.Sprintf("phase%d", phaseN-1)] == "RSA" &&
		!p.getRsaPhaseState(phaseN-1, key).transitioned.Load() {
		prev := p.getRsaPhaseState(phaseN-1, key)
		p.requestQCLater(qcOf(r, phaseN-1, batchID), func() bool { return prev.transitioned.Load() || p.completed.has(key) })
		return
	}

	canVote := phaseN != 1 || !isChainBlock(r) || p.chainParentReady(r)

	if canVote && !state.echoed.Load() && voteGuard(p.node.nodeID, r.GetView(), r.MessageId, phaseN, key) && state.echoed.CompareAndSwap(false, true) {
		echoID := batchID
		if byzVoteActive(p.node.nodeID) {
			echoID = tamperDigest(batchID)
		}
		mySig := p.RsaSignWithSha256(msgPayload(r, phaseN, echoID), p.node.rsaPrivKey)
		if _, existed := state.sigs.LoadOrStore(p.node.nodeID, mySig); !existed {
			state.count.Add(1)
		}

		echoMsg := proto.Clone(r).(*Message)
		echoMsg.NodeId = p.node.nodeID
		echoMsg.Proof.RsaSignatures = []*pb.SigEntry{
			{NodeId: p.node.nodeID, Signature: mySig},
		}

		echoMsg.Proof.BlsAggregation = nil
		echoMsg.Proof.BlsSignatures = nil
		echoMsg.BatchInfo.Requests = nil
		echoMsg.BatchInfo.Refs = nil
		b, err := GobEncode(echoMsg)
		if err == nil {
			cmd := phaseCmd(phaseN, "RSA")
			if echoMsg.MessageId < 8 {
				log.Printf("[MSGSIZE] node=%s mid=%d phase=%d sig=RSA kind=vote bytes=%d", p.node.nodeID, echoMsg.MessageId, phaseN, len(b))
			}
			p.broadcast(command(cmd), b)
		}
	}

	count := int(state.count.Load())
	if count < Threshold {
		return
	}
	if !state.transitioned.CompareAndSwap(false, true) {
		return
	}

	var sigs []*pb.SigEntry
	state.sigs.Range(func(k, v interface{}) bool {
		sigs = append(sigs, &pb.SigEntry{NodeId: k.(string), Signature: v.([]byte)})
		return true
	})
	if r.Proof == nil {
		r.Proof = &pb.Proof{}
	}
	r.Proof.RsaSignatures = sigs
	r.Proof.BlsAggregation = nil
	r.Proof.BlsSignatures = nil
	p.vcRecordQC(qcFromRsa(r, phaseN, batchID, sigs))

	p.advanceAfterRSA(phaseN, r)
}

func (p *Consensus) advanceAfterRSA(n int, msg *Message) {
	if n == 1 && isChainBlock(msg) {
		p.chainOnQC(msg, nil, nil)
		return
	}
	if msg.BatchInfo != nil {
		msg.BatchInfo.Requests = nil
	}
	batchID := msg.BatchInfo.BatchDigest

	if p.isViewLeader() && n < phaseCountOf(msg) {
		p.latencyTrackerLock.Lock()
		if tracker, exists := p.latencyTrackers[msg.MessageId]; exists {
			switch n + 1 {
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

	if n >= phaseCountOf(msg) {
		p.finalizeLocal(msg)
		return
	}

	nextN := n + 1
	nextSig := msg.PhaseConfig[fmt.Sprintf("phase%d", nextN)]
	msg.NodeId = p.node.nodeID
	switch nextN {
	case 2:
		msg.MessageType = "commit"
	case 3:
		msg.MessageType = "decide"
	}

	if nextSig == "RSA" {

		if _, err := hex.DecodeString(batchID); err != nil {
			log.Printf("[%s] advanceAfterRSA: batchID decode failed: %v", p.node.nodeID, err)
			return
		}
		if !voteGuard(p.node.nodeID, msg.GetView(), msg.MessageId, nextN, msgKey(msg, batchID)) {
			return
		}
		nextID := batchID
		if byzVoteActive(p.node.nodeID) {
			nextID = tamperDigest(batchID)
		}
		mySig := p.RsaSignWithSha256(msgPayload(msg, nextN, nextID), p.node.rsaPrivKey)
		msg.Proof.RsaSignatures = []*pb.SigEntry{
			{NodeId: p.node.nodeID, Signature: mySig},
		}
		msg.Proof.BlsSignatures = nil
		st := p.getRsaPhaseState(nextN, msgKey(msg, batchID))
		if _, existed := st.sigs.LoadOrStore(p.node.nodeID, mySig); !existed {
			st.count.Add(1)
		}
		st.echoed.Store(true)
		b, err := GobEncode(msg)
		if err != nil {
			log.Printf("[%s] advanceAfterRSA serialization failed: %v", p.node.nodeID, err)
			return
		}
		if msg.MessageId < 8 {
			log.Printf("[MSGSIZE] node=%s mid=%d phase=%d sig=RSA kind=vote bytes=%d", p.node.nodeID, msg.MessageId, nextN, len(b))
		}
		p.broadcast(command(phaseCmd(nextN, "RSA")), b)

		if int(st.count.Load()) >= Threshold && st.transitioned.CompareAndSwap(false, true) {
			p.advanceAfterRSA(nextN, msg)
		}
		return
	}

	if !voteGuard(p.node.nodeID, msg.GetView(), msg.MessageId, nextN, msgKey(msg, batchID)) {
		return
	}
	bID := batchID
	if byzVoteActive(p.node.nodeID) {
		bID = tamperDigest(batchID)
	}
	mySig := p.node.blsKey.Sign(msgPayload(msg, nextN, bID))
	if p.node.nodeID == leaderOf(msg.GetView()) {

		self := &Message{
			MessageType: msg.MessageType, NodeId: p.node.nodeID, MessageId: msg.MessageId, PhaseConfig: msg.PhaseConfig, View: msg.GetView(),
			BatchInfo: &pb.BatchInfo{BatchDigest: batchID},
			Proof:     &pb.Proof{BlsSignatures: []*pb.SigEntry{{NodeId: p.node.nodeID, Signature: mySig}}},
		}
		p.processBlsAgg(nextN, self)
		return
	}
	st := p.getBlsPhaseState(nextN, msgKey(msg, batchID))
	if pt, err := DecodeBLSPoint(mySig); err == nil {
		if _, existed := st.sigs.LoadOrStore(p.node.nodeID, blsSignature{NodeID: p.node.nodeID, Sig: pt}); !existed {
			st.count.Add(1)
		}
	}
	out := &Message{
		MessageType: msg.MessageType,
		NodeId:      p.node.nodeID,
		MessageId:   msg.MessageId,
		PhaseConfig: msg.PhaseConfig,
		View:        msg.GetView(),
		BatchInfo:   &pb.BatchInfo{BatchDigest: batchID},
		Proof: &pb.Proof{
			BlsSignatures: []*pb.SigEntry{
				{NodeId: p.node.nodeID, Signature: mySig},
			},
		},
	}
	b, err := GobEncode(out)
	if err == nil && msg.MessageId < 8 {
		log.Printf("[MSGSIZE] node=%s mid=%d phase=%d sig=BLS kind=vote bytes=%d", p.node.nodeID, msg.MessageId, nextN, len(b))
	}
	if err != nil {
		log.Printf("[%s] advanceAfterRSA(BLS) serialization failed: %v", p.node.nodeID, err)
		return
	}
	cmd := blsAggCmd(nextN)
	p.sendToNode(leaderOf(msg.GetView()), cmd, b)
}
