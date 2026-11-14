package tusk

import (
	"bytes"
	"crypto/sha256"
	"time"
)

type QCReqMsg struct {
	Round  uint64
	Author string
	Digest []byte
	From   string
}

type QCRespMsg struct {
	Round   uint64
	Author  string
	Digest  []byte
	From    string
	Block   []byte
	Batches []VoteBatchMsg
	Votes   []VoteMsg
}

const qcFetchDelay = 300 * time.Millisecond

func (n *Node) requestMissingQCsLater(block *Block) {
	time.AfterFunc(qcFetchDelay, func() {
		n.lock.Lock()
		var want []QCReqMsg
		for sender, h := range block.PreviousHash {
			if _, ok := n.dag[block.Round-1][sender]; !ok {
				want = append(want, QCReqMsg{Round: block.Round - 1, Author: sender, Digest: h, From: n.name})
			}
		}
		n.lock.Unlock()
		for _, req := range want {
			k := tallyKey(req.Author, req.Round, req.Digest, 'R') + "|qc"
			n.cert.mu.Lock()
			recent := time.Since(n.cert.requested[k]) < qcFetchDelay
			if !recent {
				n.cert.requested[k] = time.Now()
			}
			n.cert.mu.Unlock()
			if recent {
				continue
			}
			if err := n.broadcast(QCReqTag, req); err != nil {
				n.logger.Error("broadcast QC request failed", "round", req.Round, "err", err)
			}
		}
		if len(want) > 0 {
			n.requestMissingQCsLater(block)
		}
	})
}

func (n *Node) handleQCReqMsg(m *QCReqMsg) {
	if m.From == n.name {
		return
	}
	resp, ok := n.qcResponseFor(m)
	if !ok {
		return
	}
	if err := n.sendTo(m.From, QCRespTag, resp); err != nil {
		n.logger.Error("send QC response failed", "to", m.From, "err", err)
	}
}

func (n *Node) qcResponseFor(m *QCReqMsg) (QCRespMsg, bool) {
	k := tallyKey(m.Author, m.Round, m.Digest, 'R')
	n.cert.mu.Lock()
	resp := QCRespMsg{Round: m.Round, Author: m.Author, Digest: m.Digest, From: n.name}
	if b, ok := n.cert.blocks[vkey(m.Author, m.Round)]; ok {
		d := sha256.Sum256(b)
		if bytes.Equal(d[:], m.Digest) {
			resp.Block = b
		}
	}
	for _, b := range n.cert.evBatches[k] {
		resp.Batches = append(resp.Batches, *b)
	}
	for _, v := range n.cert.evVotes[k] {
		resp.Votes = append(resp.Votes, *v)
	}
	enough := len(n.cert.votes[k]) >= n.quorumNum
	n.cert.mu.Unlock()
	return resp, enough
}

func (n *Node) handleQCRespMsg(m *QCRespMsg) {
	if len(m.Block) > 0 {
		d := sha256.Sum256(m.Block)
		if bytes.Equal(d[:], m.Digest) {
			k := vkey(m.Author, m.Round)
			n.cert.mu.Lock()
			var pending *CertMsg
			if _, have := n.cert.blocks[k]; !have {
				n.cert.blocks[k] = m.Block
				pending = n.cert.pendingCerts[k]
			}
			n.cert.mu.Unlock()
			if pending != nil {
				n.tryDeliverCert(pending)
			}
		}
	}
	for i := range m.Batches {
		b := m.Batches[i]
		n.handleVoteBatchMsg(&b)
	}
	for i := range m.Votes {
		v := m.Votes[i]
		if v.CertType == 'R' {
			n.handleVoteMsg(&v)
		}
	}
}
