package tusk

import (
	"os"
	"sync"
	"time"
)

type VoteBatchMsg struct {
	Round   uint64
	Voter   string
	Authors []string
	Digests [][]byte
	Sig     []byte
}

func batchPayload(round uint64, voter string, authors []string, digests [][]byte) []byte {
	out := make([]byte, 0, 34+len(voter)+len(authors)*48)
	out = append(out, "dagvoteb|R|"...)
	out = append(out, voter...)
	out = append(out, '|')
	for i := 0; i < 8; i++ {
		out = append(out, byte(round>>(8*(7-i))))
	}
	for i := range authors {
		out = append(out, '|')
		out = append(out, authors[i]...)
		out = append(out, ':')
		out = append(out, digests[i]...)
	}
	return out
}

type rBatcher struct {
	mu         sync.Mutex
	pending    map[uint64]*VoteBatchMsg
	first      map[uint64]time.Time
	voted      map[uint64]int
	quorumSent map[uint64]bool
	maxRound   uint64
	every      time.Duration
	maxWait    time.Duration
}

func rBatchEnabled() bool { return os.Getenv("DAG_R_BATCH") == "1" }

func (n *Node) startRBatcher(stop <-chan struct{}) {
	if n.rb == nil {
		return
	}
	t := time.NewTicker(n.rb.every)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			n.flushRBatches(false)
		}
	}
}

func (n *Node) queueRVote(round uint64, author string, digest []byte) {
	n.rb.mu.Lock()
	m := n.rb.pending[round]
	if m == nil {
		m = &VoteBatchMsg{Round: round, Voter: n.name}
		n.rb.pending[round] = m
		n.rb.first[round] = time.Now()
	}
	m.Authors = append(m.Authors, author)
	m.Digests = append(m.Digests, digest)
	n.rb.voted[round]++
	if round > n.rb.maxRound {
		n.rb.maxRound = round
	}
	flush := n.rBatchDue(round)
	if flush {
		n.rb.quorumSent[round] = true
		delete(n.rb.pending, round)
		delete(n.rb.first, round)
	}
	n.rb.mu.Unlock()
	if flush {
		n.sendRBatch(m)
	}
}

func (n *Node) rBatchDue(round uint64) bool {
	return (!n.rb.quorumSent[round] && n.rb.voted[round] >= n.quorumNum) || n.rb.voted[round] >= n.nodeNum
}

func (n *Node) noteBVote(round uint64) {
	n.rb.mu.Lock()
	n.rb.voted[round]++
	if round > n.rb.maxRound {
		n.rb.maxRound = round
	}
	m := n.rb.pending[round]
	flush := m != nil && n.rBatchDue(round)
	if flush {
		n.rb.quorumSent[round] = true
		delete(n.rb.pending, round)
		delete(n.rb.first, round)
	}
	n.rb.mu.Unlock()
	if flush {
		n.sendRBatch(m)
	}
}

func (n *Node) flushRBatches(_ bool) {
	now := time.Now()
	n.rb.mu.Lock()
	var out []*VoteBatchMsg
	for r, m := range n.rb.pending {
		if now.Sub(n.rb.first[r]) >= n.rb.maxWait {
			out = append(out, m)
			delete(n.rb.pending, r)
			delete(n.rb.first, r)
		}
	}
	for r := range n.rb.voted {
		_, live := n.rb.pending[r]

		if !live && (n.rb.voted[r] >= n.nodeNum || r+200 < n.rb.maxRound) {
			delete(n.rb.voted, r)
			delete(n.rb.quorumSent, r)
		}
	}
	n.rb.mu.Unlock()
	for _, m := range out {
		n.sendRBatch(m)
	}
}

func (n *Node) flushRBatchesUpTo(round uint64) {
	n.rb.mu.Lock()
	var out []*VoteBatchMsg
	for r, m := range n.rb.pending {
		if r <= round {
			out = append(out, m)
			delete(n.rb.pending, r)
			delete(n.rb.first, r)
		}
	}
	n.rb.mu.Unlock()
	for _, m := range out {
		n.sendRBatch(m)
	}
}

func (n *Node) sendRBatch(m *VoteBatchMsg) {
	payload := batchPayload(m.Round, m.Voter, m.Authors, m.Digests)
	if n.byzVoteNow(m.Round) {
		payload = tamperPayload(payload)
	}
	sig, err := n.schemeFor(true).Sign(payload)
	if err != nil {
		n.logger.Error("sign vote batch failed", "err", err)
		return
	}
	m.Sig = sig
	n.rbatchSent.Add(1)
	n.rbatchVotes.Add(int64(len(m.Authors)))
	if err := n.broadcast(VoteBatchTag, *m); err != nil {
		n.logger.Error("broadcast vote batch failed", "round", m.Round, "err", err)
	}
}

func (n *Node) handleVoteBatchMsg(m *VoteBatchMsg) {

	if n.certTypes == "" || len(m.Authors) != len(m.Digests) || len(m.Authors) == 0 {
		return
	}
	if !n.schemeFor(true).VerifyOne(m.Voter, batchPayload(m.Round, m.Voter, m.Authors, m.Digests), m.Sig) {
		n.logger.Error("invalid vote batch signature", "voter", m.Voter, "round", m.Round)
		return
	}
	for i, author := range m.Authors {
		if n.recordVote(m.Round, author, m.Voter, m.Digests[i], m.Sig, m) {
			n.tryDeliverCert(&CertMsg{Round: m.Round, Author: author, Digest: m.Digests[i], CertType: 'R'})
		}
	}
}
