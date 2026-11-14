package tusk

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sync"
	"time"

	"merge_consensus/dag/certsign"
	"merge_consensus/dag/conn"
	"merge_consensus/dag/sign"
)

type ProposeMsg struct {
	Round      uint64
	Sender     string
	BlockBytes []byte
	CertType   byte
}

type VoteMsg struct {
	Round    uint64
	Author   string
	Voter    string
	Digest   []byte
	CertType byte
	Sig      []byte
}

type CertMsg struct {
	Round    uint64
	Author   string
	Digest   []byte
	CertType byte
	Signers  []string
	Cert     []byte
}

func certPayload(round uint64, author string, digest []byte, ctype byte) []byte {
	out := make([]byte, 0, 34+len(author)+len(digest))
	out = append(out, "dagcert|"...)
	out = append(out, author...)
	out = append(out, '|')
	var r [8]byte
	for i := 0; i < 8; i++ {
		r[i] = byte(round >> (8 * (7 - i)))
	}
	out = append(out, r[:]...)
	out = append(out, '|')
	out = append(out, digest...)
	out = append(out, '|', ctype)
	return out
}

type certState struct {
	mu sync.Mutex

	blocks map[string][]byte

	votes map[string]map[string][]byte

	pendingCerts map[string]*CertMsg

	delivered map[string]bool

	voted map[string][]byte

	requested map[string]time.Time

	waitParents map[uint64][]parentWait

	evBatches map[string][]*VoteBatchMsg
	evVotes   map[string][]*VoteMsg
}

type parentWait struct {
	m      *ProposeMsg
	digest []byte
}

func newCertState() *certState {
	return &certState{
		blocks:       map[string][]byte{},
		votes:        map[string]map[string][]byte{},
		pendingCerts: map[string]*CertMsg{},
		delivered:    map[string]bool{},
		voted:        map[string][]byte{},
		requested:    map[string]time.Time{},
		waitParents:  map[uint64][]parentWait{},
		evBatches:    map[string][]*VoteBatchMsg{},
		evVotes:      map[string][]*VoteMsg{},
	}
}

const maxRefSpan = 1 << 22

func (r ClientRange) wellFormed() bool { return r.Lo <= r.Hi && r.Hi-r.Lo < maxRefSpan }

func tallyKey(author string, round uint64, digest []byte, ctype byte) string {
	return vkey(author, round) + "|" + hex.EncodeToString(digest) + "|" + string(ctype)
}

func vkey(author string, round uint64) string {
	return author + "|" + hex.EncodeToString([]byte{byte(round), byte(round >> 8), byte(round >> 16), byte(round >> 24)})
}

func (n *Node) broadcastBlockCert(round uint64) {
	previousHash := n.selectPreviousBlocks(round - 1)
	n.vt.ev('P', round, n.name, len(previousHash))
	block := n.newBlock(round, previousHash)
	blockAsBytes, err := encode(block)
	if err != nil {
		panic(err)
	}
	ctype := n.proposeType(round)
	msg := ProposeMsg{Round: round, Sender: n.name, BlockBytes: blockAsBytes, CertType: ctype}
	if n.byzProposeNow(round) && len(block.Refs) > 0 {

		evilBlock := *block
		evilRefs := append([]ClientRange(nil), block.Refs...)
		d := append([]byte(nil), evilRefs[0].Digest...)
		if len(d) == 0 {
			d = []byte{0}
		}
		d[0] ^= 0xff
		evilRefs[0].Digest = d
		evilBlock.Refs = evilRefs
		evilBytes, err := encode(&evilBlock)
		if err == nil {
			evilMsg := ProposeMsg{Round: round, Sender: n.name, BlockBytes: evilBytes, CertType: ctype}
			for target := range n.clusterAddr {
				if target == n.name {
					continue
				}
				m := msg
				if byzVictims[target] {
					m = evilMsg
				}
				if err := n.sendTo(target, ProposeTag, m); err != nil {
					n.logger.Error("byz propose send failed", "to", target, "round", round, "err", err)
				}
			}
			return
		}
	}
	if err := n.broadcast(ProposeTag, msg); err != nil {
		n.logger.Error("broadcast propose failed", "round", round, "err", err)
	}
}

func (n *Node) handleProposeMsg(m *ProposeMsg) {
	n.vt.ev('R', m.Round, m.Sender, 0)
	digest := sha256.Sum256(m.BlockBytes)
	k := vkey(m.Sender, m.Round)

	n.cert.mu.Lock()
	if prev, ok := n.cert.voted[k]; ok && hex.EncodeToString(prev) != hex.EncodeToString(digest[:]) {
		n.cert.mu.Unlock()
		n.logger.Error("equivocating author: a second block for the same slot is not voted on",
			"author", m.Sender, "round", m.Round)
		return
	}
	already := n.cert.voted[k] != nil
	n.cert.blocks[k] = m.BlockBytes
	n.cert.voted[k] = digest[:]
	pending := n.cert.pendingCerts[k]
	n.cert.mu.Unlock()

	if pending != nil {
		n.tryDeliverCert(pending)
	}
	if already {
		return
	}
	n.voteAfterParents(m, digest[:])
}

type parentStatus int

const (
	parentsOK parentStatus = iota
	parentsMissing
	parentsBad
)

func (n *Node) parentsCertifiedLocked(block *Block) parentStatus {
	if block.Round <= 1 {
		if len(block.PreviousHash) != 0 {
			return parentsBad
		}
		return parentsOK
	}
	if len(block.PreviousHash) < n.quorumNum {
		return parentsBad
	}
	st := parentsOK
	for sender, h := range block.PreviousHash {
		parent, ok := n.dag[block.Round-1][sender]
		if !ok {
			st = parentsMissing
			continue
		}
		ph, err := parent.getHash()
		if err != nil || !bytes.Equal(ph, h) {
			return parentsBad
		}
	}
	for _, w := range block.WeakLinks {
		if w.Round+2 > block.Round {
			return parentsBad
		}
		parent, ok := n.dag[w.Round][w.Sender]
		if !ok {
			st = parentsMissing
			continue
		}
		ph, err := parent.getHash()
		if err != nil || !bytes.Equal(ph, w.Hash) {
			return parentsBad
		}
	}
	return st
}

func (n *Node) voteAfterParents(m *ProposeMsg, digest []byte) {
	block := new(Block)
	if err := decode(m.BlockBytes, block); err != nil || block.Round != m.Round || block.Sender != m.Sender {
		n.logger.Error("proposal does not match its position; not voting", "author", m.Sender, "round", m.Round)
		return
	}
	for _, r := range block.Refs {
		if !r.wellFormed() {
			n.logger.Error("proposal carries a malformed reference; not voting", "author", m.Sender, "round", m.Round)
			return
		}
	}
	n.lock.Lock()
	st := n.parentsCertifiedLocked(block)
	if st == parentsMissing {
		n.cert.mu.Lock()
		n.cert.waitParents[m.Round] = append(n.cert.waitParents[m.Round], parentWait{m: m, digest: digest})
		n.cert.mu.Unlock()
	}
	n.lock.Unlock()
	switch st {
	case parentsBad:
		n.logger.Error("proposal references are invalid; not voting", "author", m.Sender, "round", m.Round)
		return
	case parentsMissing:
		n.requestMissingQCsLater(block)
		return
	}
	n.voteOnProposal(m, digest)
}

func (n *Node) retryParentWaits(r uint64) {
	n.cert.mu.Lock()
	var ready []parentWait
	for round, ws := range n.cert.waitParents {
		if round > r {
			ready = append(ready, ws...)
			delete(n.cert.waitParents, round)
		}
	}
	n.cert.mu.Unlock()
	for _, w := range ready {
		n.voteAfterParents(w.m, w.digest)
	}
}

func (n *Node) voteOnProposal(m *ProposeMsg, digest []byte) {

	if m.Sender != n.name {
		if ok, refs := n.refsAvailable(m.BlockBytes); !ok {
			n.refWaits.Add(1)
			go n.voteWhenAvailable(m, digest, refs)
			return
		}
	}
	n.castVote(m, digest)
}

func (n *Node) castVote(m *ProposeMsg, digest []byte) {
	if (m.CertType != 'R' && m.CertType != 'B') || (m.CertType == 'R' && n.certTypes == "") {
		return
	}
	allToAll := n.voteAllToAll(m)
	if n.rb != nil && allToAll {
		n.queueRVote(m.Round, m.Sender, digest)
		return
	}
	payload := certPayload(m.Round, m.Sender, digest, m.CertType)
	if n.byzVoteNow(m.Round) {
		payload = tamperPayload(payload)
	}
	sig, err := n.schemeFor(allToAll).Sign(payload)
	if err != nil {
		n.logger.Error("sign vote failed", "err", err)
		return
	}
	vote := VoteMsg{Round: m.Round, Author: m.Sender, Voter: n.name, Digest: digest, CertType: m.CertType, Sig: sig}
	if allToAll {

		if err := n.broadcast(VoteTag, vote); err != nil {
			n.logger.Error("broadcast vote failed", "round", m.Round, "err", err)
		}
		return
	}

	if err := n.sendTo(m.Sender, VoteTag, vote); err != nil {
		n.logger.Error("send vote failed", "to", m.Sender, "err", err)
	}
	if n.rb != nil {
		n.noteBVote(m.Round)
	}
}

func (n *Node) handleVoteMsg(m *VoteMsg) {

	if m.CertType != 'R' && m.CertType != 'B' {
		return
	}
	allToAll := m.CertType == 'R'
	if allToAll && n.certTypes == "" {
		return
	}
	if !allToAll && m.Author != n.name {
		return
	}
	payload := certPayload(m.Round, m.Author, m.Digest, m.CertType)
	if !n.schemeFor(allToAll).VerifyOne(m.Voter, payload, m.Sig) {
		n.logger.Error("invalid vote signature", "voter", m.Voter, "round", m.Round)
		return
	}
	k := tallyKey(m.Author, m.Round, m.Digest, m.CertType)
	n.cert.mu.Lock()
	if n.cert.votes[k] == nil {
		n.cert.votes[k] = map[string][]byte{}
	}
	if _, dup := n.cert.votes[k][m.Voter]; dup {
		n.cert.mu.Unlock()
		return
	}
	n.cert.votes[k][m.Voter] = m.Sig
	if allToAll {
		n.cert.evVotes[k] = append(n.cert.evVotes[k], m)
	}
	enough := len(n.cert.votes[k]) == n.quorumNum
	if enough && m.Author == n.name {
		n.vt.ev('C', m.Round, m.Author, 0)
	}
	var snapshot map[string][]byte
	if enough && !allToAll {
		snapshot = make(map[string][]byte, len(n.cert.votes[k]))
		for kk, v := range n.cert.votes[k] {
			snapshot[kk] = v
		}
	}
	n.cert.mu.Unlock()
	if !enough {
		return
	}

	if allToAll {

		n.tryDeliverCert(&CertMsg{Round: m.Round, Author: m.Author, Digest: m.Digest, CertType: 'R'})
		return
	}

	payload = certPayload(m.Round, n.name, m.Digest, 'B')
	signers, cert, err := n.schemeFor(false).MakeCert(payload, snapshot)
	if err != nil {
		n.logger.Error("make certificate failed", "round", m.Round, "err", err)
		return
	}
	cm := CertMsg{Round: m.Round, Author: n.name, Digest: m.Digest, CertType: 'B', Signers: signers, Cert: cert}
	if err := n.broadcast(CertTag, cm); err != nil {
		n.logger.Error("broadcast certificate failed", "round", m.Round, "err", err)
	}
}

func (n *Node) handleCertMsg(m *CertMsg) {
	if m.CertType != 'B' {
		return
	}
	if len(m.Signers) < n.quorumNum {
		n.logger.Error("certificate below quorum", "author", m.Author, "round", m.Round,
			"signers", len(m.Signers), "need", n.quorumNum)
		return
	}
	payload := certPayload(m.Round, m.Author, m.Digest, 'B')
	if !n.schemeFor(false).VerifyCert(m.Signers, payload, m.Cert) {
		n.logger.Error("invalid certificate", "author", m.Author, "round", m.Round)
		return
	}
	n.tryDeliverCert(m)
}

func (n *Node) tryDeliverCert(m *CertMsg) {
	k := vkey(m.Author, m.Round)
	n.cert.mu.Lock()
	blockBytes, haveBlock := n.cert.blocks[k]
	if !haveBlock {
		n.cert.pendingCerts[k] = m
		n.cert.mu.Unlock()
		n.scheduleFetch(m)
		return
	}
	if n.cert.delivered[k] {
		n.cert.mu.Unlock()
		return
	}
	digest := sha256.Sum256(blockBytes)
	if hex.EncodeToString(digest[:]) != hex.EncodeToString(m.Digest) {

		n.cert.pendingCerts[k] = m
		n.cert.mu.Unlock()
		n.logger.Error("certificate digest does not match the block we hold; fetching",
			"author", m.Author, "round", m.Round)
		n.requestBlock(m)
		return
	}
	n.cert.delivered[k] = true
	delete(n.cert.pendingCerts, k)
	n.cert.mu.Unlock()
	n.vt.ev('X', m.Round, m.Author, 0)

	block := new(Block)
	if err := decode(blockBytes, block); err != nil {
		n.logger.Error("certified block does not decode", "author", m.Author, "round", m.Round)
		return
	}
	n.handleNewBlockMsg(block)
}

func (n *Node) sendTo(target string, msgType uint8, msg interface{}) error {
	msgAsBytes, err := encode(msg)
	if err != nil {
		return err
	}
	sig := sign.SignEd25519(n.privateKey, msgAsBytes)
	addrWithPort := n.clusterAddr[target] + ":" + itoa(n.clusterPort[target])
	netConn, err := n.trans.GetConn(addrWithPort)
	if err != nil {
		return err
	}
	if err = conn.SendMsg(netConn, msgType, msg, sig); err != nil {
		return err
	}
	return n.trans.ReturnConn(netConn)
}

func (n *Node) InitCertifier(mode, keyDir string, pubKeys map[string][]byte) error {
	nodes := make([]string, 0, len(n.clusterAddr))
	for name := range n.clusterAddr {
		nodes = append(nodes, name)
	}

	if t := os.Getenv("DAG_TYPES"); t != "" {
		for i := 0; i < len(t); i++ {
			if t[i] != 'R' && t[i] != 'B' {
				return fmt.Errorf("DAG_TYPES may only contain R/B, got %q", t)
			}
		}
		r, err := certsign.New("rsa", n.name, nodes, n.privateKey, n.publicKeyMap, keyDir)
		if err != nil {
			return fmt.Errorf("build RSA scheme: %w", err)
		}
		b, err := certsign.New("bls", n.name, nodes, n.privateKey, n.publicKeyMap, keyDir)
		if err != nil {
			return fmt.Errorf("build BLS scheme: %w", err)
		}
		n.certTypes, n.schemeR, n.schemeB = t, r, b
		n.certScheme = b
		n.cert = newCertState()
		if s := os.Getenv("DAG_SWITCH_SCHEDULE"); s != "" {
			if n.rb == nil {
				return fmt.Errorf("DAG_SWITCH_SCHEDULE requires DAG_R_BATCH=1 (receiver tells R/B apart by message kind)")
			}
			plan, err := parseSwitchSchedule(s)
			if err != nil {
				return err
			}
			n.switchPlan = plan
		}
		n.logger.Info("certificate types selected", "types", t, "quorum", n.quorumNum, "switch", os.Getenv("DAG_SWITCH_SCHEDULE"))
		return nil
	}
	s, err := certsign.New(mode, n.name, nodes, n.privateKey, n.publicKeyMap, keyDir)
	if err != nil {
		return err
	}
	n.certScheme = s
	n.cert = newCertState()
	n.logger.Info("certificate scheme selected", "mode", s.Name(), "quorum", n.quorumNum)
	return nil
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}

func (n *Node) typeAt(round uint64) byte {
	if n.certTypes == "" {
		return 'B'
	}
	return typeForRound(n.certTypes, round)
}

func (n *Node) isAllToAll(round uint64) bool {
	return n.certTypes != "" && n.typeAt(round) == 'R'
}

func (n *Node) schemeAt(round uint64) certsign.Scheme {
	if n.certTypes == "" {
		return n.certScheme
	}
	if n.typeAt(round) == 'R' {
		return n.schemeR
	}
	return n.schemeB
}

func (n *Node) recordVote(round uint64, author, voter string, digest []byte, sig []byte, ev *VoteBatchMsg) bool {
	k := tallyKey(author, round, digest, 'R')
	n.cert.mu.Lock()
	defer n.cert.mu.Unlock()
	if ev != nil && len(n.cert.evBatches[k]) < n.nodeNum {
		n.cert.evBatches[k] = append(n.cert.evBatches[k], ev)
	}
	if n.cert.votes[k] == nil {
		n.cert.votes[k] = map[string][]byte{}
	}
	if _, dup := n.cert.votes[k][voter]; dup {
		return false
	}
	n.cert.votes[k][voter] = sig
	enough := len(n.cert.votes[k]) == n.quorumNum
	if enough && author == n.name {
		n.vt.ev('C', round, author, 0)
	}
	return enough
}
