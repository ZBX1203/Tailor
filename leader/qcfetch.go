package main

import (
	"sync"
	"time"

	pb "merge_consensus/merge_proto"

	"google.golang.org/protobuf/proto"
)

var qcReqMu sync.Mutex
var qcReqLast = map[string]time.Time{}

const qcRequestDelay = 300 * time.Millisecond

func qcWantKey(q *pb.QCProof) string {
	return tupleKey(q.View, q.Digest, q.Cfg) + "|" + itoa64(q.Mid) + "/" + itoa64(int64(q.Phase))
}

func (p *Consensus) requestQCLater(want *pb.QCProof, have func() bool) {
	time.AfterFunc(qcRequestDelay, func() {
		if have() {
			return
		}
		k := qcWantKey(want)
		qcReqMu.Lock()
		if t, ok := qcReqLast[k]; ok && time.Since(t) < qcRequestDelay {
			qcReqMu.Unlock()
			return
		}
		qcReqLast[k] = time.Now()
		qcReqMu.Unlock()
		b, err := proto.Marshal(&pb.QCRequest{Want: want, From: p.node.nodeID})
		if err == nil {
			p.broadcast("QCRequest", b)
		}
		p.requestQCLater(want, have)
	})
}

func (p *Consensus) lookupQC(w *pb.QCProof) *pb.QCProof {
	p.vc.mu.Lock()
	defer p.vc.mu.Unlock()
	var q *pb.QCProof
	if len(w.Cfg) == 1 {
		q = p.vc.chainQC[w.Mid]
	} else if in := p.vc.inst[w.Mid]; in != nil {
		q = in.qc[w.Phase]
	}
	if q == nil || q.View != w.View || q.Digest != w.Digest || q.Cfg != w.Cfg || q.Phase != w.Phase {
		return nil
	}
	return q
}

func (p *Consensus) handleQCRequest(content []byte) {
	req := new(pb.QCRequest)
	if err := proto.Unmarshal(content, req); err != nil || req.Want == nil {
		return
	}
	if _, known := NodeTable[req.From]; !known {
		return
	}
	q := p.lookupQC(req.Want)
	if q == nil || q.Cfg[q.Phase-1] != 'R' {
		return
	}
	if b, err := proto.Marshal(q); err == nil {
		p.sendToNode(req.From, "QCResponse", b)
	}
}

func (p *Consensus) handleQCResponse(content []byte) {
	q := new(pb.QCProof)
	if err := proto.Unmarshal(content, q); err != nil || q.Phase < 1 || int(q.Phase) > len(q.Cfg) || q.Cfg[q.Phase-1] != 'R' {
		return
	}
	if !p.VerifyQC(q) {
		return
	}
	p.injectRsaQC(q)
}

func itoa64(v int64) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
