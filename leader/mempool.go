package main

import (
	"crypto/sha256"
	"encoding/hex"
	"log"
	"sync"

	pb "merge_consensus/merge_proto"
)

type clientPool struct {
	mu      sync.Mutex
	base    uint64
	reqs    []*pb.Request
	digests [][32]byte
}

type Mempool struct {
	pools     *ShardedMap[uint32, *clientPool]
	committed *ShardedMap[uint32, uint64]
	advMu     sync.Mutex
}

func NewMempool() *Mempool {
	return &Mempool{
		pools:     NewShardedMap[uint32, *clientPool](8),
		committed: NewShardedMap[uint32, uint64](8),
	}
}

func (m *Mempool) Add(req *pb.Request) {
	clientID, seq := decodeReqID(req.ReqId)
	p, ok := m.pools.Get(clientID)
	if !ok {

		p = &clientPool{base: seq}
		m.pools.Set(clientID, p)
	}
	p.mu.Lock()
	expected := p.base + uint64(len(p.reqs))
	if seq != expected {
		p.mu.Unlock()
		log.Printf("[mempool] non-contiguous request from client=%d seq=%d expected=%d, dropped", clientID, seq, expected)
		return
	}
	p.reqs = append(p.reqs, req)
	p.digests = append(p.digests, getDigestMempool(req))
	p.mu.Unlock()
}

func (m *Mempool) pending(cid uint32) uint64 {
	p, ok := m.pools.Get(cid)
	if !ok {
		return 0
	}
	com, _ := m.committed.Get(cid)
	p.mu.Lock()
	defer p.mu.Unlock()
	top := p.base + uint64(len(p.reqs))
	if top <= com {
		return 0
	}
	if com < p.base {
		com = p.base
	}
	return top - com
}

func (m *Mempool) maxSeq(cid uint32) uint64 {
	p, ok := m.pools.Get(cid)
	if !ok {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.reqs) == 0 {
		return 0
	}
	return p.base + uint64(len(p.reqs)) - 1
}

func (m *Mempool) fetch(cid uint32, lo, hi uint64) ([]*pb.Request, [][32]byte, bool) {
	p, ok := m.pools.Get(cid)
	if !ok {
		return nil, nil, false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	top := p.base + uint64(len(p.reqs))
	if lo > hi || lo < p.base || hi >= top {
		return nil, nil, false
	}
	s, e := int(lo-p.base), int(hi-p.base)
	return p.reqs[s : e+1], p.digests[s : e+1], true
}

func (m *Mempool) packBatch(batchSize uint64) ([]*pb.Request, []*pb.ClientRange) {

	var active []uint32
	total := uint64(0)
	m.pools.Range(func(cid uint32, _ *clientPool) bool {
		if pd := m.pending(cid); pd > 0 {
			active = append(active, cid)
			total += pd
		}
		return true
	})
	if total < batchSize {
		return nil, nil
	}
	sortU32(active)

	cursor := make(map[uint32]uint64, len(active))
	takeLo := make(map[uint32]uint64, len(active))
	takeHi := make(map[uint32]uint64, len(active))
	maxSnap := make(map[uint32]uint64, len(active))
	for _, cid := range active {
		com, _ := m.committed.Get(cid)
		cursor[cid] = com
		maxSnap[cid] = m.maxSeq(cid)
	}
	need := batchSize
	for need > 0 {
		progressed := false
		for _, cid := range active {
			if need == 0 {
				break
			}
			if cursor[cid] >= maxSnap[cid] {
				continue
			}
			next := cursor[cid] + 1
			if _, ok := takeLo[cid]; !ok {
				takeLo[cid] = next
			}
			takeHi[cid] = next
			cursor[cid] = next
			need--
			progressed = true
		}
		if !progressed {
			break
		}
	}

	var allReqs []*pb.Request
	var refs []*pb.ClientRange
	for _, cid := range active {
		lo, ok := takeLo[cid]
		if !ok {
			continue
		}
		hi := takeHi[cid]
		rs, ds, ok2 := m.fetch(cid, lo, hi)
		if !ok2 {
			return nil, nil
		}

		refs = append(refs, &pb.ClientRange{ClientId: cid, Lo: lo, Hi: hi, Digest: aggregateRaw(ds)})
		allReqs = append(allReqs, rs...)
	}

	for _, r := range refs {
		m.committed.Set(r.ClientId, r.Hi)
	}
	return allReqs, refs
}

func (m *Mempool) advance(cid uint32, hi uint64) {
	m.advMu.Lock()
	defer m.advMu.Unlock()
	if cur, _ := m.committed.Get(cid); hi > cur {
		m.committed.Set(cid, hi)
	}
}

func (m *Mempool) setWatermark(cid uint32, hi uint64) {
	m.advMu.Lock()
	defer m.advMu.Unlock()
	m.committed.Set(cid, hi)
}

func (m *Mempool) totalPending() int {
	t := 0
	m.pools.Range(func(cid uint32, _ *clientPool) bool {
		t += int(m.pending(cid))
		return true
	})
	return t
}

func (m *Mempool) Cleanup() {

}

func aggregateDigests(ds [][32]byte) string {
	h := sha256.New()
	for i := range ds {
		h.Write(ds[i][:])
	}
	return hex.EncodeToString(h.Sum(nil))
}

func aggregateRaw(ds [][32]byte) []byte {
	h := sha256.New()
	for i := range ds {
		h.Write(ds[i][:])
	}
	return h.Sum(nil)
}

func getDigestMempool(req *pb.Request) [32]byte {
	h := sha256.New()
	h.Write([]byte(req.Content))
	var b [16]byte

	putInt64(b[:8], req.ReqId)
	putInt64(b[8:], req.Timestamp)
	h.Write(b[:])
	h.Write([]byte(req.ClientAddr))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func putInt64(b []byte, v int64) {
	u := uint64(v)
	b[0] = byte(u >> 56)
	b[1] = byte(u >> 48)
	b[2] = byte(u >> 40)
	b[3] = byte(u >> 32)
	b[4] = byte(u >> 24)
	b[5] = byte(u >> 16)
	b[6] = byte(u >> 8)
	b[7] = byte(u)
}

func sortU32(a []uint32) {
	for i := 1; i < len(a); i++ {
		v := a[i]
		j := i - 1
		for j >= 0 && a[j] > v {
			a[j+1] = a[j]
			j--
		}
		a[j+1] = v
	}
}
