package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"log"
	pb "merge_consensus/merge_proto"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/proto"
)

var (
	rrListSet   = map[string]bool{}
	rrListDelay time.Duration
)

func init() {
	f, err := os.Open("rr_list.txt")
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		return
	}
	d, err := strconv.Atoi(strings.TrimSpace(sc.Text()))
	if err != nil || d <= 0 {
		return
	}
	rrListDelay = time.Duration(d) * time.Millisecond
	for sc.Scan() {
		id := strings.TrimSpace(sc.Text())
		if id == "" || strings.HasPrefix(id, "#") {
			continue
		}
		rrListSet[id] = true
	}
	log.Printf("[RR-LIST] rr_list.txt delay=%dms list=%v", d, rrListSet)
}

func rrListBothIn(senderID, targetID string) bool {
	if len(rrListSet) == 0 || rrListDelay == 0 {
		return false
	}
	return rrListSet[senderID] && rrListSet[targetID]
}

type command string

var (
	channelWaitSampleCounter int64 = 0
	channelWaitSampleRate    int64 = 500
)

var rsaPubKeyCache = make(map[string][]byte)

func InitRSAPubKeyCache() {
	for nodeID := range NodeTable {
		key, err := os.ReadFile("Keys/" + nodeID + "/" + nodeID + "_RSA_PUB")
		if err == nil {
			rsaPubKeyCache[nodeID] = key
		}
	}
}

func Newnode(nodeID, addr string, batchSize, mcb int) *Consensus {
	p := new(Consensus)
	p.batchSize = batchSize
	log.Printf("batchsize = %d\n", p.batchSize)

	p.mempool = NewMempool()

	p.replyWorkerCount = runtime.NumCPU() * 2
	p.replyTaskChan = make(chan replyTask, batchSize*(mcb+1))
	p.batchReplyChan = make(chan batchReplyTask, 50)
	p.lateReplies = make(map[int64][]byte)
	p.lateFinals = make(map[int64]*Message)
	if execMode == "kv" {
		p.exec = newExecutor(0, p.batchReplyChan)
		globalExec = p.exec
		go p.exec.loop()
		log.Printf("[%s] execution layer enabled (EXEC_MODE=kv): executing strictly by seq, reply carries result_hash", p.node.nodeID)
	}

	{
		p.maxConcurrentBatch = mcb
		p.window = newWinLimiter(p.maxConcurrentBatch)
		fmt.Printf("[%s] concurrency config: at most %d batches processed in parallel\n", nodeID, p.maxConcurrentBatch)
	}

	p.RequestsCache = NewShardedMap[int64, []*pb.Request](32)

	p.RefsCache = NewShardedMap[int64, []*pb.ClientRange](32)
	p.clientAddrs = NewShardedMap[uint32, string](8)

	p.node.nodeID = nodeID
	p.node.addr = addr
	p.node.LastExecutedBatch = 0
	p.node.LastExecutedMsg = 0
	p.ViewNumber = 0
	p.messageIDCounter = 0

	p.node.blsKey = GetBLSKey(nodeID)
	p.node.rsaPrivKey = p.getPivKey(nodeID)
	p.node.rsaPubKey = p.getPubKey(nodeID)

	p.clientReplied = make(map[string]bool)
	p.completed = newCompletedSet(4096)
	p.commitOrder = newCommitOrderBarrier()
	p.chainMsgs = make(map[int64]*Message)
	p.chainReady = make(chan struct{}, 1)
	p.chainWait = make(map[string][]chainPending)
	p.chainCertAt = make(map[int64]string)

	p.vc = newViewState()
	p.leaderCh = make(chan struct{}, 1)
	go p.startPacker()
	p.startViewMonitor()

	for i := 0; i < p.replyWorkerCount; i++ {
		p.replyWg.Add(1)
		go p.replyWorker()
	}
	for i := 0; i < 16; i++ {
		go p.batchReplyWorker()
	}

	{
		p.latencyTrackers = make(map[int64]*BatchLatencyTracker)
		os.MkdirAll("logs", 0755)

		logFile, err := os.OpenFile("logs/latency_breakdown.csv",
			os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0666)
		if err != nil {
			log.Printf("[%s] failed to create latency log file: %v", nodeID, err)
		} else {
			p.latencyLogFile = logFile
			logFile.WriteString("Timestamp,MessageID,T1_batchCreation_ms,T2_preparePhase_ms,T3_commitPhase_ms,T4_decidePhase_ms,total_latency_ms\n")
			logFile.Sync()
		}

		waitLogFile, err := os.OpenFile("logs/channel_wait_time.csv",
			os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0666)
		if err != nil {
			log.Printf("[%s] failed to create channel wait-time log: %v", nodeID, err)
		} else {
			p.channelWaitLogFile = waitLogFile
			waitLogFile.WriteString("Timestamp,ReqID,WaitTime_ms\n")
			waitLogFile.Sync()
		}

		go p.startChannelUsageMonitor()

		p.waitTimeLogCh = make(chan string, 1000)
		go func() {
			for logLine := range p.waitTimeLogCh {
				p.channelWaitLogFile.WriteString(logLine)
			}
		}()
	}

	return p
}

func (p *Consensus) startPacker() {
	for {
		p.awaitLeadership()
		p.maybeSwitch()

		semStart := time.Now()
		p.window.acquire()
		semWaitNs := time.Since(semStart).Nanoseconds()
		chainWaitT0 := time.Now()

		isChain := chainOn
		if chainTrace && isChain {
			log.Printf("[CHAIN] iter nprop=%d pending=%d lastcert=%d", atomic.LoadInt64(&p.chainNProp), atomic.LoadInt64(&p.chainPendingMid), atomic.LoadInt64(&p.chainLastMid))
		}
		if isChain && !chainFirst {

			for retry := 0; ; retry++ {
				done := false
				select {
				case <-p.chainReady:

					if atomic.LoadInt64(&p.chainLastMid) < atomic.LoadInt64(&p.chainPendingMid) {
						log.Printf("[CHAIN] guard: token but lastcert=%d != pending=%d → keep waiting", atomic.LoadInt64(&p.chainLastMid), atomic.LoadInt64(&p.chainPendingMid))
						continue
					}
					done = true
					if chainTrace {
						log.Printf("[CHAIN] gotoken pending_mid=%d", p.chainPendingMid)
					}
				case <-time.After(5 * time.Second):
					if retry >= 12 {
						log.Printf("[%s] chained: still no QC after %d resends, stop waiting and continue proposing", p.node.nodeID, retry)
						done = true
					} else {
						p.chainMu.Lock()
						pend := p.chainMsgs[p.chainPendingMid]
						p.chainMu.Unlock()
						if pend != nil {
							if b, err := GobEncode(pend); err == nil {
								p.broadcast(command(phaseCmd(1, pend.PhaseConfig["phase1"])), b)
								log.Printf("[%s] chained: timed out waiting 5s for QC, resending proposal %d (attempt %d)", p.node.nodeID, pend.MessageId, retry+1)
							}
						}
					}
				}
				if done {
					break
				}
			}
		}

		if chainTrace {
			atomic.StoreInt64(&chainReadyWaitMs, time.Since(chainWaitT0).Milliseconds())
		}
		if isChain && chainFlushMid >= 0 && p.chainFlushDone() {
			p.maybeSwitch()
		}

		bs := p.batchSize
		if isChain && chainFlushMid >= 0 {
			bs = 1
			chainFlushBlocks++
		} else if !isChain && orderedStage == 1 {
			bs = 1
			orderedStage = 2
		}
		packStart := time.Now()
		var reqs []*pb.Request
		var refs []*pb.ClientRange
		packRetries := int64(0)
		for {
			callStart := time.Now()
			reqs, refs = p.mempool.packBatch(uint64(bs))
			atomic.AddInt64(&packerCallNs, time.Since(callStart).Nanoseconds())
			atomic.AddInt64(&packerCallCount, 1)
			if refs != nil {
				break
			}
			packRetries++
			time.Sleep(1 * time.Millisecond)
		}
		packWaitNs := time.Since(packStart).Nanoseconds()

		atomic.AddInt64(&packerSemWaitNs, semWaitNs)
		atomic.AddInt64(&packerPackWaitNs, packWaitNs)
		atomic.AddInt64(&packerBatchCount, 1)
		atomic.AddInt64(&packerRetriesTotal, packRetries)

		if len(reqs) > 0 && reqs[0].EnqueueTime > 0 && p.isViewLeader() && p.channelWaitLogFile != nil {
			r := reqs[0]
			dequeueTime := time.Now().UnixNano()
			waitTimeMs := float64(dequeueTime-r.EnqueueTime) / 1_000_000.0
			if waitTimeMs > 1.0 && atomic.AddInt64(&channelWaitSampleCounter, 1)%channelWaitSampleRate == 0 {
				logLine := fmt.Sprintf("%s,%d,%.3f\n",
					time.Now().Format("15:04:05.000"), r.ReqId, waitTimeMs)
				select {
				case p.waitTimeLogCh <- logLine:
				default:
				}
			}
		}

		perClient := make([][32]byte, len(refs))
		for i, r := range refs {
			copy(perClient[i][:], r.Digest)
		}
		batchDigest := aggregateDigests(perClient)
		mid := atomic.AddInt64(&p.messageIDCounter, 1) - 1
		var ctype byte
		segStart := false
		if isChain {
			if chainTypes != "" {

				types := chainCurTypes
				if types == "" {
					types = chainTypes
				}
				ctype = types[int(mid)%len(types)]
			}
			segStart = chainSegNew
			chainSegNew = false
			chainFirst = false
			chainLastPackedMid = mid
		}
		go p.processRefs(reqs, refs, batchDigest, mid, isChain, ctype, segStart, structLabel())
	}
}

var chainLatLog = os.Getenv("CHAIN_LATLOG") == "1"

var chainFirst = true

var chainOn = chainedB && os.Getenv("CHAIN_START") != "0"

var chainCurTypes string

var chainSegNew = false

func (p *Consensus) replyWorker() {
	defer p.replyWg.Done()

	for task := range p.replyTaskChan {
		reply := pb.Reply{
			ReqId:      task.request.ReqId,
			SenderId:   p.node.nodeID,
			SequenceId: int64(task.sequenceID),
			Timestamp:  task.timestamp,
			Result:     true,
		}

		reply.Mac = GenerateReplyMAC(task.request.ReqId, p.node.nodeID, int64(task.sequenceID), true)

		grpcReplyToClient(task.request.ClientAddr, &reply)
	}
}

func (p *Consensus) stashLateReply(mid int64, content []byte) bool {
	p.lateReplyMu.Lock()
	p.lateReplies[mid] = content
	p.lateReplyMu.Unlock()
	if _, ok := p.RefsCache.Get(mid); ok {
		p.lateReplyMu.Lock()
		_, still := p.lateReplies[mid]
		delete(p.lateReplies, mid)
		p.lateReplyMu.Unlock()
		if still {
			return false
		}
	}
	return true
}

func (p *Consensus) takeLateReply(mid int64) ([]byte, bool) {
	p.lateReplyMu.Lock()
	c, ok := p.lateReplies[mid]
	if ok {
		delete(p.lateReplies, mid)
	}
	p.lateReplyMu.Unlock()
	return c, ok
}

func (p *Consensus) deliverBatch(mid int64, refs []*pb.ClientRange) {
	if !p.vcFirstDelivery(mid) {
		return
	}
	p.noteDelivered(refs)
	if p.exec != nil {
		reqs, _ := p.RequestsCache.Get(mid)
		p.exec.Submit(mid, refs, reqs)
		return
	}
	p.batchReplyChan <- batchReplyTask{refs: refs, sequenceID: int(mid), timestamp: time.Now().UnixNano()}
}

func (p *Consensus) batchReplyWorker() {
	for task := range p.batchReplyChan {
		seqID := int64(task.sequenceID)
		for _, ref := range task.refs {
			addr, ok := p.clientAddrs.Get(ref.ClientId)
			if !ok {
				log.Printf("[%s] range-reply: unknown reply address for clientID=%d (mid=%d)", p.node.nodeID, ref.ClientId, seqID)
				continue
			}
			rr := &pb.RangeReply{
				ClientId:   ref.ClientId,
				Lo:         ref.Lo,
				Hi:         ref.Hi,
				SenderId:   p.node.nodeID,
				SequenceId: seqID,
				Result:     true,
				ResultHash: task.resultHash,
				Mac:        GenerateRangeReplyMAC(ref.ClientId, ref.Lo, ref.Hi, p.node.nodeID, seqID, true, task.resultHash),
			}
			grpcSendBatchReply(addr, &pb.BatchReply{RangeReplies: []*pb.RangeReply{rr}})
		}
	}
}

func (p *Consensus) assignPhase(cmd string, content []byte) {

	if failureMode == 2 || failureMode == 3 {
		if _, isMalicious := maliciousNodeTable[p.node.nodeID]; isMalicious {
			if failureMode == 2 {
				fmt.Printf("[%s] maliciousNode does not reply\n", p.node.nodeID)
			}
			return
		}
	}

	switch command(cmd) {
	case "Prepare":
		p.handleBlsPhase(1, content)
	case "Phase1_RSA":
		p.handleRsaPhase(1, content)
	case "phase1BlsAggregation":
		p.handleBlsAgg(1, content)
	case "Commit_RSA":
		p.handleRsaPhase(2, content)
	case "Commit_BLS":
		p.handleBlsPhase(2, content)
	case "phase2BlsAggregation":
		p.handleBlsAgg(2, content)
	case "Decide_RSA":
		p.handleRsaPhase(3, content)
	case "Decide_BLS":
		p.handleBlsPhase(3, content)
	case "phase3BlsAggregation":
		p.handleBlsAgg(3, content)
	case "Reply":
		p.handleReply(content)
	case "ViewChange":
		p.handleViewChange(content)
	case "NewView":
		p.handleNewView(content)
	case "QCRequest":
		p.handleQCRequest(content)
	case "QCResponse":
		p.handleQCResponse(content)
	default:
		log.Printf("[%s] unknown message type: %s", p.node.nodeID, cmd)
	}
}

func (p *Consensus) processRefs(reqs []*pb.Request, refs []*pb.ClientRange, batchDigest string, currentMessageId int64, isChain bool, ctype byte, segStart bool, label string) {

	if p.isViewLeader() {
		p.latencyTrackerLock.Lock()
		p.latencyTrackers[currentMessageId] = &BatchLatencyTracker{
			MessageID:       currentMessageId,
			BatchSize:       len(reqs),
			T0_BatchCreated: time.Now(),
			HasT0:           true,
		}
		p.latencyTrackerLock.Unlock()
	}

	p.RefsCache.Set(currentMessageId, refs)
	p.RequestsCache.Set(currentMessageId, reqs)

	logFirstBatchUnder(label, uint64(currentMessageId))
	batchMsg := &Message{
		View:        curView.Load(),
		MessageId:   int64(currentMessageId),
		PhaseConfig: buildPhaseConfig(),
		BatchInfo: &pb.BatchInfo{
			Refs:        refs,
			BatchSize:   int32(len(reqs)),
			BatchDigest: batchDigest,
		},
		Proof: &pb.Proof{},
	}
	if isChain && ctype != 0 {
		batchMsg.PhaseConfig = chainPhaseConfigOf(ctype)
	}
	if isChain && isChainBlock(batchMsg) {
		p.chainMu.Lock()
		if p.chainLastDig != "" && !segStart {
			if p.chainLastQC != nil {
				batchMsg.Proof.BlsAggregation = &pb.BLSAggregation{AggregatedSig: p.chainLastQC.AggregatedSig, Participants: p.chainLastQC.Participants}
			}
			batchMsg.PhaseConfig["parent"] = p.chainLastDig
			batchMsg.PhaseConfig["parent_mid"] = strconv.FormatInt(p.chainLastMid, 10)
			batchMsg.PhaseConfig["parent_view"] = strconv.FormatInt(p.chainLastView, 10)
			batchDigest = chainDigest(batchDigest, p.chainLastDig, p.chainLastView)
			batchMsg.BatchInfo.BatchDigest = batchDigest
			if j := p.chainJustify; j != nil && j.Mid == p.chainLastMid && j.Digest == p.chainLastDig {
				batchMsg.Justify = j
				p.chainJustify = nil
			}
		}
		p.chainMsgs[currentMessageId] = batchMsg
		atomic.StoreInt64(&p.chainPendingMid, int64(currentMessageId))
		p.chainMu.Unlock()
		if chainTrace {
			chainT.Store(int64(currentMessageId), time.Now())
			log.Printf("[CHAIN] propose mid=%d ready_wait_ms=%d dig=%.8s parent_mid=%s", currentMessageId, atomic.SwapInt64(&chainReadyWaitMs, 0), batchDigest, batchMsg.PhaseConfig["parent_mid"])
		}
		atomic.AddInt64(&p.chainNProp, 1)
	}
	if !isChain {
		p.vcRecordProposal(batchMsg)
	}
	if semTimeoutMs > 0 && p.isViewLeader() {
		bd, mid := batchDigest, currentMessageId
		time.AfterFunc(time.Duration(semTimeoutMs)*time.Millisecond, func() {
			if !p.completed.has(bd) {
				log.Printf("[%s] batch MessageId=%d not finalized after %dms timeout → releasing semaphore slot (dedup table prevents double release)", p.node.nodeID, mid, semTimeoutMs)
				p.releaseSemOnce(bd)
				p.commitOrder.skip(mid)
			}
		})
	}
	p.startConsensusForRequest(batchMsg)
}

const refsRetrySleep = 5 * time.Millisecond

var refsRetryMax = func() int {
	if s := os.Getenv("REFS_WAIT_MS"); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v > 0 {
			return v / 5
		}
	}
	return 10
}()

var semTimeoutMs = func() int {
	if s := os.Getenv("SEM_TIMEOUT_MS"); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v > 0 {
			return v
		}
	}
	return 0
}()

var commitOrderWaitMs = func() int {
	if s := os.Getenv("COMMIT_ORDER_WAIT_MS"); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v > 0 {
			return v
		}
	}
	return 0
}()

var chainedB = os.Getenv("CHAINED_B") == "1"

var chainDepth = func() int64 {
	if s := os.Getenv("CHAIN_DEPTH"); s == "3" {
		return 3
	}
	return 2
}()

func isPureBB(m *Message) bool {
	return m != nil && len(m.PhaseConfig) >= 2 && m.PhaseConfig["phase1"] == "BLS" && m.PhaseConfig["phase2"] == "BLS" && m.PhaseConfig["phase3"] == ""
}

var chainTypes = os.Getenv("CHAIN_TYPES")

func chainPhaseConfigOf(t byte) map[string]string {
	s := "RSA"
	if t == 'B' {
		s = "BLS"
	}
	return map[string]string{"phase1": s}
}

func isChainBlock(m *Message) bool {
	if !chainedB || m == nil {
		return false
	}
	single := m.PhaseConfig["phase1"] != "" && m.PhaseConfig["phase2"] == ""
	if chainTypes != "" {
		return single
	}
	return isPureBB(m) || single
}

type chainPending struct {
	bls     bool
	content []byte
}

func (p *Consensus) chainLinear(r *Message) bool {
	pm, has := r.PhaseConfig["parent_mid"]
	if !has {
		return true
	}
	pmid, err := strconv.ParseInt(pm, 10, 64)
	if err != nil || pmid != r.MessageId-1 {
		log.Printf("[%s] chained: proposal %d has parent_mid=%s, not mid−1, dropping", p.node.nodeID, r.MessageId, pm)
		return false
	}
	return true
}

func (p *Consensus) chainParentReady(r *Message) bool {
	pd, has := r.PhaseConfig["parent"]
	if !has || p.node.nodeID == leaderOf(r.GetView()) {
		return true
	}
	if r.Proof != nil && r.Proof.BlsAggregation != nil && len(r.Proof.BlsAggregation.AggregatedSig) > 0 {
		return true
	}

	p.chainMu.Lock()
	d, ok := p.chainCertAt[r.MessageId-1]
	p.chainMu.Unlock()
	return (ok && d == pd) || p.completed.has(pd)
}

var chainReadyWaitMs int64

func (p *Consensus) chainStash(r *Message, content []byte) {
	pd := r.PhaseConfig["parent"]
	if chainTrace {
		log.Printf("[CHAIN] stash mid=%d parent_mid=%s", r.MessageId, r.PhaseConfig["parent_mid"])
	}
	q := chainPending{bls: r.PhaseConfig["phase1"] == "BLS", content: content}
	if pm, err := strconv.ParseInt(r.PhaseConfig["parent_mid"], 10, 64); err == nil && (r.Proof == nil || r.Proof.BlsAggregation == nil || len(r.Proof.BlsAggregation.AggregatedSig) == 0) {
		want := &pb.QCProof{View: r.GetView(), Mid: pm, Phase: 1, Digest: pd, Cfg: "R"}
		p.requestQCLater(want, func() bool { return p.chainParentReady(r) })
	}
	p.chainWaitMu.Lock()
	p.chainWait[pd] = append(p.chainWait[pd], q)
	p.chainWaitMu.Unlock()
	if p.chainParentReady(r) {
		p.chainReplay(pd)
	}
}

func (p *Consensus) chainReplay(parentDigest string) {
	p.chainWaitMu.Lock()
	pend := p.chainWait[parentDigest]
	delete(p.chainWait, parentDigest)
	p.chainWaitMu.Unlock()
	if chainTrace && len(pend) > 0 {
		log.Printf("[CHAIN] replay n=%d", len(pend))
	}
	for _, q := range pend {
		if q.bls {
			go p.handleBlsPhase(1, q.content)
		} else {
			go p.handleRsaPhase(1, q.content)
		}
	}
}

type commitOrderBarrier struct {
	mu   sync.Mutex
	cond *sync.Cond
	next int64
}

var outOfOrderCommits int64

var coWaitBuckets [6]int64
var coWaitSumMs, coWaitMaxMs, coWaitCalls int64

func commitOrderRecord(ms int64) {
	atomic.AddInt64(&coWaitCalls, 1)
	atomic.AddInt64(&coWaitSumMs, ms)
	for {
		m := atomic.LoadInt64(&coWaitMaxMs)
		if ms <= m || atomic.CompareAndSwapInt64(&coWaitMaxMs, m, ms) {
			break
		}
	}
	i := 5
	switch {
	case ms < 1:
		i = 0
	case ms < 10:
		i = 1
	case ms < 50:
		i = 2
	case ms < 200:
		i = 3
	case ms < 1000:
		i = 4
	}
	atomic.AddInt64(&coWaitBuckets[i], 1)
}

func CommitOrderStats() string {
	c := atomic.LoadInt64(&coWaitCalls)
	avg := 0.0
	if c > 0 {
		avg = float64(atomic.LoadInt64(&coWaitSumMs)) / float64(c)
	}
	return fmt.Sprintf("commitOrder calls=%d wait_avg_ms=%.2f wait_max_ms=%d hist=%d,%d,%d,%d,%d,%d skipped=%d",
		c, avg, atomic.LoadInt64(&coWaitMaxMs),
		atomic.LoadInt64(&coWaitBuckets[0]), atomic.LoadInt64(&coWaitBuckets[1]), atomic.LoadInt64(&coWaitBuckets[2]),
		atomic.LoadInt64(&coWaitBuckets[3]), atomic.LoadInt64(&coWaitBuckets[4]), atomic.LoadInt64(&coWaitBuckets[5]),
		atomic.LoadInt64(&outOfOrderCommits))
}

func newCommitOrderBarrier() *commitOrderBarrier {
	b := &commitOrderBarrier{}
	b.cond = sync.NewCond(&b.mu)
	return b
}

func (b *commitOrderBarrier) wait(id int64) {
	if commitOrderWaitMs == 0 {
		return
	}
	t0 := time.Now()
	defer func() { commitOrderRecord(time.Since(t0).Milliseconds()) }()
	deadline := t0.Add(time.Duration(commitOrderWaitMs) * time.Millisecond)
	timer := time.AfterFunc(time.Duration(commitOrderWaitMs)*time.Millisecond, func() { b.mu.Lock(); b.cond.Broadcast(); b.mu.Unlock() })
	defer timer.Stop()
	b.mu.Lock()
	for b.next < id && time.Now().Before(deadline) {
		b.cond.Wait()
	}
	if b.next < id {
		n := atomic.AddInt64(&outOfOrderCommits, 1)
		if n%100 == 1 {
			log.Printf("[commitOrder] timeout release MessageId=%d (waiting for %d, cumulative out-of-order %d)", id, b.next, n)
		}
	}
	if id+1 > b.next {
		b.next = id + 1
	}
	b.cond.Broadcast()
	b.mu.Unlock()
}

func (b *commitOrderBarrier) advance(id int64) { b.skip(id) }

func (b *commitOrderBarrier) skip(id int64) {
	if commitOrderWaitMs == 0 {
		return
	}
	b.mu.Lock()
	if id+1 > b.next {
		b.next = id + 1
	}
	b.cond.Broadcast()
	b.mu.Unlock()
}

func (p *Consensus) verifyBatchRefs(bi *pb.BatchInfo) ([]*pb.Request, string, bool) {

	perRef := make([][]*pb.Request, len(bi.Refs))
	for attempt := 0; attempt < refsRetryMax; attempt++ {
		allOk := true
		for i, ref := range bi.Refs {
			if perRef[i] != nil {
				continue
			}
			reqs, digs, ok := p.mempool.fetch(ref.ClientId, ref.Lo, ref.Hi)
			if !ok {
				allOk = false
				continue
			}

			if len(ref.Digest) == 0 || !bytes.Equal(aggregateRaw(digs), ref.Digest) {
				log.Printf("[%s] verifyBatchRefs: ref(cid=%d lo=%d hi=%d) digest missing/mismatched → byzantine, rejecting whole batch",
					p.node.nodeID, ref.ClientId, ref.Lo, ref.Hi)
				return nil, "", false
			}
			perRef[i] = reqs
		}
		if allOk {
			var allReqs []*pb.Request
			for _, rs := range perRef {
				allReqs = append(allReqs, rs...)
			}

			perClient := make([][32]byte, len(bi.Refs))
			for i, ref := range bi.Refs {
				copy(perClient[i][:], ref.Digest)
			}
			return allReqs, aggregateDigests(perClient), true
		}
		time.Sleep(refsRetrySleep)
	}
	log.Printf("[%s] verifyBatchRefs: ref still missing after %d retries → dropping Prepare (client stream may not have caught up, or leader sending too fast)",
		p.node.nodeID, refsRetryMax)
	return nil, "", false
}

func (p *Consensus) startConsensusForRequest(msg *Message) {
	p.transitionToNextPhase(0, msg)
}

func (p *Consensus) handleReply(content []byte) {
	r := new(Message)
	err := GobDecode(content, r)
	if err != nil {
		log.Printf("[%s] failed to parse message: %v", p.node.nodeID, err)
		return
	}

	batchID := r.BatchInfo.BatchDigest
	if !validConfig(r) || isChainBlock(r) {
		return
	}
	if !p.matchesAccepted(r) {
		log.Printf("[%s] Reply for instance %d certifies another digest than the accepted proposal, not committing", p.node.nodeID, r.MessageId)
		return
	}

	var lastPhaseConfig string
	var lastPhaseKey string
	if phase3Config, exists := r.PhaseConfig["phase3"]; exists {
		lastPhaseConfig = phase3Config
		lastPhaseKey = "phase3"
	} else if phase2Config, exists := r.PhaseConfig["phase2"]; exists {
		lastPhaseConfig = phase2Config
		lastPhaseKey = "phase2"
	} else {
		log.Printf("[%s] missing phase config", p.node.nodeID)
		return
	}

	switch lastPhaseConfig {
	case "BLS":

		p.clientLock.Lock()
		done := p.clientReplied[batchID]
		p.clientLock.Unlock()
		if done {
			return
		}

		if len(r.Proof.BlsAggregation.AggregatedSig) == 0 {
			log.Printf("[%s] missing BLS aggregate signature", p.node.nodeID)
			return
		}
		if len(r.Proof.BlsAggregation.Participants) < Threshold {
			log.Printf("[%s] missing BLS signature participant info", p.node.nodeID)
			return
		}

		aggregatedSig, err := NewSignatureFromBytes(r.Proof.BlsAggregation.AggregatedSig)
		if err != nil {
			log.Printf("[%s] failed to deserialize BLS signature: %v", p.node.nodeID, err)
			return
		}

		if !VerifyWithPreAggregatedKey(r.Proof.BlsAggregation.Participants, msgPayload(r, phaseCountOf(r), batchID), aggregatedSig) {
			log.Printf("[%s] BLS signature verification failed", p.node.nodeID)
			return
		}
		p.vcRecordQC(qcFromBls(r, phaseCountOf(r), batchID, r.Proof.BlsAggregation))
		p.clientLock.Lock()
		if p.clientReplied[batchID] {
			p.clientLock.Unlock()
			return
		}
		p.clientReplied[batchID] = true
		p.clientLock.Unlock()

		refs, ok := p.RefsCache.Get(r.MessageId)
		if isNoop(r) {
			refs, ok = nil, true
		}
		if !ok {
			if p.stashLateReply(r.MessageId, content) {
				p.clientLock.Lock()
				delete(p.clientReplied, batchID)
				p.clientLock.Unlock()
				return
			}
			refs, _ = p.RefsCache.Get(r.MessageId)
		}
		p.deliverBatch(r.MessageId, refs)
		p.commitOrder.advance(r.MessageId)
		p.RefsCache.Delete(r.MessageId)
		p.RequestsCache.Delete(r.MessageId)

	case "RSA":

		p.clientLock.Lock()
		done := p.clientReplied[batchID]
		p.clientLock.Unlock()
		if done {
			return
		}

		if _, err := hex.DecodeString(batchID); err != nil {
			log.Printf("[%s] failed to decode digest: %v", p.node.nodeID, err)
			return
		}
		validSigners := make(map[string]bool)
		var validSigs []*pb.SigEntry
		for _, sigInfo := range r.Proof.RsaSignatures {
			if validSigners[sigInfo.NodeId] {
				continue
			}
			if !p.RsaVerifyCached(msgPayload(r, phaseCountOf(r), batchID), sigInfo.Signature, sigInfo.NodeId) {
				continue
			}
			validSigners[sigInfo.NodeId] = true
			validSigs = append(validSigs, sigInfo)
		}
		if len(validSigners) < Threshold {
			log.Printf("[%s] insufficient Reply RSA proofs: %d/%d", p.node.nodeID, len(validSigners), Threshold)
			return
		}
		p.vcRecordQC(qcFromRsa(r, phaseCountOf(r), batchID, validSigs))
		p.clientLock.Lock()
		if p.clientReplied[batchID] {
			p.clientLock.Unlock()
			return
		}
		p.clientReplied[batchID] = true
		p.clientLock.Unlock()

		refs, ok := p.RefsCache.Get(r.MessageId)
		if isNoop(r) {
			refs, ok = nil, true
		} else if !ok || len(refs) == 0 {
			if p.stashLateReply(r.MessageId, content) {
				p.clientLock.Lock()
				delete(p.clientReplied, batchID)
				p.clientLock.Unlock()
				return
			}
			refs, _ = p.RefsCache.Get(r.MessageId)
		}
		p.deliverBatch(r.MessageId, refs)
		p.commitOrder.advance(r.MessageId)
		p.RefsCache.Delete(r.MessageId)
		p.RequestsCache.Delete(r.MessageId)
		_ = lastPhaseKey
	}
}

func (p *Consensus) broadcastSplit(cmd command, content, evil []byte, victims map[string]bool) {
	for nodeID, addr := range NodeTable {
		if nodeID == p.node.nodeID {
			continue
		}
		body := content
		if victims[nodeID] {
			body = evil
		}
		delayed := rrListBothIn(p.node.nodeID, nodeID)
		ad, ct := addr, body
		if delayed {
			time.AfterFunc(rrListDelay, func() { grpcSendMessage(ad, string(cmd), ct) })
		} else {
			go grpcSendMessage(ad, string(cmd), ct)
		}
	}
}

func (p *Consensus) broadcast(cmd command, content []byte) {
	msg := &pb.ConsensusMessage{Command: string(cmd), Content: content}
	for nodeID, addr := range NodeTable {
		if nodeID == p.node.nodeID {
			continue
		}
		delayed := rrListBothIn(p.node.nodeID, nodeID)
		ps, err := getPeerStream(addr)
		if err != nil {
			cmdS, ct, ad := string(cmd), content, addr
			if delayed {
				time.AfterFunc(rrListDelay, func() { grpcSendMessage(ad, cmdS, ct) })
			} else {
				go grpcSendMessage(ad, cmdS, ct)
			}
			continue
		}
		if delayed {
			time.AfterFunc(rrListDelay, func() { ps.SendAsync(msg) })
		} else {
			ps.SendAsync(msg)
		}
	}
}

func (p *Consensus) getPubKey(nodeID string) []byte {
	key, err := os.ReadFile("Keys/" + nodeID + "/" + nodeID + "_RSA_PUB")
	if err != nil {
		log.Panic(err)
	}
	return key
}

func (p *Consensus) getPivKey(nodeID string) []byte {
	key, err := os.ReadFile("Keys/" + nodeID + "/" + nodeID + "_RSA_PIV")
	if err != nil {
		log.Panic(err)
	}
	return key
}

func (p *Consensus) markDecideCompleted(latestSeqID int64) {
	atomic.AddInt64(&p.decideCompletedCount, 1)
}

func (p *Consensus) releaseSemOnce(batchID string) {
	if !p.isViewLeader() {
		return
	}
	if _, loaded := p.semReleased.LoadOrStore(batchID, struct{}{}); loaded {
		return
	}
	p.window.release()
}

func (p *Consensus) cleanupConsensusState(batchID string, messageId int64) {
	p.semReleased.Delete(batchID)

	p.clientLock.Lock()
	delete(p.clientReplied, batchID)
	p.clientLock.Unlock()

	p.latencyTrackerLock.Lock()
	delete(p.latencyTrackers, messageId)
	p.latencyTrackerLock.Unlock()
}

func (p *Consensus) startDecideTpsMonitor() {
	if p.node.nodeID != leaderOf(0) {
		return
	}

	go func() {
		if err := os.MkdirAll("logs", 0755); err != nil {
			log.Printf("cannot create logs directory: %v", err)
			return
		}

		tpsFile, err := os.OpenFile("logs/tps_stats.csv",
			os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0666)
		if err != nil {
			log.Printf("cannot create TPS log file: %v", err)
			return
		}
		defer tpsFile.Close()

		tpsFile.WriteString("Time,Runtime_s,BatchCount,TPS,AvgTPS,MaxTPS\n")

		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		var lastCount int64 = 0
		var maxTps int64 = 0
		var firstBatchTime time.Time
		started := false

		for range ticker.C {
			currentCount := atomic.LoadInt64(&p.decideCompletedCount)

			if !started {
				if currentCount > 0 {
					started = true
					firstBatchTime = time.Now()
					lastCount = currentCount
				}
				continue
			}

			tps := (currentCount - lastCount) * int64(p.batchSize)
			elapsed := time.Since(firstBatchTime).Seconds()

			var avgTps float64
			if elapsed > 0 {
				avgTps = (float64(currentCount) / elapsed) * float64(p.batchSize)
			}

			if tps > maxTps {
				maxTps = tps
			}

			logLine := fmt.Sprintf("%s,%.1f,%d,%d,%.2f,%d\n",
				time.Now().Format("15:04:05"), elapsed, currentCount, tps, avgTps, maxTps)
			tpsFile.WriteString(logLine)
			tpsFile.Sync()

			lastCount = currentCount
		}
	}()
}

func (p *Consensus) outputLatencyBreakdown(tracker *BatchLatencyTracker) {

	if chainLatLog && tracker.HasT0 && !tracker.HasT2 && !tracker.T4_Completed.IsZero() {
		line := fmt.Sprintf("%s,%d,0.00,0.00,0.00,0.00,%.2f\n", tracker.T4_Completed.Format("15:04:05.000"), tracker.MessageID,
			float64(tracker.T4_Completed.Sub(tracker.T0_BatchCreated).Microseconds())/1000.0)
		if p.latencyLogFile != nil {
			p.latencyLogFile.WriteString(line)
		}
		p.latencyTrackerLock.Lock()
		delete(p.latencyTrackers, tracker.MessageID)
		p.latencyTrackerLock.Unlock()
		return
	}

	if !tracker.HasT0 || !tracker.HasT1 || !tracker.HasT2 {
		log.Printf("[%s] Batch %d missing timestamps: T0=%v T1=%v T2=%v",
			p.node.nodeID, tracker.MessageID,
			tracker.HasT0, tracker.HasT1, tracker.HasT2)
		return
	}

	batchCreation := float64(tracker.T1_PreparePhase.Sub(tracker.T0_BatchCreated).Microseconds()) / 1000.0
	preparePhase := float64(tracker.T2_CommitPhase.Sub(tracker.T1_PreparePhase).Microseconds()) / 1000.0
	var commitPhase, decidePhase float64
	if tracker.HasT3 {

		commitPhase = float64(tracker.T3_DecidePhase.Sub(tracker.T2_CommitPhase).Microseconds()) / 1000.0
		decidePhase = float64(tracker.T4_Completed.Sub(tracker.T3_DecidePhase).Microseconds()) / 1000.0
	} else {

		commitPhase = float64(tracker.T4_Completed.Sub(tracker.T2_CommitPhase).Microseconds()) / 1000.0
		decidePhase = 0
	}
	totalLatency := float64(tracker.T4_Completed.Sub(tracker.T0_BatchCreated).Microseconds()) / 1000.0

	line := fmt.Sprintf("%s,%d,%.2f,%.2f,%.2f,%.2f,%.2f\n",
		tracker.T4_Completed.Format("15:04:05.000"),
		tracker.MessageID, batchCreation, preparePhase, commitPhase, decidePhase, totalLatency)

	if p.latencyLogFile != nil {
		p.latencyLogFile.WriteString(line)
		p.latencyLogFile.Sync()
	}

	p.latencyTrackerLock.Lock()
	delete(p.latencyTrackers, tracker.MessageID)
	p.latencyTrackerLock.Unlock()
}

func (p *Consensus) startChannelUsageMonitor() {
	if p.node.nodeID != leaderOf(0) {
		return
	}

	go func() {
		if err := os.MkdirAll("logs", 0755); err != nil {
			log.Printf("cannot create logs directory: %v", err)
			return
		}

		monitorFile, err := os.OpenFile("logs/channel_usage.csv",
			os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0666)
		if err != nil {
			log.Printf("cannot create Channel usage log: %v", err)
			return
		}
		defer monitorFile.Close()

		monitorFile.WriteString("Time,Runtime_s,IntakeCh_Len,IntakeCh_Cap,IntakeCh_Usage%,ReplyTask_Len,ReplyTask_Cap,ReplyTask_Usage%\n")

		softCap := p.batchSize * p.maxConcurrentBatch * 10
		if softCap <= 0 {
			softCap = p.batchSize * 10
		}

		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		startTime := time.Now()

		for range ticker.C {
			intakeLen := p.mempool.totalPending()
			intakeCap := softCap
			intakeUsage := 0.0
			if intakeCap > 0 {
				intakeUsage = float64(intakeLen) / float64(intakeCap) * 100
			}

			replyLen := len(p.replyTaskChan)
			replyCap := cap(p.replyTaskChan)
			replyUsage := 0.0
			if replyCap > 0 {
				replyUsage = float64(replyLen) / float64(replyCap) * 100
			}

			elapsed := time.Since(startTime).Seconds()
			logLine := fmt.Sprintf("%s,%.1f,%d,%d,%.2f,%d,%d,%.2f\n",
				time.Now().Format("15:04:05"), elapsed,
				intakeLen, intakeCap, intakeUsage,
				replyLen, replyCap, replyUsage)

			monitorFile.WriteString(logLine)
			monitorFile.Sync()
		}
	}()

	log.Printf("[%s] Channel usage monitor started: logs/channel_usage.csv", p.node.nodeID)
}

func GobEncode(data interface{}) ([]byte, error) {
	m, ok := data.(proto.Message)
	if !ok {
		return nil, fmt.Errorf("GobEncode: expected proto.Message, got %T", data)
	}
	return proto.Marshal(m)
}

func GobDecode(data []byte, v interface{}) error {
	m, ok := v.(proto.Message)
	if !ok {
		return fmt.Errorf("GobDecode: expected proto.Message, got %T", v)
	}
	if err := proto.Unmarshal(data, m); err != nil {
		return err
	}

	if cp, ok := v.(*Message); ok {
		if cp.BatchInfo == nil {
			cp.BatchInfo = &pb.BatchInfo{}
		}
		if cp.Proof == nil {
			cp.Proof = &pb.Proof{}
		}
		if cp.Proof.BlsAggregation == nil {
			cp.Proof.BlsAggregation = &pb.BLSAggregation{}
		}
	}
	return nil
}

func (p *Consensus) startGarbageAttack() {
	leaderAddr := NodeTable[leaderOf(curView.Load())]
	log.Printf("[BYZANTINE-MODE3][%s] starting to send junk messages to Leader(%s) to consume bandwidth", p.node.nodeID, leaderAddr)

	payload := make([]byte, 2048)
	ticker := time.NewTicker(1 * time.Millisecond)
	defer ticker.Stop()
	for range ticker.C {
		go grpcSendMessage(leaderAddr, "phase1BlsAggregation", payload)
	}
}

func (p *Consensus) chainCommitList(k int64) []*Message {
	if m, ok := p.chainMsgs[k]; ok {
		if d, certified := p.chainCertAt[k]; !certified || d != m.BatchInfo.BatchDigest {
			return nil
		}
	}
	var back []*Message
	var child *Message
	for cur := k; cur >= 0; cur-- {
		m, ok := p.chainMsgs[cur]
		if !ok {
			break
		}
		if child != nil && child.PhaseConfig["parent"] != m.BatchInfo.BatchDigest {
			log.Printf("[%s] chained: parent digest of mid=%d does not match local block mid=%d, stopping commit", p.node.nodeID, child.MessageId, cur)
			break
		}
		back = append(back, m)
		child = m
	}
	skip := int(chainDepth - 1)
	if len(back) <= skip {
		return nil
	}
	out := append([]*Message(nil), back[skip:]...)
	sort.Slice(out, func(i, j int) bool { return out[i].MessageId < out[j].MessageId })
	return out
}

func (p *Consensus) chainOnQC(r *Message, aggSig []byte, participants []string) {
	if chainTrace {
		ty := "B"
		if aggSig == nil {
			ty = "R"
		}
		log.Printf("[CHAIN] cert mid=%d type=%s by=%s since_propose_ms=%d dig=%.8s", r.MessageId, ty, r.NodeId, chainSinceMs(r.MessageId), r.BatchInfo.BatchDigest)
	}
	p.chainMu.Lock()
	if r.MessageId > p.chainMaxCert {
		p.chainMaxCert = r.MessageId
	}
	if r.MessageId >= atomic.LoadInt64(&p.chainLastMid) || p.chainLastDig == "" {
		if aggSig != nil {
			p.chainLastQC = &pb.BLSAggregation{AggregatedSig: aggSig, Participants: participants}
		} else {
			p.chainLastQC = nil
		}
		p.chainLastDig = r.BatchInfo.BatchDigest
		p.chainLastView = r.GetView()
		atomic.StoreInt64(&p.chainLastMid, r.MessageId)
	}
	p.chainCertAt[r.MessageId] = r.BatchInfo.BatchDigest
	var q *pb.QCProof
	if p.vc != nil {
		p.vc.mu.Lock()
		q = p.vc.chainQC[r.MessageId]
		p.vc.mu.Unlock()
	}
	if q != nil && q.Digest == r.BatchInfo.BatchDigest {
		p.chainUpdateLock(q)
	}
	for mid := range p.chainCertAt {
		if mid < r.MessageId-64 {
			delete(p.chainCertAt, mid)
		}
	}

	toCommit := p.chainCommitList(r.MessageId)
	for _, m := range toCommit {
		delete(p.chainMsgs, m.MessageId)
	}
	p.chainMu.Unlock()
	select {
	case p.chainReady <- struct{}{}:
		if chainTrace && p.isViewLeader() {
			log.Printf("[CHAIN] token mid=%d", r.MessageId)
		}
	default:
		if chainTrace && p.isViewLeader() {
			log.Printf("[CHAIN] token-dropped mid=%d (buffer full)", r.MessageId)
		}
	}
	for _, m := range toCommit {
		p.finalizeLocal(m)
		p.chainReplay(m.BatchInfo.BatchDigest)
	}
	if aggSig == nil {
		p.chainReplay(r.BatchInfo.BatchDigest)
	}
}

func (p *Consensus) chainOnProposal(r *Message) bool {
	pm, hasParent := r.PhaseConfig["parent_mid"]
	pmid, _ := strconv.ParseInt(pm, 10, 64)
	if chainTrace {
		chainT.LoadOrStore(r.MessageId, time.Now())
	}
	pv := chainParentView(r)
	var parentQC *pb.QCProof
	if hasParent && p.node.nodeID != leaderOf(r.GetView()) {
		if r.Proof != nil && r.Proof.BlsAggregation != nil && len(r.Proof.BlsAggregation.AggregatedSig) > 0 {
			if len(r.Proof.BlsAggregation.Participants) < Threshold ||
				!VerifyWithPreAggregatedKey(r.Proof.BlsAggregation.Participants, votePayload(pv, pmid, 1, r.PhaseConfig["parent"], "B"), r.Proof.BlsAggregation.AggregatedSig) {
				log.Printf("[%s] chained: parent QC carried by proposal %d failed verification", p.node.nodeID, r.MessageId)
				return false
			}
			parentQC = &pb.QCProof{View: pv, Mid: pmid, Phase: 1, Digest: r.PhaseConfig["parent"], Cfg: "B", BlsAggregation: r.Proof.BlsAggregation}
			p.vcRecordQC(parentQC)
		} else if !p.getRsaPhaseState(1, tupleKey(pv, r.PhaseConfig["parent"], "R")).transitioned.Load() && !p.completed.has(r.PhaseConfig["parent"]) {
			log.Printf("[%s] chained: R-type parent certificate of proposal %d not ready (should have been blocked by chainParentReady)", p.node.nodeID, r.MessageId)
			return false
		}
	}
	p.chainMu.Lock()
	if !p.chainSafeToVote(r) {
		p.chainMu.Unlock()
		log.Printf("[%s] chained: block %d extends a QC ranked below this replica's lock, not voting", p.node.nodeID, r.MessageId)
		return false
	}
	if parentQC != nil {
		p.chainUpdateLock(parentQC)
		p.chainCertAt[pmid] = parentQC.Digest
	}
	p.chainMsgs[r.MessageId] = r
	var toCommit []*Message
	if p.node.nodeID != leaderOf(r.GetView()) {

		if hasParent && r.Proof != nil && r.Proof.BlsAggregation != nil && len(r.Proof.BlsAggregation.AggregatedSig) > 0 && pmid > p.chainMaxCert {
			p.chainMaxCert = pmid
		}

		toCommit = p.chainCommitList(p.chainMaxCert)
		for _, m := range toCommit {
			delete(p.chainMsgs, m.MessageId)
		}
	}
	p.chainMu.Unlock()
	for _, m := range toCommit {
		p.finalizeLocal(m)
	}
	return true
}
