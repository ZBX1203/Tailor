package tusk

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"github.com/hashicorp/go-hclog"
	"math"
	"merge_consensus/dag/certsign"
	"merge_consensus/dag/config"
	"merge_consensus/dag/conn"
	"merge_consensus/dag/rbc"
	"merge_consensus/dag/sign"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Node struct {
	name          string
	lock          sync.RWMutex
	dag           map[uint64]map[string]*Block
	pendingBlocks map[uint64]map[string]*Block

	hasChild   map[string]bool
	weakOn     bool
	weakWindow uint64
	weakLinks  atomic.Int64

	headerDelay time.Duration
	headerTxs   int
	chain       *Chain
	round       uint64
	logger      hclog.Logger

	names     []string
	nodeNum   int
	quorumNum int

	clusterAddr          map[string]string
	clusterPort          map[string]int
	clusterAddrWithPorts map[string]uint8
	isFaulty             bool

	maxPool     int
	trans       *conn.NetworkTransport
	batchSize   int
	roundNumber uint64

	publicKeyMap map[string]ed25519.PublicKey
	privateKey   ed25519.PrivateKey

	reflectedTypesMap map[uint8]reflect.Type

	certScheme certsign.Scheme
	cert       *certState

	certTypes string
	schemeR   certsign.Scheme
	schemeB   certsign.Scheme

	switchPlan []switchStep
	switchT0   atomic.Int64
	switchMu   sync.Mutex
	switchCur  string
	switchDone int

	switchBarrier bool

	switchByRound bool
	barrierRound  atomic.Uint64
	barrierT0     time.Time

	ctlog *commitTimeLog

	nextRound  chan uint64
	evaluation []int64
	commitTime []int64
	rbc        *rbc.ReliableBroadcaster

	committedBlocks  atomic.Int64
	committedTxs     atomic.Int64
	firstCommitNanos atomic.Int64

	rep *replier
	ex  *dagExecutor

	clog *commitLog

	vt *vtracer

	rb *rBatcher

	lastAnchor atomic.Uint64
	rbatchSent atomic.Int64

	rbatchVotes atomic.Int64

	mp        *mempool
	refChunk  uint64
	refRetry  uint64
	nodeIndex int
	alog      *commitLog

	decidedAnchor uint64

	missingParents atomic.Int64

	refMisses atomic.Int64

	reproposed atomic.Int64

	refWaits        atomic.Int64
	refWaitTimeouts atomic.Int64

	refDigestBad  atomic.Int64
	blockFetchReq atomic.Int64
	blockFetched  atomic.Int64

	refLateAtCommit atomic.Int64
	refsWait        time.Duration

	selfProposed  atomic.Int64
	selfCommitted atomic.Int64

	sampMu   sync.Mutex
	cumTxs   []int64
	cumTimes []float64
}

func NewNode(conf *config.Config) *Node {
	var n Node
	n.name = conf.Name
	n.dag = make(map[uint64]map[string]*Block)
	n.pendingBlocks = make(map[uint64]map[string]*Block)
	n.hasChild = make(map[string]bool)
	n.weakOn = os.Getenv("DAG_WEAK") != "0"
	n.weakWindow = 50
	if v := os.Getenv("DAG_HEADER_DELAY_MS"); v != "" {
		if x, err := strconv.Atoi(v); err == nil && x > 0 {
			n.headerDelay = time.Duration(x) * time.Millisecond
		}
	}
	n.headerTxs = 100000
	if v := os.Getenv("DAG_HEADER_TXS"); v != "" {
		if x, err := strconv.Atoi(v); err == nil && x > 0 {
			n.headerTxs = x
		}
	}
	if v := os.Getenv("DAG_WEAK_WINDOW"); v != "" {
		if x, err := strconv.ParseUint(v, 10, 64); err == nil && x > 0 {
			n.weakWindow = x
		}
	}
	n.chain = &Chain{
		round:  0,
		blocks: make(map[string]*Block),
	}
	block := &Block{
		Sender:       "zhang",
		Round:        0,
		PreviousHash: nil,
		TimeStamp:    0,
	}
	hash, _ := block.getHashAsString()
	n.chain.blocks[hash] = block
	n.round = 1
	n.logger = hclog.New(&hclog.LoggerOptions{
		Name:   "Tusk-node",
		Output: hclog.DefaultOutput,
		Level:  hclog.Level(conf.LogLevel),
	})

	n.clusterAddr = conf.ClusterAddr
	n.clusterPort = conf.ClusterPort
	n.clusterAddrWithPorts = conf.ClusterAddrWithPorts

	n.names = make([]string, 0, len(n.clusterAddr))
	for name := range n.clusterAddr {
		n.names = append(n.names, name)
	}
	sort.Strings(n.names)
	n.nodeNum = len(n.clusterAddr)
	n.quorumNum = int(math.Ceil(float64(2*n.nodeNum) / 3.0))
	n.rep = newReplier(n.name)
	n.rep.node = &n
	n.clog = newCommitLog(os.Getenv("DAG_LOG_DIR"))
	n.ctlog = newCommitTimeLog(os.Getenv("DAG_LOG_DIR"))
	n.switchBarrier = os.Getenv("DAG_SWITCH_MODE") == "barrier"
	n.switchByRound = os.Getenv("DAG_SWITCH_BY_ROUND") == "1"
	n.vt = newVTracer(os.Getenv("DAG_LOG_DIR"))
	if rBatchEnabled() {
		n.rb = &rBatcher{pending: map[uint64]*VoteBatchMsg{}, first: map[uint64]time.Time{},
			voted: map[uint64]int{}, quorumSent: map[uint64]bool{}, every: 5 * time.Millisecond, maxWait: 200 * time.Millisecond}
		if v := os.Getenv("DAG_RBATCH_WAIT_MS"); v != "" {
			if x, err := strconv.Atoi(v); err == nil && x > 0 {
				n.rb.maxWait = time.Duration(x) * time.Millisecond
			}
		}
	}

	{
		n.mp = newMempool()
		n.refChunk = 512
		n.refRetry = 20
		n.refsWait = 2 * time.Second
		if v := os.Getenv("DAG_REFS_WAIT_MS"); v != "" {
			if x, err := strconv.Atoi(v); err == nil && x > 0 {
				n.refsWait = time.Duration(x) * time.Millisecond
			}
		}
		if v := os.Getenv("DAG_REF_RETRY"); v != "" {
			if x, err := strconv.ParseUint(v, 10, 64); err == nil && x > 0 {
				n.refRetry = x
			}
		}
		if v := os.Getenv("DAG_REF_CHUNK"); v != "" {
			if x, err := strconv.ParseUint(v, 10, 64); err == nil && x > 0 {
				n.refChunk = x
			}
		}
		for i, nm := range n.names {
			if nm == n.name {
				n.nodeIndex = i
			}
		}
	}
	n.alog = newAnchorLog(os.Getenv("DAG_LOG_DIR"))
	n.isFaulty = conf.IsFaulty
	n.maxPool = conf.MaxPool
	n.batchSize = conf.BatchSize
	n.roundNumber = uint64(conf.Round)
	n.publicKeyMap = conf.PublicKeyMap
	n.privateKey = conf.PrivateKey

	n.reflectedTypesMap = reflectedTypesMap

	n.nextRound = make(chan uint64, 1)

	if os.Getenv("DAG_EXEC") == "kv" {
		n.ex = newDagExecutor(&n)
	}
	return &n
}

func (n *Node) waitHeader(last time.Time) {
	if n.headerDelay <= 0 {
		return
	}
	for {
		if time.Since(last) >= n.headerDelay {
			return
		}
		if n.mp.pendingEstimate(n.nodeNum) >= n.headerTxs {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func (n *Node) RunLoop() {
	n.switchT0.Store(time.Now().UnixNano())
	stop := make(chan struct{})
	go n.startTpsMonitor(stop)
	go n.startRBatcher(stop)
	go n.drainToMempool(stop)
	defer close(stop)
	var currentRound uint64
	currentRound = 1
	start := time.Now().UnixNano()
	lastProp := time.Now()
	for {
		if currentRound > n.roundNumber {
			break
		}
		if n.certScheme != nil {
			n.selfProposed.Add(1)
			go n.broadcastBlockCert(currentRound)
		} else {
			go n.broadcastBlock(currentRound)
		}
		lastProp = time.Now()

		select {
		case currentRound = <-n.nextRound:
		}
		n.waitHeader(lastProp)
	}

	time.Sleep(5 * time.Second)
	n.lock.Lock()
	end := n.commitTime[len(n.commitTime)-1]
	pastTime := float64(end-start) / 1e9
	blockNum := len(n.evaluation)
	throughPut := float64(blockNum*n.batchSize) / pastTime
	totalTime := int64(0)
	for _, t := range n.evaluation {
		totalTime += t
	}
	latency := float64(totalTime) / 1e9 / float64(blockNum)
	n.lock.Unlock()

	n.logger.Info("the average", "latency", latency, "throughput", throughPut)
	n.logger.Info("the total commit", "block number", blockNum, "time", pastTime)

	firstC := n.firstCommitNanos.Load()
	blocks := n.committedBlocks.Load()
	actualTxs := n.committedTxs.Load()
	var alignedTPS, actualTPS, window, fullnessPct float64
	if firstC > 0 && end > firstC {
		window = float64(end-firstC) / 1e9
		alignedTPS = (float64(blocks) / window) * float64(n.batchSize)
		actualTPS = float64(actualTxs) / window
	}
	if blocks > 0 {
		fullnessPct = float64(actualTxs) / (float64(blocks) * float64(n.batchSize)) * 100
	}
	n.logger.Info("TPS", "node", n.name, "committedBlocks", blocks, "window_s", window,
		"alignedTPS_testbrb", alignedTPS, "actualTPS", actualTPS, "blockFullness_pct", fullnessPct)
	n.WriteSummary(os.Getenv("DAG_LOG_DIR"))
}

func (n *Node) WriteSummary(dir string) {
	n.vt.close()
	if dir == "" {
		return
	}
	blocks := n.committedBlocks.Load()
	txs := n.committedTxs.Load()
	first := n.firstCommitNanos.Load()
	window := 0.0
	if first > 0 {
		window = float64(time.Now().UnixNano()-first) / 1e9
	}
	tps := 0.0
	if window > 0 {
		tps = float64(txs) / window
	}
	fullness := 0.0
	if blocks > 0 && n.batchSize > 0 {
		fullness = float64(txs) / (float64(blocks) * float64(n.batchSize)) * 100
	}
	sustained := n.sustainedTPS(10)
	line := fmt.Sprintf("node=%s committedBlocks=%d committedTxs=%d window_s=%.2f sustainedTPS=%.0f "+
		"actualTPS=%.0f blockFullness_pct=%.1f missingParents=%d refMisses=%d mempool=%d "+
		"selfProposed=%d selfCommitted=%d orphanPct=%.1f reproposed=%d refWaits=%d refWaitTimeouts=%d refLateAtCommit=%d rbatchSent=%d refDigestBad=%d weakLinks=%d rbatchVotes=%d blockFetchReq=%d blockFetched=%d\n",
		n.name, blocks, txs, window, sustained, tps, fullness, n.missingParents.Load(),
		n.refMisses.Load(), n.mempoolSize(),
		n.selfProposed.Load(), n.selfCommitted.Load(), n.orphanPct(), n.reproposed.Load(),
		n.refWaits.Load(), n.refWaitTimeouts.Load(), n.refLateAtCommit.Load(), n.rbatchSent.Load(), n.refDigestBad.Load(), n.weakLinks.Load(), n.rbatchVotes.Load(), n.blockFetchReq.Load(), n.blockFetched.Load())
	if n.ex != nil {
		line = strings.TrimRight(line, "\n") + " " + n.ex.stats() + "\n"
		n.ex.close()
	}
	_ = os.WriteFile(filepath.Join(dir, "summary.txt"), []byte(line), 0o644)
}

func (n *Node) InitRBC(conf *config.Config) {
	addrWithPort := n.clusterAddr[n.name] + ":" + strconv.Itoa(n.clusterPort[n.name])
	n.rbc = rbc.NewRBCer(n.name, "rbc", addrWithPort, conf.ClusterAddrWithPorts, rbcMsgType, n.trans,
		n.nodeNum-n.quorumNum, n.nodeNum, conf.LogLevel)
}

func (n *Node) selectPreviousBlocks(round uint64) map[string][]byte {
	n.lock.Lock()
	defer n.lock.Unlock()
	var previousHash map[string][]byte
	previousHash = make(map[string][]byte)
	if round == 0 {
		previousHash = nil
		return previousHash
	}
	for sender, block := range n.dag[round] {
		hash, _ := block.getHash()
		previousHash[sender] = hash
	}
	return previousHash
}

func (n *Node) recordCommitted(block *Block) {
	n.firstCommitNanos.CompareAndSwap(0, time.Now().UnixNano())
	if n.ex != nil {
		n.ex.submit(block)
	} else {
		n.rep.enqueue(block)
	}
	n.clog.add(block)
	n.committedBlocks.Add(1)

	nNew := n.mp.countNew(block.Refs)
	n.committedTxs.Add(int64(nNew))
	n.ctlog.add(block, nNew)
	if block.Sender == n.name {
		n.mp.confirm(block.Round)
		n.selfCommitted.Add(1)
	}
}

func (n *Node) startTpsMonitor(stop <-chan struct{}) {

	dir := os.Getenv("DAG_LOG_DIR")
	if dir == "" {
		dir = "logs"
	}
	_ = os.MkdirAll(dir, 0755)
	f, err := os.OpenFile(dir+"/tps_stats.csv", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0666)
	if err != nil {
		n.logger.Error("cannot open tps csv", "err", err)
		return
	}
	defer f.Close()
	f.WriteString("Time,Runtime_s,BatchCount,TPS,AvgTPS,MaxTPS,CumTxs\n")

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	var lastTxs, maxTps int64
	var firstTime time.Time
	started := false
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:

			txs := n.committedTxs.Load()
			blocks := n.committedBlocks.Load()
			if !started {
				if txs > 0 {
					started = true
					firstTime = time.Now()
					lastTxs = txs
				}
				continue
			}
			tps := txs - lastTxs
			elapsed := time.Since(firstTime).Seconds()
			var avgTps float64
			if elapsed > 0 {
				avgTps = float64(txs) / elapsed
			}
			if tps > maxTps {
				maxTps = tps
			}
			n.sampMu.Lock()
			n.cumTxs = append(n.cumTxs, txs)
			n.cumTimes = append(n.cumTimes, elapsed)
			n.sampMu.Unlock()

			f.WriteString(fmt.Sprintf("%s,%.1f,%d,%d,%.2f,%d,%d\n",
				time.Now().Format("15:04:05"), elapsed, blocks, tps, avgTps, maxTps, txs))
			f.Sync()
			lastTxs = txs
		}
	}
}

func (n *Node) leaderName(round uint64) string {
	return n.names[(round/2)%uint64(n.nodeNum)]
}

func (n *Node) storePendingBlocks(block *Block) {
	if _, ok := n.pendingBlocks[block.Round]; !ok {
		n.pendingBlocks[block.Round] = make(map[string]*Block)
	}
	n.pendingBlocks[block.Round][block.Sender] = block
}

func (n *Node) tryToUpdateDAG(block *Block) {
	n.lock.Lock()
	defer n.lock.Unlock()
	if n.checkWhetherCanAddToDAG(block) {
		if _, ok := n.dag[block.Round]; !ok {
			n.dag[block.Round] = make(map[string]*Block)
		}
		n.dag[block.Round][block.Sender] = block
		n.vt.ev('D', block.Round, block.Sender, 0)
		if n.cert != nil {
			go n.retryParentWaits(block.Round)
		}

		if block.Round > 0 {
			for sndr := range block.PreviousHash {
				n.hasChild[vkey(sndr, block.Round-1)] = true
			}
		}
		for _, w := range block.WeakLinks {
			n.hasChild[vkey(w.Sender, w.Round)] = true
		}
		go n.tryToNextRound(block.Round)
		n.tryToCommitLeader(block.Round)
		if n.weakOn {

			go n.tryPendingFrom(block.Round + 1)
		} else {
			go n.tryToUpdateDAGFromPending(block.Round + 1)
		}
	} else {
		n.storePendingBlocks(block)
	}
}

func (n *Node) checkWhetherCanAddToDAG(block *Block) bool {

	linkHash := block.PreviousHash
	for sender, h := range linkHash {
		parent, ok := n.dag[block.Round-1][sender]
		if !ok {
			return false
		}
		if ph, err := parent.getHash(); err != nil || !bytes.Equal(ph, h) {
			return false
		}
	}

	for _, w := range block.WeakLinks {
		if w.Round+2 > block.Round {
			return false
		}
		if _, ok := n.dag[w.Round][w.Sender]; !ok {
			return false
		}
	}
	return true
}

func (n *Node) tryPendingFrom(round uint64) {
	n.lock.Lock()
	defer n.lock.Unlock()
	for r, m := range n.pendingBlocks {
		if r < round {
			continue
		}
		for sender, block := range m {

			if r > round && len(block.WeakLinks) == 0 {
				continue
			}
			delete(m, sender)
			go n.tryToUpdateDAG(block)
		}
	}
}

func (n *Node) tryToUpdateDAGFromPending(round uint64) {
	n.lock.Lock()
	defer n.lock.Unlock()
	if _, ok := n.pendingBlocks[round]; !ok {
		return
	}
	for sender, block := range n.pendingBlocks[round] {
		delete(n.pendingBlocks[round], sender)
		go n.tryToUpdateDAG(block)
	}
}

func (n *Node) tryToNextRound(round uint64) {
	n.lock.Lock()
	defer n.lock.Unlock()
	if n.round != round {
		return
	}
	blocks := n.dag[round]
	if len(blocks) >= n.quorumNum {
		n.vt.ev('N', round, "-", len(blocks))
		n.round++
		if n.rb != nil {
			go n.flushRBatchesUpTo(round)
		}
		go func() {
			n.nextRound <- round + 1
		}()
		if _, ok := n.dag[round+1]; ok {

			go n.tryToNextRound(round + 1)
		}
	}
}

func (n *Node) tryToCommitLeader(round uint64) {
	if round%2 == 0 {
		round--
	}
	if round <= n.decidedAnchor {
		return
	}
	leader := n.leaderName(round)
	anchor, ok := n.dag[round][leader]
	if !ok || !n.checkWhetherValidLeader(round) {
		return
	}
	n.anchorTrace(round, n.supportCount(round), len(n.dag[round+1]))

	for _, r := range n.anchorChain(anchor, n.decidedAnchor) {
		n.commitAncestorBlocks(r)
		n.chain.round = r
	}
	n.commitAncestorBlocks(round)
	n.decidedAnchor = round
	n.chain.round = round
	n.commitTime = append(n.commitTime, time.Now().UnixNano())
}

func (n *Node) anchorChain(top *Block, floor uint64) []uint64 {
	chain := make([]uint64, 0, 4)
	cur := top
	for cur != nil {
		inPast := n.anchorsInPast(cur, floor)
		if len(inPast) == 0 {
			break
		}
		r := inPast[len(inPast)-1]
		chain = append(chain, r)
		cur = n.dag[r][n.leaderName(r)]
	}
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}
	return chain
}

func (n *Node) anchorsInPast(anchor *Block, floor uint64) []uint64 {
	seen := make(map[string]bool)
	frontier := map[string]*Block{anchor.Sender: anchor}
	found := make([]uint64, 0, 4)

	for r := anchor.Round; r > floor && r > 0; r-- {
		next := make(map[string]*Block)
		for _, b := range frontier {
			h, _ := b.getHashAsString()
			if seen[h] {
				continue
			}
			seen[h] = true
			if b.Round < anchor.Round && b.Round > floor &&
				b.Round%2 == 1 && b.Sender == n.leaderName(b.Round) {
				found = append(found, b.Round)
			}
			for sndr := range b.PreviousHash {
				if p := n.dag[r-1][sndr]; p != nil {
					next[sndr] = p
				}
			}
		}
		if len(next) == 0 {
			break
		}
		frontier = next
	}
	sort.Slice(found, func(i, j int) bool { return found[i] < found[j] })
	return found
}

func (n *Node) commitAncestorBlocks(round uint64) {
	anchor := n.dag[round][n.leaderName(round)]
	if anchor == nil {
		return
	}
	if round > n.lastAnchor.Load() {
		n.lastAnchor.Store(round)
	}

	pending := make(map[uint64]map[string]*Block)

	frontier := map[uint64]map[string]*Block{round: {anchor.Sender: anchor}}
	seen := make(map[string]bool)
	low := round
	push := func(p *Block) {
		if frontier[p.Round] == nil {
			frontier[p.Round] = make(map[string]*Block)
		}
		frontier[p.Round][p.Sender] = p
		if p.Round < low {
			low = p.Round
		}
	}

	for r := round; ; r-- {
		for _, b := range frontier[r] {
			hash, _ := b.getHashAsString()
			if seen[hash] {
				continue
			}
			seen[hash] = true

			if _, done := n.chain.blocks[hash]; done {
				continue
			}
			if pending[b.Round] == nil {
				pending[b.Round] = make(map[string]*Block)
			}
			pending[b.Round][b.Sender] = b
			if r == 0 {
				continue
			}
			for sndr := range b.PreviousHash {
				parent := n.dag[r-1][sndr]
				if parent == nil {

					n.missingParents.Add(1)
					continue
				}
				ph, _ := parent.getHashAsString()
				if seen[ph] {
					continue
				}
				push(parent)
			}
			for _, w := range b.WeakLinks {
				wp := n.dag[w.Round][w.Sender]
				if wp == nil {
					n.missingParents.Add(1)
					continue
				}
				wh, _ := wp.getHashAsString()
				if seen[wh] {
					continue
				}
				push(wp)
			}
		}
		if r == 0 || r <= low {
			break
		}
	}

	rounds := make([]uint64, 0, len(pending))
	for r := range pending {
		rounds = append(rounds, r)
	}
	sort.Slice(rounds, func(i, j int) bool { return rounds[i] < rounds[j] })

	now := time.Now().UnixNano()
	for _, r := range rounds {
		senders := make([]string, 0, len(pending[r]))
		for sndr := range pending[r] {
			senders = append(senders, sndr)
		}
		sort.Strings(senders)
		for _, sndr := range senders {
			b := pending[r][sndr]
			hash, _ := b.getHashAsString()
			n.chain.blocks[hash] = b
			n.evaluation = append(n.evaluation, now-b.TimeStamp)
			n.recordCommitted(b)
		}
	}
}

func (n *Node) checkWhetherValidLeader(round uint64) bool {
	return n.supportCount(round) > n.nodeNum-n.quorumNum
}

func (n *Node) supportCount(round uint64) int {
	leader := n.leaderName(round)
	count := 0
	for _, block := range n.dag[round+1] {
		if _, ok := block.PreviousHash[leader]; ok {
			count++
		}
	}
	return count
}

func (n *Node) newBlock(round uint64, previousHash map[string][]byte) *Block {

	back := uint64(4)
	if n.weakOn {
		back = 10
	}
	if a := n.lastAnchor.Load(); a > back {
		if got := n.mp.reclaimUpTo(a - back); got > 0 {
			n.reproposed.Add(int64(got))
		}
	}
	if got := n.mp.reclaim(round, n.refRetry); got > 0 {
		n.reproposed.Add(int64(got))
	}
	var refs []ClientRange
	if !n.inBarrier() {
		refs = n.mp.take(n.nodeIndex, n.nodeNum, n.refChunk, n.batchSize)
	}
	n.mp.markInflight(round, refs)
	return &Block{
		Sender:       n.name,
		Round:        round,
		PreviousHash: previousHash,
		Refs:         refs,
		TimeStamp:    time.Now().UnixNano(),
		WeakLinks:    n.selectWeakLinks(round),
	}

}

func (n *Node) selectWeakLinks(round uint64) []VertexRef {
	if !n.weakOn || round < 3 {
		return nil
	}
	n.lock.Lock()
	defer n.lock.Unlock()
	lo := uint64(1)
	if round > n.weakWindow+2 {
		lo = round - 2 - n.weakWindow + 1
	}
	var out []VertexRef
	for r := lo; r+2 <= round; r++ {
		for sender, b := range n.dag[r] {
			if n.hasChild[vkey(sender, r)] {
				continue
			}
			hs, _ := b.getHashAsString()
			if _, done := n.chain.blocks[hs]; done {
				continue
			}
			h, _ := b.getHash()
			out = append(out, VertexRef{Round: r, Sender: sender, Hash: h})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Round != out[j].Round {
			return out[i].Round < out[j].Round
		}
		return out[i].Sender < out[j].Sender
	})
	n.weakLinks.Add(int64(len(out)))
	return out
}

func (n *Node) verifySigED25519(peer string, data interface{}, sig []byte) bool {
	pubKey, ok := n.publicKeyMap[peer]
	if !ok {
		n.logger.Error("node is unknown", "node", peer)
		return false
	}
	dataAsBytes, err := encode(data)
	if err != nil {
		n.logger.Error("fail to encode the data", "error", err)
		return false
	}
	ok, err = sign.VerifySignEd25519(pubKey, dataAsBytes, sig)
	if err != nil {
		n.logger.Error("fail to verify the ED25519 signature", "error", err)
		return false
	}
	return ok
}

func (n *Node) IsFaultyNode() bool {
	return n.isFaulty
}

func (n *Node) sustainedTPS(winSec int) float64 {
	n.sampMu.Lock()
	defer n.sampMu.Unlock()
	if len(n.cumTxs) <= winSec {
		return 0
	}
	best := 0.0
	for i := winSec; i < len(n.cumTxs); i++ {
		dt := n.cumTimes[i] - n.cumTimes[i-winSec]
		if dt <= 0 {
			continue
		}
		if r := float64(n.cumTxs[i]-n.cumTxs[i-winSec]) / dt; r > best {
			best = r
		}
	}
	return best
}

func (n *Node) orphanPct() float64 {
	p := n.selfProposed.Load()
	if p == 0 {
		return 0
	}
	return float64(p-n.selfCommitted.Load()) / float64(p) * 100
}
