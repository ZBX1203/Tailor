package main

import (
	pb "merge_consensus/merge_proto"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

type RsaPhaseState struct {
	sigs         sync.Map
	count        atomic.Int32
	echoed       atomic.Bool
	transitioned atomic.Bool
}

type BlsPhaseState struct {
	sigs       sync.Map
	count      atomic.Int32
	aggregated atomic.Bool
	done       atomic.Bool
}

type PrevProofGate struct {
	verified atomic.Bool
	pending  sync.Map
}

type pendingRsaVote struct {
	nodeID    string
	signature []byte
}

type Message = pb.ConsensusPayload

type BatchLatencyTracker struct {
	MessageID   int64
	BatchSize   int
	BatchDigest string

	T0_BatchCreated time.Time
	T1_PreparePhase time.Time
	T2_CommitPhase  time.Time
	T3_DecidePhase  time.Time
	T4_Completed    time.Time

	HasT0, HasT1, HasT2, HasT3 bool
	Completed                  bool
}

type node struct {
	nodeID            string
	addr              string
	rsaPrivKey        []byte
	rsaPubKey         []byte
	blsKey            *blsKey
	LastExecutedBatch int
	LastExecutedMsg   int
}

type Client struct {
	msgCounter   int64
	replyCh      chan *pb.Reply
	rangeReplyCh chan *pb.RangeReply
	conns        []pb.MergeConsensusServiceClient
}

type batchGroup struct {
	mu        sync.Mutex
	confirmed map[string]bool
	done      bool
}

var GlobalBatchGroups = NewShardedMap[string, *batchGroup](128)

type RequestPayload struct {
	Request *pb.Request
	State   int
}

type replyTask struct {
	request    *pb.Request
	sequenceID int
	timestamp  int64
}

type batchReplyTask struct {
	refs       []*pb.ClientRange
	sequenceID int
	timestamp  int64
	resultHash []byte
}

type Consensus struct {
	vc         *viewState
	leaderCh   chan struct{}
	node       node
	ViewNumber int
	batchSize  int

	mempool       *Mempool
	RequestsCache *ShardedMap[int64, []*pb.Request]

	RefsCache   *ShardedMap[int64, []*pb.ClientRange]
	clientAddrs *ShardedMap[uint32, string]

	prevProofGates sync.Map

	earlyRsaEchoBuffered atomic.Uint64
	earlyRsaEchoReplayed atomic.Uint64

	messageIDCounter   int64
	maxConcurrentBatch int
	window             *winLimiter
	semReleased        sync.Map
	clientLock         sync.RWMutex

	phase1RsaStates sync.Map
	phase2RsaStates sync.Map
	phase3RsaStates sync.Map
	phase1BlsStates sync.Map
	phase2BlsStates sync.Map
	phase3BlsStates sync.Map

	completed *completedSet

	commitOrder *commitOrderBarrier

	chainMu         sync.Mutex
	chainMsgs       map[int64]*Message
	chainLastQC     *pb.BLSAggregation
	chainLastDig    string
	chainLastView   int64
	chainLastMid    int64
	chainReady      chan struct{}
	chainNProp      int64
	chainPendingMid int64

	chainMaxCert int64
	chainLock    *pb.QCProof
	chainJustify *pb.QCProof
	committedWM  map[uint32]uint64
	chainCertAt  map[int64]string
	chainWaitMu  sync.Mutex
	chainWait    map[string][]chainPending

	clientReplied map[string]bool

	replyWorkerCount int
	replyTaskChan    chan replyTask
	batchReplyChan   chan batchReplyTask
	exec             *Executor
	lateReplyMu      sync.Mutex
	lateReplies      map[int64][]byte
	lateFinals       map[int64]*Message
	replyWg          sync.WaitGroup

	decideCompletedCount int64

	latencyTrackers    map[int64]*BatchLatencyTracker
	latencyTrackerLock sync.RWMutex
	latencyLogFile     *os.File
	channelWaitLogFile *os.File
	waitTimeLogCh      chan string

	totalLatencyMs float64
	latencyCount   int
	latencyMutex   sync.Mutex

	rsaVerifyCount   int64
	rsaVerifyTimeSum int64
	rsaVerifyMutex   sync.Mutex
	rsaVerifyLog     *os.File

	blsVerifyCount   int64
	blsVerifyTimeSum int64
	blsVerifyMutex   sync.Mutex
	blsVerifyLog     *os.File
}
