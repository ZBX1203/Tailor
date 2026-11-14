package main

import (
	"log"
	"sync"
)

type winLimiter struct {
	mu       sync.Mutex
	cond     *sync.Cond
	inflight int
	limit    int
}

func newWinLimiter(limit int) *winLimiter {
	if limit < 1 {
		limit = 1
	}
	w := &winLimiter{limit: limit}
	w.cond = sync.NewCond(&w.mu)
	return w
}

func (w *winLimiter) acquire() {
	w.mu.Lock()
	for w.inflight >= w.limit {
		w.cond.Wait()
	}
	w.inflight++
	w.mu.Unlock()
}

func (w *winLimiter) release() {
	w.mu.Lock()
	if w.inflight > 0 {
		w.inflight--
	} else {
		log.Printf("[window] in-flight count already 0 on release (double release?), ignoring")
	}
	w.cond.Broadcast()
	w.mu.Unlock()
}

func (w *winLimiter) setLimit(n int) int {
	if n < 1 {
		n = 1
	}
	w.mu.Lock()
	old := w.limit
	w.limit = n
	w.cond.Broadcast()
	w.mu.Unlock()
	return old
}

func (w *winLimiter) snapshot() (int, int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.inflight, w.limit
}
