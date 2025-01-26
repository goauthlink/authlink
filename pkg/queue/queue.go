// Copyright 2025 The AuthLink Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package queue

import (
	"context"
	"sync"
)

type Consumer[qitem any] func(qitem) error

type Queue[qitem any] struct {
	cond    sync.Cond
	items   []*qitem
	stopped bool
}

func NewQueue[qitem any]() *Queue[qitem] {
	return &Queue[qitem]{
		cond:    *sync.NewCond(&sync.Mutex{}),
		items:   make([]*qitem, 0),
		stopped: false,
	}
}

func (q *Queue[qitem]) Push(event qitem) {
	q.cond.L.Lock()
	defer q.cond.L.Unlock()

	if !q.stopped {
		q.items = append(q.items, &event)
	}

	q.cond.Signal()
}

func (q *Queue[qitem]) get() (qi *qitem, stop bool) {
	q.cond.L.Lock()
	defer q.cond.L.Unlock()

	if !q.stopped && len(q.items) == 0 {
		q.cond.Wait()
	}

	if q.stopped {
		return nil, true
	}

	qi = q.items[0]
	q.items[0] = nil
	q.items = q.items[1:]

	return qi, false
}

func (q *Queue[qitem]) processNextItem(consumer Consumer[qitem]) bool {
	qi, stop := q.get()
	if stop {
		return false
	}

	if err := consumer(*qi); err != nil {
		println("err", err.Error())
	}

	return true
}

func (q *Queue[qitem]) Consume(ctx context.Context, consumer Consumer[qitem]) {
	go func() {
		<-ctx.Done()
		q.cond.L.Lock()
		q.stopped = true
		q.cond.Signal()
		q.cond.L.Unlock()
	}()

	for q.processNextItem(consumer) {
	}
}
