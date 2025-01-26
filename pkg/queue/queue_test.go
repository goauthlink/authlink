// Copyright 2025 The AuthLink Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package queue

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type testEvent struct {
	id int
}

func Test_ConsumeAsync(t *testing.T) {
	queue := NewQueue[testEvent]()

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		ctx, stop := context.WithTimeout(context.Background(), time.Second*5)
		id := 0
		queue.Consume(ctx, func(te testEvent) error {
			defer func() {
				id++
			}()
			if id < 9 {
				assert.Equal(t, id, te.id)
				return nil
			}
			if id == 9 {
				assert.Equal(t, id, te.id)
				stop()
				return nil
			}

			return nil
		})
	}()

	for i := 0; i < 10; i++ {
		queue.Push(testEvent{
			id: i,
		})
	}

	wg.Wait()
}

func Test_ConsumeAfter(t *testing.T) {
	queue := NewQueue[testEvent]()
	for i := 0; i < 10; i++ {
		queue.Push(testEvent{
			id: i,
		})
	}

	ctx, stop := context.WithTimeout(context.Background(), time.Second*5)
	id := 0
	queue.Consume(ctx, func(te testEvent) error {
		defer func() {
			id++
		}()
		if id < 9 {
			assert.Equal(t, id, te.id)
			return nil
		}
		if id == 9 {
			assert.Equal(t, id, te.id)
			stop()
			return nil
		}

		return nil
	})
}
