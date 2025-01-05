// Copyright 2024 The AuthLink Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package agent

import (
	"context"
	"fmt"
	"time"

	"github.com/goauthlink/authlink/pkg/metrics"
	"github.com/goauthlink/authlink/sdk/policy"
)

type Policy struct {
	checker             *policy.Checker
	checkLogger         *CheckLogger
	counterRqTotal      metrics.Metric
	counterRqFailed     metrics.Metric
	histogramRqDuration metrics.Metric
}

func NewPolicy(
	checker *policy.Checker,
	checkLogger *CheckLogger,
) *Policy {
	counterRqTotal, _ := metrics.NewCounter("check_rq_total", "A counter of check requests")
	counterRqFailed, _ := metrics.NewCounter("check_rq_failed", "A counter of failed check requests (500 response code)")
	histogramRqDuration, _ := metrics.NewHistogram("check_rq_duration_ms", "A histogram of duration for check requests",
		1, 2, 5, 10, 20, 100, 1000,
	)

	return &Policy{
		checker:             checker,
		checkLogger:         checkLogger,
		counterRqTotal:      counterRqTotal,
		counterRqFailed:     counterRqFailed,
		histogramRqDuration: histogramRqDuration,
	}
}

func (p *Policy) Check(_ context.Context, in policy.CheckInput) (*policy.CheckResult, error) {
	start := time.Now()

	defer func() {
		finish := time.Since(start)
		p.histogramRqDuration.Record(float64(finish.Milliseconds()), nil)
		p.counterRqTotal.Record(1, nil)
	}()

	result, err := p.checker.Check(in)
	if err != nil {
		p.counterRqFailed.Record(1, nil)
		return result, fmt.Errorf("policy check failed: %w", err)
	}

	if p.checkLogger != nil {
		p.checkLogger.Log(in, *result)
	}

	return result, nil
}

func (p *Policy) SetData(data []byte) error {
	// todo: may by logging?
	return p.checker.SetData(data)
}

func (p *Policy) Data() interface{} {
	return p.checker.Data()
}

func (p *Policy) SetPolicy(policy []byte) error {
	// todo: may by logging?
	return p.checker.SetPolicy(policy)
}

func (p *Policy) Policy() []byte {
	return p.checker.Policy()
}
