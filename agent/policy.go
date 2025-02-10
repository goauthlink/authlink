// Copyright 2025 The AuthLink Authors. All rights reserved.
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

type PolicyChecker interface {
	Check(_ context.Context, in policy.CheckInput) (*policy.CheckResult, error)
	SetData(data []byte) error
	Data() interface{}
	SetConfigs(configs []policy.Config) error
	Configs() []policy.Config
}

type agentChecker struct {
	checker             *policy.Checker
	checkLogger         *CheckLogger
	counterRqTotal      metrics.Metric
	counterRqFailed     metrics.Metric
	histogramRqDuration metrics.Metric
}

func NewPolicyChecker(
	checker *policy.Checker,
	checkLogger *CheckLogger,
) *agentChecker {
	counterRqTotal, _ := metrics.NewCounter("check_rq_total", "A counter of check requests")
	counterRqFailed, _ := metrics.NewCounter("check_rq_failed", "A counter of failed check requests (500 response code)")
	histogramRqDuration, _ := metrics.NewHistogram("check_rq_duration_ms", "A histogram of duration for check requests",
		1, 2, 5, 10, 20, 100, 1000,
	)

	return &agentChecker{
		checker:             checker,
		checkLogger:         checkLogger,
		counterRqTotal:      counterRqTotal,
		counterRqFailed:     counterRqFailed,
		histogramRqDuration: histogramRqDuration,
	}
}

func (p *agentChecker) Check(_ context.Context, in policy.CheckInput) (*policy.CheckResult, error) {
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

func (p *agentChecker) SetData(data []byte) error {
	// todo: may by logging?
	return p.checker.SetData(data)
}

func (p *agentChecker) Data() interface{} {
	return p.checker.Data()
}

func (p *agentChecker) SetConfigs(policy []policy.Config) error {
	// todo: may by logging?
	return p.checker.SetConfigs(policy)
}

func (p *agentChecker) Configs() []policy.Config {
	return p.checker.Policy()
}
