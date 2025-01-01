package agent

import (
	"context"
	"fmt"
	"time"

	"github.com/goauthlink/authlink/agent/observe"
	"github.com/goauthlink/authlink/sdk/policy"
)

type Policy struct {
	checker     *policy.Checker
	checkLogger *CheckLogger
	metrics     observe.Metrics
}

func NewPolicy(
	checker *policy.Checker,
	checkLogger *CheckLogger,
	metrics observe.Metrics,
) *Policy {
	return &Policy{
		checker:     checker,
		checkLogger: checkLogger,
		metrics:     metrics,
	}
}

func (p *Policy) Check(ctx context.Context, in policy.CheckInput) (*policy.CheckResult, error) {
	start := time.Now()

	defer func() {
		finish := time.Since(start)
		if p.metrics != nil {
			p.metrics.CheckRqDurationObserve(ctx, finish.Milliseconds())
			p.metrics.CheckRqTotalInc(ctx)
		}
	}()

	result, err := p.checker.Check(in)
	if err != nil {
		p.metrics.CheckRqFailedInc(ctx)
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
