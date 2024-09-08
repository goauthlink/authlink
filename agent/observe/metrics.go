package observe

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/exporters/prometheus"
	api "go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/sdk/metric"
)

type Metrics interface {
	CheckRqTotalInc(ctx context.Context)
	CheckRqFailedInc(ctx context.Context)
	CheckRqDurationObserve(ctx context.Context, ms int64)
}

type agentMetrics struct {
	checkRqTotalCounter      api.Int64Counter
	checkRqFailedCounter     api.Int64Counter
	checkRqDurationHistogram api.Int64Histogram
}

const (
	checkRqTotalName    = "check_rq_total"
	checkRqFailedName   = "check_rq_failed"
	checkRqDurationName = "check_rq_duration"
)

func NewMetrics() (Metrics, error) {
	exporter, err := prometheus.New()
	if err != nil {
		return nil, fmt.Errorf("creating prometheus client: %w", err)
	}

	provider := metric.NewMeterProvider(metric.WithReader(exporter))

	meter := provider.Meter("auth-request-agent", api.WithInstrumentationAttributes())

	// metrics
	checkRqTotalCounter, err := meter.Int64Counter(checkRqTotalName,
		api.WithDescription("A counter of check requests"),
	)
	if err != nil {
		return nil, fmt.Errorf("creating metric %s: %w", checkRqTotalName, err)
	}

	checkRqFailedCounter, err := meter.Int64Counter(checkRqFailedName,
		api.WithDescription("A counter of failed check requests (500 response code)"),
	)
	if err != nil {
		return nil, fmt.Errorf("creating metric %s: %w", checkRqTotalName, err)
	}

	checkRqDurationHistogram, err := meter.Int64Histogram(checkRqDurationName,
		api.WithDescription("A histogram of duration for check requests"),
		api.WithExplicitBucketBoundaries(1, 2, 5, 10, 20, 100, 1000),
	)
	if err != nil {
		return nil, fmt.Errorf("creating metric %s: %w", checkRqTotalName, err)
	}

	metrics := agentMetrics{
		checkRqTotalCounter:      checkRqTotalCounter,
		checkRqFailedCounter:     checkRqFailedCounter,
		checkRqDurationHistogram: checkRqDurationHistogram,
	}

	return &metrics, nil
}

func (m *agentMetrics) CheckRqTotalInc(ctx context.Context) {
	m.checkRqTotalCounter.Add(ctx, 1)
}

func (m *agentMetrics) CheckRqFailedInc(ctx context.Context) {
	m.checkRqFailedCounter.Add(ctx, 1)
}

func (m *agentMetrics) CheckRqDurationObserve(ctx context.Context, ms int64) {
	m.checkRqDurationHistogram.Record(ctx, ms)
}
