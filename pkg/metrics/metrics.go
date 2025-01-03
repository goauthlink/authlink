// Copyright 2024 The AuthLink Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package metrics

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel"
	api "go.opentelemetry.io/otel/metric"
)

var meter = func() api.Meter {
	return otel.GetMeterProvider().Meter("authlink-agent")
}

type Metric interface {
	Record(ctx context.Context, val float64)
}

type counter struct {
	c api.Float64Counter
}

func NewCounter(name, desc string) (Metric, error) {
	apiCounter, err := meter().Float64Counter(name, api.WithDescription(desc))
	if err != nil {
		return nil, fmt.Errorf("new otel float64 counter %s: %w", name, err)
	}
	return &counter{
		c: apiCounter,
	}, nil
}

func (c *counter) Record(ctx context.Context, val float64) {
	c.c.Add(ctx, val)
}

type histogram struct {
	h api.Float64Histogram
}

func NewHistogram(name, desc string, bounds ...float64) (Metric, error) {
	apiHistogram, err := meter().Float64Histogram(name,
		api.WithDescription(desc),
		api.WithExplicitBucketBoundaries(bounds...),
	)
	if err != nil {
		return nil, fmt.Errorf("new otel float64 histogram %s: %w", name, err)
	}

	return &histogram{
		h: apiHistogram,
	}, nil
}

func (h *histogram) Record(ctx context.Context, val float64) {
	h.h.Record(ctx, val)
}
