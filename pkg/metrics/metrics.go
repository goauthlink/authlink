// Copyright 2024 The AuthLink Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package metrics

import (
	"context"
	"fmt"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	otelprom "go.opentelemetry.io/otel/exporters/prometheus"
	api "go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/sdk/metric"
)

var meter = func() api.Meter {
	return otel.GetMeterProvider().Meter("authlink-agent")
}

type Metric interface {
	Record(val float64, attr map[string]string)
}

func RegisterPrometheusExporter() (http.Handler, error) {
	promOpts := []otelprom.Option{
		otelprom.WithoutScopeInfo(),
		otelprom.WithoutTargetInfo(),
		otelprom.WithoutUnits(),
		otelprom.WithoutCounterSuffixes(),
	}

	prom, err := otelprom.New(promOpts...)
	if err != nil {
		return nil, fmt.Errorf("creating prometheus client: %w", err)
	}

	mp := metric.NewMeterProvider(metric.WithReader(prom))
	otel.SetMeterProvider(mp)

	handler := promhttp.HandlerFor(prometheus.DefaultGatherer, promhttp.HandlerOpts{})

	return handler, nil
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

func withAttrs(attr map[string]string) api.MeasurementOption {
	kv := make([]attribute.KeyValue, 0, len(attr))
	for k, v := range attr {
		kv = append(kv, attribute.Key(k).String(v))
	}

	return api.WithAttributes(kv...)
}

func (c *counter) Record(val float64, attr map[string]string) {
	opts := []api.AddOption{}
	if len(attr) > 0 {
		opts = append(opts, withAttrs(attr))
	}

	c.c.Add(context.Background(), val, opts...)
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

func (h *histogram) Record(val float64, attr map[string]string) {
	opts := []api.RecordOption{}
	if len(attr) > 0 {
		opts = append(opts, withAttrs(attr))
	}

	h.h.Record(context.Background(), val, opts...)
}
