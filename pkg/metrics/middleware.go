// Copyright 2025 The AuthLink Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package metrics

import (
	"net/http"
	"strconv"
	"time"
)

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rec *responseWriter) WriteHeader(code int) {
	rec.status = code
	rec.ResponseWriter.WriteHeader(code)
}

var httpTimeRqBucket = []float64{
	0.00005,
	0.0001,
	0.0005,
	0.001,
	0.003,
	0.005,
	0.01,
	0.03,
	0.06,
	0.1,
	0.3,
	0.6,
	1,
}

func NewHTTPMiddleware(h http.Handler) (http.Handler, error) {
	durationMetric, err := NewHistogram("http_request_time_seconds", "A histogram of duration for http requests.", httpTimeRqBucket...)
	if err != nil {
		return nil, err
	}

	rqCount, err := NewCounter("http_request_total", "Aggregate HTTP response codes (e.g., 2xx, 3xx, etc.)")
	if err != nil {
		return nil, err
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()
		rw := &responseWriter{w, 0}

		h.ServeHTTP(rw, r)

		attrs := map[string]string{
			"code": strconv.Itoa(rw.status),
			"url":  r.URL.Path,
		}

		duration := time.Since(startTime).Seconds()

		durationMetric.Record(duration, attrs)
		rqCount.Record(1, attrs)
	}), nil
}
