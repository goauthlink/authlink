// Copyright 2025 The AuthLink Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package policy

import (
	"testing"
)

func Benchmark_CheckBase(b *testing.B) {
	config := `
cn:
  - header: "x-source"
    prefix: "prefix:"
vars:
  var1: ["client1", "client4"]
policies:
  - uri: ["~/order/[0-9]+/info"]
    method: ["get"]
    allow: ["client1"]
  - uri: ["~/user/[0-9]+"]
    method: ["post"]
    allow: ["client1"]
  - uri: ["~/user/[0-9]+"]
    method: ["get"]
    allow: ["client1"]
  - uri: ["/ep2"]
    allow: ["prefix:client1"]
  - uri: ["/ep3"]
    allow: ["$var1"]`

	checker := NewChecker()
	pconfig, err := YamlToPolicyConfig([]byte(config))
	if err != nil {
		b.Fatal(err)
	}

	if err := checker.SetConfigs([]Config{*pconfig}); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := checker.Check(CheckInput{
			Uri:     "/user/1",
			Method:  "GET",
			Headers: map[string]string{"x-source": "client1"},
		})
		if err != nil {
			b.Fatal(err)
		}
	}
}

func Benchmark_JsonPath(b *testing.B) {
	config := `
cn:
  - header: "x-source"
vars:
  var1: ["{.team2[*].name}"]
policies:
  - uri: ["~/order/[0-9]+/info"]
    method: ["get"]
    allow: ["client2"]
  - uri: ["~/user/[0-9]+"]
    method: ["post"]
    allow: ["client3"]
  - uri: ["~/user/[0-9]+"]
    method: ["get"]
    allow: ["client2"]
  - uri: ["/ep2"]
    allow: ["prefix:{.team2[*].name}"]
  - uri: ["/ep3"]
    allow: ["$var1"]
  - uri: ["/ep1"]
    allow: ["{.team1[*].name}"]`

	data := []byte(`{
  "team1": [
    {
      "name": "client1" 
    },
    {
      "name": "client2"
    }
  ],
  "team2": [
    {
      "name": "client1"
    },
    {
      "name": "client2" 
    }
  ]
}`)

	checker := NewChecker()
	pconfig, err := YamlToPolicyConfig([]byte(config))
	if err != nil {
		b.Fatal(err)
	}

	if err := checker.SetConfigs([]Config{*pconfig}); err != nil {
		b.Fatal(err)
	}

	if err := checker.SetData(data); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := checker.Check(CheckInput{
			Uri:     "/ep1",
			Method:  "GET",
			Headers: map[string]string{"x-source": "client1"},
		})
		if err != nil {
			b.Fatal(err)
		}
		if result.Allow == false {
			b.Fatal("unexpected result, want true")
		}
	}
}
