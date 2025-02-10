// Copyright 2025 The AuthLink Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package policy

import (
	"fmt"
	"net/http"
	"reflect"
	"testing"

	"github.com/goauthlink/authlink/pkg/testutils"
	"github.com/goauthlink/authlink/test/util"
)

type testCase struct {
	in              CheckInput
	allowed         bool
	wantedResultErr string
}

func initChecker(t *testing.T, checker *Checker, yamlPolicy, data []byte) {
	pconfig, err := YamlToPolicyConfig(yamlPolicy)
	if err != nil {
		t.Fatal(err)
	}

	if err := checker.SetConfigs([]Config{*pconfig}); err != nil {
		t.Fatal(err)
	}

	if len(data) > 0 {
		if err := checker.SetData(data); err != nil {
			t.Fatal(err)
		}
	}
}

func Test_QueryInVars(t *testing.T) {
	config := `
cn:
  - header: "x-source1"
  - header: "x-source2"
    prefix: "prefix:"
vars:
  var1: ["{.team1[*].name}"]
policies:
  - uri: ["/endpoint1"]
    allow: ["$var1", "{.team2[*].name}", "client5"]
  - uri: ["/endpoint2"]
    allow: ["prefix:{.team1[*].name}"]`

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
      "name": "client3"
    },
    {
      "name": "client4" 
    }
  ]
}`)

	// from vars
	checker := NewChecker()
	initChecker(t, checker, []byte(config), data)

	in := CheckInput{
		Uri:     "/endpoint1",
		Method:  http.MethodGet,
		Headers: map[string]string{"x-source1": "client1"},
	}
	result, err := checker.Check(in)

	testutils.AssertNoError(t, err)
	assertAllowed(t, result.Allow, true, in)

	// from query
	result, err = checker.Check(CheckInput{
		Uri:     "/endpoint1",
		Method:  http.MethodGet,
		Headers: map[string]string{"x-source1": "client1"},
	})

	testutils.AssertNoError(t, err)
	assertAllowed(t, result.Allow, true, in)

	// with prefix
	result, err = checker.Check(CheckInput{
		Uri:     "/endpoint2",
		Method:  http.MethodGet,
		Headers: map[string]string{"x-source2": "client1"},
	})

	testutils.AssertNoError(t, err)
	assertAllowed(t, result.Allow, true, in)
}

// todo: test multiple configs

func Test_InvalidateData(t *testing.T) {
	config := `
cn:
  - header: "x-source"
policies:
  - uri: ["/endpoint"]
    allow: ["{.team[*].name}"]
`

	data := []byte(`{
"team": [
    {
      "name": "client1" 
    },
    {
      "name": "client2"
    }
  ]
}`)

	checker := NewChecker()
	initChecker(t, checker, []byte(config), data)

	in := CheckInput{
		Uri:     "/endpoint",
		Method:  http.MethodGet,
		Headers: map[string]string{"x-source": "client1"},
	}
	result, err := checker.Check(in)

	testutils.AssertNoError(t, err)
	if !reflect.DeepEqual([]string{"client1", "client2"}, checker.dataCache["{.team[*].name}"]) {
		t.Fatalf("got %s", checker.dataCache["{.team[*].name}"])
	}
	assertAllowed(t, result.Allow, true, in)

	newData := []byte(`{
"team": [
    {
      "name": "client3" 
    },
    {
      "name": "client4"
    }
  ]
}`)

	testutils.AssertNoError(t, checker.SetData(newData))
	if _, exist := checker.dataCache["{.team[*].name}"]; exist {
		t.Fatal("{.team[*].name} exists in cache")
	}

	in = CheckInput{
		Uri:     "/endpoint",
		Method:  http.MethodGet,
		Headers: map[string]string{"x-source": "client1"},
	}
	result, err = checker.Check(in)

	if !reflect.DeepEqual([]string{"client3", "client4"}, checker.dataCache["{.team[*].name}"]) {
		t.Fatalf("got %s", checker.dataCache["{.team[*].name}"])
	}
	testutils.AssertNoError(t, err)
	assertAllowed(t, result.Allow, false, in)
}

func Test_Data(t *testing.T) {
	config := `
cn:
  - header: "x-source1"
  - header: "x-source2"
    prefix: "prefix:"
vars:
  var1: ["{.team2[*].name}"]
policies:
  - uri: ["/ep1"]
    allow: ["{.team1[*].name}"]
  - uri: ["/ep2"]
    allow: ["prefix:{.team2[*].name}"]
  - uri: ["/ep3"]
    allow: ["$var1"]
  - uri: ["/ep4"]
    allow: ["{.team3[*].name}"]
`

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
      "name": "client3"
    },
    {
      "name": "client4" 
    }
  ]
}`)

	checker := NewChecker()
	initChecker(t, checker, []byte(config), data)
	testutils.AssertNoError(t, checker.SetData(data))

	cases := []testCase{
		{
			in: CheckInput{
				Uri:     "/ep1",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source1": "client1"},
			},
			allowed: true,
		},
		{
			in: CheckInput{
				Uri:     "/ep1",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source1": "client2"},
			},
			allowed: true,
		},
		{
			in: CheckInput{
				Uri:     "/ep1",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source1": "client3"},
			},
			allowed: false,
		},
		// prefix
		{
			in: CheckInput{
				Uri:     "/ep2",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source2": "client3"},
			},
			allowed: true,
		},
		{
			in: CheckInput{
				Uri:     "/ep2",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source2": "client4"},
			},
			allowed: true,
		},
		{
			in: CheckInput{
				Uri:     "/ep2",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source1": "client2"},
			},
			allowed: false,
		},
		// vars
		{
			in: CheckInput{
				Uri:     "/ep3",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source1": "client3"},
			},
			allowed: true,
		},
		{
			in: CheckInput{
				Uri:     "/ep3",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source1": "client4"},
			},
			allowed: true,
		},
		// data not found
		{
			in: CheckInput{
				Uri:     "/ep4",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source1": "client3"},
			},
			allowed:         false,
			wantedResultErr: "jsonpath finding results failure: team3 is not found",
		},
	}

	for _, c := range cases {
		t.Run("case", func(t *testing.T) {
			result, err := checker.Check(c.in)
			testutils.AssertNoError(t, err)
			assertAllowed(t, result.Allow, c.allowed, c.in)
			assertWantedErrEqual(t, *result, c.wantedResultErr)
		})
	}
}

func Test_Vars(t *testing.T) {
	config := `
cn:
  - header: "x-source1"
  - header: "x-source2"
    prefix: "prefix:"
vars:
  var1: ["client1"]
  var2: ["client2"]
  var3: ["prefix:client3"]
policies:
  - uri: ["/ep1"]
    allow: ["$var1"]
  - uri: ["/ep2"]
    allow: ["$var2", "$var3"]`

	checker := NewChecker()
	initChecker(t, checker, []byte(config), []byte{})

	cases := []testCase{
		{
			in: CheckInput{
				Uri:     "/ep1",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source1": "client1"},
			},
			allowed: true,
		},
		{
			in: CheckInput{
				Uri:     "/ep1",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source1": "client2"},
			},
			allowed: false,
		},
		{
			in: CheckInput{
				Uri:     "/ep2",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source1": "client2"},
			},
			allowed: true,
		},
		{
			in: CheckInput{
				Uri:    "/ep2",
				Method: http.MethodGet,
			},
			allowed: false,
		},
		{
			in: CheckInput{
				Uri:     "/ep2",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source2": "client3"},
			},
			allowed: true,
		},
	}

	for _, c := range cases {
		result, err := checker.Check(c.in)
		testutils.AssertNoError(t, err)
		assertAllowed(t, result.Allow, c.allowed, c.in)
	}
}

func Test_ClientNameWildCard(t *testing.T) {
	config := `
cn:
  - header: "x-source1"
  - header: "x-source2"
    prefix: "prefix:"
policies:
  - uri: ["/ep1"]
    allow: ["prefix:*"]
  - uri: ["/ep2"]
    allow: ["*"]`

	checker := NewChecker()
	initChecker(t, checker, []byte(config), []byte{})

	cases := []testCase{
		{
			in: CheckInput{
				Uri:     "/ep1",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source2": "client1"},
			},
			allowed: true,
		},
		{
			in: CheckInput{
				Uri:     "/ep1",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source2": "client2"},
			},
			allowed: true,
		},
		{
			in: CheckInput{
				Uri:     "/ep1",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source3": "client3"},
			},
			allowed: false,
		},
		{
			in: CheckInput{
				Uri:     "/ep2",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source1": "client1"},
			},
			allowed: true,
		},
		{
			in: CheckInput{
				Uri:     "/ep2",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source2": "client1"},
			},
			allowed: false,
		},
	}

	for _, c := range cases {
		result, err := checker.Check(c.in)
		testutils.AssertNoError(t, err)
		assertAllowed(t, result.Allow, c.allowed, c.in)
	}
}

func Test_JWT_TokenValidation(t *testing.T) {
	rootDir, cleanFs, err := util.MakeTmpFs("", t.Name(), map[string][]byte{
		"/keyfile1.key": []byte("secret"),
		"/keyfile2.key": []byte("invalid_secret"),
	})
	testutils.AssertNoError(t, err)
	defer cleanFs()

	config := `
cn:
  - jwt: 
      payload: "user"
      header: "Auth1"
      keyFile: "` + rootDir + `/keyfile1.key"
    prefix: "jwt1:"
  - jwt: 
      payload: "user"
      header: "Auth2"
      keyFile: "` + rootDir + `/keyfile2.key"
    prefix: "jwt2:"
policies:
  - uri: ["/ep1"]
    allow: ["jwt1:jhon", "jwt2:jhon"]`

	checker := NewChecker()
	initChecker(t, checker, []byte(config), []byte{})

	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiamhvbiJ9.RO0UD8zn-NRJ7XlIuQMfeyoxLclFPF7N5PRkIJMgsck" // payload with user:jhon

	cases := []testCase{
		{
			in: CheckInput{
				Uri:     "/ep1",
				Headers: map[string]string{"Auth1": jwt},
			},
			allowed: true,
		},
		{
			in: CheckInput{
				Uri:     "/ep1",
				Headers: map[string]string{"Auth2": jwt},
			},
			wantedResultErr: "parse jwt token: token signature is invalid: signature is invalid",
			allowed:         false,
		},
	}

	for _, c := range cases {
		result, err := checker.Check(c.in)
		testutils.AssertNoError(t, err)
		assertWantedErrEqual(t, *result, c.wantedResultErr)
		assertAllowed(t, result.Allow, c.allowed, c.in)
	}
}

func Test_JWT_PayloadParser(t *testing.T) {
	config := `
cn:
  - header: "x-source"
  - jwt: 
      payload: "user"
      header: "Authorization"
    prefix: "jwt:"
  - jwt:
      payload: "user"
      cookie: "jwt"
    prefix: "cookie:"
policies:
  - uri: ["/ep1"]
    allow: ["jwt:jhon", "cookie:jhon"]
  - uri: ["/ep2"]
    allow: ["jessica"]`

	checker := NewChecker()
	initChecker(t, checker, []byte(config), []byte{})

	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiamhvbiJ9.aFR_EpsSSaquZiO8ow8ygy_RvNyMBPfBMPnNA9jyEDM" // payload with user:jhon

	cases := []testCase{
		{
			in: CheckInput{
				Uri:     "/ep1",
				Headers: map[string]string{"Cookie": "some-cookie=test; jwt=" + jwt},
			},
			allowed: true,
		},
		{
			in: CheckInput{
				Uri:     "/ep1",
				Headers: map[string]string{"x-source": "client1"},
			},
			allowed: false,
		},
		{
			in: CheckInput{
				Uri:     "/ep2",
				Headers: map[string]string{"Authorization": jwt},
			},
			allowed: false,
		},
		{
			in: CheckInput{
				Uri:     "/ep1",
				Headers: map[string]string{"Authorization": jwt},
			},
			allowed: true,
		},
		{
			in: CheckInput{
				Uri:     "/ep1",
				Headers: map[string]string{"Authorization": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjp7Im5hbWUiOiJqaG9uIn19.Jk_NZmxy5LkxGjS_dhvDq-yXxvTs6xSNxErHoen9qhs"},
			},
			allowed:         false,
			wantedResultErr: fmt.Sprintf(errPayloadFieldIsntStringType, "user", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjp7Im5hbWUiOiJqaG9uIn19.Jk_NZmxy5LkxGjS_dhvDq-yXxvTs6xSNxErHoen9qhs"),
		},
	}

	for _, c := range cases {
		result, err := checker.Check(c.in)
		testutils.AssertNoError(t, err)
		assertWantedErrEqual(t, *result, c.wantedResultErr)
		assertAllowed(t, result.Allow, c.allowed, c.in)
	}
}

func Test_DefaultPolicy(t *testing.T) {
	config := `
cn:
  - header: "x-source"
default:
  - client1`

	checker := NewChecker()
	initChecker(t, checker, []byte(config), []byte{})

	cases := []testCase{
		{
			in: CheckInput{
				Uri:     "/get",
				Headers: map[string]string{"x-source": "client1"},
			},
			allowed: true,
		},
		{
			in: CheckInput{
				Uri:     "/get",
				Headers: map[string]string{"x-source": "client2"},
			},
			allowed: false,
		},
		{
			in: CheckInput{
				Uri:     "/get",
				Headers: map[string]string{"x-source1": "client1"},
			},
			allowed: false,
		},
	}

	for _, c := range cases {
		result, err := checker.Check(c.in)
		testutils.AssertNoError(t, err)
		assertAllowed(t, result.Allow, c.allowed, c.in)
	}
}

func Test_CnPriority(t *testing.T) {
	config := `
cn:
  - header: "x-source1"
  - header: "x-source2"
    prefix: "prefix:"
policies:
  - uri: ["/ep1"]
    method: ["get"]
    allow: ["prefix:client1"]`

	checker := NewChecker()
	initChecker(t, checker, []byte(config), []byte{})

	cases := []testCase{
		{
			in: CheckInput{
				Uri:     "/ep1",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source1": "client2", "x-source2": "client1"},
			},
			allowed: false,
		},
		{
			in: CheckInput{
				Uri:     "/ep1",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source2": "client1"},
			},
			allowed: true,
		},
	}

	for _, c := range cases {
		result, err := checker.Check(c.in)
		testutils.AssertNoError(t, err)
		assertAllowed(t, result.Allow, c.allowed, c.in)
	}
}

func Test_MatchWithoutMethod(t *testing.T) {
	config := `
cn:
  - header: "x-source"
policies:
  - uri: ["/user"]
    allow: ["client1"]
  - uri: ["~/info"]
    allow: ["client2"]`

	checker := NewChecker()
	initChecker(t, checker, []byte(config), []byte{})

	cases := []testCase{
		{
			in: CheckInput{
				Uri:     "/user",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source": "client1"},
			},
			allowed: true,
		},
		{
			in: CheckInput{
				Uri:     "/user",
				Method:  http.MethodDelete,
				Headers: map[string]string{"x-source": "client1"},
			},
			allowed: true,
		},
		{
			in: CheckInput{
				Uri:     "/info",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source": "client2"},
			},
			allowed: true,
		},
		{
			in: CheckInput{
				Uri:     "/info",
				Method:  http.MethodDelete,
				Headers: map[string]string{"x-source": "client2"},
			},
			allowed: true,
		},
	}

	for _, c := range cases {
		result, err := checker.Check(c.in)
		testutils.AssertNoError(t, err)
		assertAllowed(t, result.Allow, c.allowed, c.in)
	}
}

func Test_MatchSimpleUri(t *testing.T) {
	config := `
cn:
  - header: "x-source"
policies:
  - uri: ["/user"]
    method: ["get"]
    allow: ["client2"]
  - uri: ["/user"]
    method: ["put"]
    allow: ["client3"]`

	checker := NewChecker()
	initChecker(t, checker, []byte(config), []byte{})

	cases := []testCase{
		// get
		{
			in: CheckInput{
				Uri:     "/user",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source": "client1"},
			},
			allowed: false,
		},
		{
			in: CheckInput{
				Uri:     "/user",
				Method:  http.MethodPut,
				Headers: map[string]string{"x-source": "client2"},
			},
			allowed: false,
		},
		{
			in: CheckInput{
				Uri:     "/user",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source": "client2"},
			},
			allowed: true,
		},
		// put
		{
			in: CheckInput{
				Uri:     "/user",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source": "client3"},
			},
			allowed: false,
		},
		{
			in: CheckInput{
				Uri:     "/user",
				Method:  http.MethodPut,
				Headers: map[string]string{"x-source": "client3"},
			},
			allowed: true,
		},
		{
			in: CheckInput{
				Uri:     "/user",
				Method:  http.MethodPut,
				Headers: map[string]string{"x-source": "client2"},
			},
			allowed: false,
		},
	}

	for _, c := range cases {
		result, err := checker.Check(c.in)
		testutils.AssertNoError(t, err)
		assertAllowed(t, result.Allow, c.allowed, c.in)
	}
}

func Test_PolicyPrioriy_RegexVsSimple(t *testing.T) {
	config := `
cn:
  - header: "x-source"
policies:
  - uri: ["~/user/[0-9]+"]
    method: ["get"]
    allow: ["client1"]
  - uri: ["/user/1"]
    method: ["get"]
    allow: ["client2"]`

	checker := NewChecker()
	initChecker(t, checker, []byte(config), []byte{})

	cases := []testCase{
		{
			in: CheckInput{
				Uri:     "/user/1",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source": "client2"},
			},
			allowed: true,
		},
		{
			in: CheckInput{
				Uri:     "/user/1",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source": "client1"},
			},
			allowed: false,
		},
	}

	for _, c := range cases {
		result, err := checker.Check(c.in)
		testutils.AssertNoError(t, err)
		assertAllowed(t, result.Allow, c.allowed, c.in)
	}
}

func Test_PolicyPrioriy_RegexVsRegex(t *testing.T) {
	config := `
cn:
  - header: "x-source"
policies:
  - uri: ["~/us(.+)"]
    method: ["get"]
    allow: ["client1"]
  - uri: ["~/user/[0-9]+"]
    method: ["get"]
    allow: ["client2"]`

	checker := NewChecker()
	initChecker(t, checker, []byte(config), []byte{})

	cases := []testCase{
		{
			in: CheckInput{
				Uri:     "/user/1",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source": "client2"},
			},
			allowed: true,
		},
		{
			in: CheckInput{
				Uri:     "/user/1",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source": "client1"},
			},
			allowed: false,
		},
	}

	for _, c := range cases {
		result, err := checker.Check(c.in)
		testutils.AssertNoError(t, err)
		assertAllowed(t, result.Allow, c.allowed, c.in)
	}
}

func Test_MatchRegexpUri(t *testing.T) {
	config := `
cn:
  - header: "x-source"
policies:
  - uri: ["~/user/[0-9]+", "~/order/[0-9]+/info"]
    method: ["get"]
    allow: ["client2"]
  - uri: ["~/user/[0-9]+"]
    method: ["post"]
    allow: ["client3"]`

	checker := NewChecker()
	initChecker(t, checker, []byte(config), []byte{})

	cases := []testCase{
		// GET user/*
		{
			in: CheckInput{
				Uri:     "/user/1",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source": "client2"},
			},
			allowed: true,
		},
		{
			in: CheckInput{
				Uri:     "/order/1/info",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source": "client2"},
			},
			allowed: true,
		},
		{
			in: CheckInput{
				Uri:     "/user/1",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source": "client1"},
			},
			allowed: false,
		},
		{
			in: CheckInput{
				Uri:     "/order/1/info",
				Method:  http.MethodGet,
				Headers: map[string]string{"x-source": "client1"},
			},
			allowed: false,
		},
		// POST user/*
		{
			in: CheckInput{
				Uri:     "/user/1",
				Method:  http.MethodPost,
				Headers: map[string]string{"x-source": "client1"},
			},
			allowed: false,
		},
		{
			in: CheckInput{
				Uri:     "/user/1",
				Method:  http.MethodPost,
				Headers: map[string]string{"x-source": "client3"},
			},
			allowed: true,
		},
		// denied
		{
			in: CheckInput{
				Uri:     "/user/1",
				Method:  http.MethodPost,
				Headers: map[string]string{"x-source": "client1"},
			},
			allowed: false,
		},
		{
			in: CheckInput{
				Uri:     "/user/1",
				Method:  http.MethodPost,
				Headers: map[string]string{"x-source": "client3"},
			},
			allowed: true,
		},
	}

	for _, c := range cases {
		result, err := checker.Check(c.in)
		testutils.AssertNoError(t, err)
		assertAllowed(t, result.Allow, c.allowed, c.in)
	}
}

func assertAllowed(t *testing.T, got, wanted bool, in CheckInput) {
	t.Helper()
	if got != wanted {
		t.Fatalf("got '%t' but got '%t' url: %s, method: %s", got, wanted, in.Uri, in.Method)
	}
}

func assertWantedErrEqual(t *testing.T, got CheckResult, wanted string) {
	if len(wanted) > 0 {
		testutils.AssertErrorContains(t, got.Err, wanted)
	} else {
		testutils.AssertNoError(t, got.Err)
	}
}
