package policy

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testCase struct {
	name    string
	in      CheckInput
	allowed bool
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
`

	prepCfg, err := PrepareConfig([]byte(config))
	require.NoError(t, err)

	data := map[string][]struct {
		name string
	}{
		"team1": {
			{name: "client1"},
			{name: "client2"},
		},
		"team2": {
			{name: "client3"},
			{name: "client4"},
		},
	}

	checker := NewChecker(prepCfg)
	checker.UpdateData(data)

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
	}

	for _, c := range cases {
		allowed, err := checker.Check(c.in)
		assert.NoError(t, err)
		assert.Equal(t, c.allowed, allowed, "url: %s, method: %s", c.in.Uri, c.in.Method)
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

	prepCfg, err := PrepareConfig([]byte(config))
	require.NoError(t, err)

	checker := NewChecker(prepCfg)

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
		allowed, err := checker.Check(c.in)
		assert.NoError(t, err)
		assert.Equal(t, c.allowed, allowed, "url: %s, method: %s, x-source: %s", c.in.Uri, c.in.Method, c.in.Headers["x-source"])
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

	prepCfg, err := PrepareConfig([]byte(config))
	require.NoError(t, err)

	checker := NewChecker(prepCfg)

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
		allowed, err := checker.Check(c.in)
		assert.NoError(t, err)
		assert.Equal(t, c.allowed, allowed, "url: %s, method: %s, x-source: %s", c.in.Uri, c.in.Method, c.in.Headers["x-source"])
	}
}

func Test_DefaultPolicy(t *testing.T) {
	config := `
cn:
  - header: "x-source"
default:
  - client1`

	prepCfg, err := PrepareConfig([]byte(config))
	require.NoError(t, err)

	checker := NewChecker(prepCfg)

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
		allowed, err := checker.Check(c.in)
		assert.NoError(t, err)
		assert.Equal(t, c.allowed, allowed)
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

	prepCfg, err := PrepareConfig([]byte(config))
	require.NoError(t, err)

	checker := NewChecker(prepCfg)

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
		allowed, err := checker.Check(c.in)
		assert.NoError(t, err)
		assert.Equal(t, c.allowed, allowed, "url: %s, method: %s, x-source: %s", c.in.Uri, c.in.Method, c.in.Headers["x-source"])
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

	prepCfg, err := PrepareConfig([]byte(config))
	require.NoError(t, err)

	checker := NewChecker(prepCfg)

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
		allowed, err := checker.Check(c.in)
		assert.NoError(t, err)
		assert.Equal(t, c.allowed, allowed, "url: %s, method: %s, x-source: %s", c.in.Uri, c.in.Method, c.in.Headers["x-source"])
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

	prepCfg, err := PrepareConfig([]byte(config))
	require.NoError(t, err)

	checker := NewChecker(prepCfg)

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
		allowed, err := checker.Check(c.in)
		assert.NoError(t, err)
		assert.Equal(t, c.allowed, allowed, "url: %s, method: %s, x-source: %s", c.in.Uri, c.in.Method, c.in.Headers["x-source"])
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

	prepCfg, err := PrepareConfig([]byte(config))
	require.NoError(t, err)

	checker := NewChecker(prepCfg)

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
		allowed, err := checker.Check(c.in)
		assert.NoError(t, err)
		assert.Equal(t, c.allowed, allowed, "url: %s, method: %s, x-source: %s", c.in.Uri, c.in.Method, c.in.Headers["x-source"])
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

	prepCfg, err := PrepareConfig([]byte(config))
	require.NoError(t, err)

	checker := NewChecker(prepCfg)

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
		allowed, err := checker.Check(c.in)
		assert.NoError(t, err)
		assert.Equal(t, c.allowed, allowed, "url: %s, method: %s, x-source: %s", c.in.Uri, c.in.Method, c.in.Headers["x-source"])
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

	prepCfg, err := PrepareConfig([]byte(config))
	require.NoError(t, err)

	checker := NewChecker(prepCfg)

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
		allowed, err := checker.Check(c.in)
		assert.NoError(t, err)
		assert.Equal(t, c.allowed, allowed, "url: %s, method: %s, x-source: %s", c.in.Uri, c.in.Method, c.in.Headers["x-source"])
	}
}
