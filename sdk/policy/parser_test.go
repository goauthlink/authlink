// Copyright 2025 The AuthLink Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package policy

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

type vaidationTestCase struct {
	name   string
	config string
	want   string
}

func Test_Validation(t *testing.T) {
	tcases := []vaidationTestCase{
		{
			config: `
cn:
  - header: "x-source"
policies:
  - uri: ["/ep1"]
    allow: ["client2"]
  - uri: ["/ep1"]
    method: ["get"]
    allow: ["client3"]`,
			want: fmt.Sprintf(validationErrDuplicatedUri, "*:/ep1"),
		},
		{
			config: `
cn:
  - header: "x-source"
policies:
  - uri: ["/ep1"]
    method: ["method"]
    allow: ["client2"]`,
			want: fmt.Sprintf(validationErrUndefinedHttpMethod, "method"),
		},
		{
			config: `
cn:
  - header: "x-source"
policies:
  - uri: ["/ep1"]
    method: ["get", "*"]
    allow: ["client2"]`,
			want: validationErrWildcardWithMethods,
		},
		{
			config: `
cn:
  - header: "x-source"
policies:
  - uri: [""]
    allow: ["client2"]`,
			want: validationErrEmptyUri,
		},
		{
			config: `
cn:
  - header: "x-source"
policies:
  - uri: []
    allow: ["client2"]`,
			want: validationErrAtLeastOneUriMustBeInRule,
		},
		{
			config: `
cn:
  - header: "x-source"
vars:
  var1: ["$var1"]
default:
  - "$var1"`,
			want: validationErrVarIsNotAllowedInThisSection,
		},
		{
			config: `
cn:
  - header: "x-source"
  - jwt:
      header: "jwt"
      cookie: "jwt"
default:
  - "*"`,
			want: validationErrHeaderOrCookieAsJWTSource,
		},
		{
			config: `
cn:
  - test: "test"
default:
  - "*"`,
			want: validationErrAtLeastOneCNSourceMustExist,
		},
	}

	for _, tcase := range tcases {
		t.Run(tcase.name, func(t *testing.T) {
			config := Config{}
			err := yaml.Unmarshal([]byte(tcase.config), &config)
			require.NoError(t, err)
			_, err = PrepareConfig(config)
			require.NotNil(t, err)
			require.ErrorContains(t, err, tcase.want)
		})
	}
}
