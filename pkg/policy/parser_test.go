// Copyright 2024 The AuthPolicyController Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package policy

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
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
	}

	for _, tcase := range tcases {
		t.Run(tcase.name, func(t *testing.T) {
			_, err := PrepareConfig([]byte(tcase.config))
			require.NotNil(t, err)
			require.ErrorContains(t, err, tcase.want)
		})
	}
}
