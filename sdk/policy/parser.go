// Copyright 2025 The AuthLink Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package policy

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"

	"k8s.io/client-go/util/jsonpath"
)

type preparedParser struct {
	Prefix     string
	JsonParser *jsonpath.JSONPath
	Jsonpath   string
}

type preparedAllow struct {
	clients []string
	parsers []preparedParser
}

type preparedPolicy struct {
	RegexUri *regexp.Regexp
	Uri      string
	Method   []string
	Allow    preparedAllow
	Priority int
}

type preparedConfig struct {
	Cn       []Cn
	Default  preparedAllow
	Policies []preparedPolicy
}

const (
	validationErrDuplicatedUri                = "duplicated method:uri found (wildcard including): %s"
	validationErrUndefinedHttpMethod          = "undefined http method: %s"
	validationErrWildcardWithMethods          = "http method wildcard must not be used with other methods"
	validationErrEmptyUri                     = "empty uri"
	validationErrAtLeastOneUriMustBeInRule    = "at least one uri must be in the rule"
	validationErrVarIsNotAllowedInThisSection = "variables is not allowed in this section"
	validationErrHeaderOrCookieAsJWTSource    = "header or cookie may be used at the same time as a jwt source"
	validationErrAtLeastOneCNSourceMustExist  = "at least one client name source must exist"
	errLoadJWTKeyFile                         = "loading JWT key file: %s"
)

func PrepareConfig(config Config) (*preparedConfig, error) {
	// prepare client names
	for _, cn := range config.Cn {
		if cn.JWT != nil {
			if cn.JWT.Cookie != nil && cn.JWT.Header != nil {
				return nil, errors.New(validationErrHeaderOrCookieAsJWTSource)
			}
			if cn.JWT.KeyFile != nil {
				d, err := os.ReadFile(*cn.JWT.KeyFile)
				if err != nil {
					return nil, fmt.Errorf(errLoadJWTKeyFile, *cn.JWT.KeyFile)
				}
				cn.JWT.KeyFileData = d
			}
		}

		if cn.JWT == nil && cn.Header == nil {
			return nil, errors.New(validationErrAtLeastOneCNSourceMustExist)
		}
	}

	// prepare policies
	uriUnique := map[string]struct{}{}
	for pi, policy := range config.Policies {
		if len(policy.Uri) == 0 {
			return nil, errors.New(validationErrAtLeastOneUriMustBeInRule)
		}

		if len(policy.Methods) == 0 {
			config.Policies[pi].Methods = []string{"*"}
		} else {
			for mi, m := range policy.Methods {
				ml := strings.ToUpper(m)
				if !slices.Contains([]string{
					http.MethodGet,
					http.MethodPost,
					http.MethodPut,
					http.MethodPatch,
					http.MethodDelete,
					http.MethodTrace,
					http.MethodHead,
					http.MethodConnect,
					http.MethodOptions,
				}, ml) {
					if m == "*" {
						return nil, errors.New(validationErrWildcardWithMethods)
					}
					return nil, fmt.Errorf(validationErrUndefinedHttpMethod, m)
				}
				config.Policies[pi].Methods[mi] = ml
			}
		}

		for _, uri := range policy.Uri {
			if len(uri) == 0 {
				return nil, errors.New(validationErrEmptyUri)
			}

			for _, m := range config.Policies[pi].Methods {
				if _, ok := uriUnique[uri+":"+m]; ok {
					return nil, fmt.Errorf(validationErrDuplicatedUri, m+":"+uri)
				}
				if _, ok := uriUnique[uri+":*"]; ok {
					return nil, fmt.Errorf(validationErrDuplicatedUri, "*:"+uri)
				}
				uriUnique[uri+":"+m] = struct{}{}
			}

			// todo: validate uri format
		}
	}

	prepDefault, err := prepareAllow(config.Default, config.Vars)
	if err != nil {
		return nil, fmt.Errorf("fail to parse client: %s", err.Error())
	}
	preparedConfig := preparedConfig{
		Cn:      config.Cn,
		Default: *prepDefault,
	}

	prepPolicies := []preparedPolicy{}

	for _, policy := range config.Policies {
		for _, uri := range policy.Uri {
			prepAllow, err := prepareAllow(policy.Allow, config.Vars)
			if err != nil {
				return nil, fmt.Errorf("fail to parse client: %s", err.Error())
			}
			if uri[0] == '~' {
				uri = "^" + strings.TrimLeft(uri, "~") + "$"
				preparedPolicy := preparedPolicy{
					RegexUri: regexp.MustCompile(uri),
					Method:   policy.Methods,
					Allow:    *prepAllow,
					Priority: len(uri),
				}
				prepPolicies = append(prepPolicies, preparedPolicy)
			} else {
				preparedPolicy := preparedPolicy{
					Uri:      uri,
					Method:   policy.Methods,
					Allow:    *prepAllow,
					Priority: 9999999,
				}
				prepPolicies = append(prepPolicies, preparedPolicy)
			}
			// todo: what should we do?
		}
	}

	sort.Slice(prepPolicies, func(i, j int) bool {
		// todo: same priorities
		return prepPolicies[i].Priority >= prepPolicies[j].Priority
	})

	preparedConfig.Policies = prepPolicies

	return &preparedConfig, nil
}

func prepareAllow(allow []string, vars Variables) (*preparedAllow, error) {
	prepAllow := &preparedAllow{}

	for _, a := range allow {
		if len(a) == 0 {
			return nil, fmt.Errorf("empty client name")
		}

		if idx := strings.Index(a, "{"); idx >= 0 {
			prepParser := preparedParser{}
			if idx > 0 {
				prepParser.Prefix = a[:idx]
			}
			prepParser.Jsonpath = a[idx:]

			prepParser.JsonParser = jsonpath.New("")
			if err := prepParser.JsonParser.Parse(prepParser.Jsonpath); err != nil {
				return nil, fmt.Errorf("fail to parse jsonpath: %s: %s", a, err.Error())
			}
			prepAllow.parsers = append(prepAllow.parsers, prepParser)

			continue
		}

		if a[0] == '$' {
			if vars == nil {
				return nil, errors.New(validationErrVarIsNotAllowedInThisSection)
			}
			v, ok := vars[strings.TrimPrefix(a, "$")]
			if !ok {
				return nil, fmt.Errorf("undefined variable %s", a)
			}

			vClients, err := prepareAllow(v, nil)
			if err != nil {
				return nil, err
			}

			prepAllow.clients = append(prepAllow.clients, vClients.clients...)
			prepAllow.parsers = append(prepAllow.parsers, vClients.parsers...)

			continue
		}

		prepAllow.clients = append(prepAllow.clients, a)
	}

	return prepAllow, nil
}
