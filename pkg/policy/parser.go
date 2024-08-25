// Copyright 2024 The AuthPolicyController Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package policy

import (
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
	"k8s.io/client-go/util/jsonpath"
)

type Cn struct {
	Prefix string `yaml:"prefix"`
	Header string `yaml:"header"`
}

type Policy struct {
	Uri     []string `yaml:"uri"`
	Methods []string `yaml:"method"`
	Allow   []string `yaml:"allow"`
}

type Variables map[string][]string

type Config struct {
	Cn       []Cn      `yaml:"cn"`
	Vars     Variables `yaml:"vars"`
	Default  []string  `yaml:"default"`
	Policies []Policy  `yaml:"policies"`
}

type preparedParser struct {
	Prefix     string
	JsonParser *jsonpath.JSONPath
}

type preparedAllow struct {
	clients     []string
	jsonParsers []preparedParser
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
)

func PrepareConfig(config []byte) (*preparedConfig, error) {
	c := Config{}

	err := yaml.Unmarshal(config, &c)
	if err != nil {
		return nil, err
	}

	uriUnique := map[string]struct{}{}
	for pi, policy := range c.Policies {
		if len(policy.Uri) == 0 {
			return nil, fmt.Errorf(validationErrAtLeastOneUriMustBeInRule)
		}

		if len(policy.Methods) == 0 {
			c.Policies[pi].Methods = []string{"*"}
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
						return nil, fmt.Errorf(validationErrWildcardWithMethods)
					}
					return nil, fmt.Errorf(validationErrUndefinedHttpMethod, m)
				}
				c.Policies[pi].Methods[mi] = ml
			}
		}

		for _, uri := range policy.Uri {
			if len(uri) == 0 {
				return nil, fmt.Errorf(validationErrEmptyUri)
			}

			for _, m := range c.Policies[pi].Methods {
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

	prepDefault, err := prepareAllow(c.Default, c.Vars)
	if err != nil {
		return nil, fmt.Errorf("fail to parse client: %s", err.Error())
	}
	preparedConfig := preparedConfig{
		Cn:      c.Cn,
		Default: *prepDefault,
	}

	prepPolicies := []preparedPolicy{}

	for _, policy := range c.Policies {
		for _, uri := range policy.Uri {
			prepAllow, err := prepareAllow(policy.Allow, c.Vars)
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
		// todo: обработать одинаковые priority
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
				a = a[idx:]
			}

			prepParser.JsonParser = jsonpath.New("")
			if err := prepParser.JsonParser.Parse(a); err != nil {
				return nil, fmt.Errorf("fail to parse jsonpath: %s: %s", a, err.Error())
			}
			prepAllow.jsonParsers = append(prepAllow.jsonParsers, prepParser)

			continue
		}

		if a[0] == '$' {
			if vars == nil {
				return nil, fmt.Errorf(validationErrVarIsNotAllowedInThisSection)
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
			prepAllow.jsonParsers = append(prepAllow.jsonParsers, vClients.jsonParsers...)

			continue
		}

		prepAllow.clients = append(prepAllow.clients, a)
	}

	return prepAllow, nil
}
