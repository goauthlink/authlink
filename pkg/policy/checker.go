// Copyright 2024 The AuthRequestAgent Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package policy

import (
	"fmt"
	"log/slog"
	"reflect"
	"slices"
	"sync"
)

type CheckInput struct {
	Uri     string
	Method  string
	Headers map[string]string
}

type preparedCn struct {
	Prefix string
	Name   string
}

type Checker struct {
	prepCfg   *preparedConfig
	rawPolicy []byte
	data      interface{}
	dataMux   sync.RWMutex
	logger    *slog.Logger
}

func NewChecker() *Checker {
	// todo: default policy
	return &Checker{
		dataMux: sync.RWMutex{},
	}
}

func (c *Checker) SetResultLogger(logger *slog.Logger) {
	c.logger = logger
}

func (c *Checker) SetPolicy(policy []byte) error {
	prepConfig, err := PrepareConfig(policy)
	if err != nil {
		return fmt.Errorf("parse policy: %s", err)
	}

	c.dataMux.Lock()
	c.prepCfg = prepConfig
	c.rawPolicy = policy
	c.dataMux.Unlock()

	return nil
}

func (c *Checker) SetData(data interface{}) {
	c.dataMux.Lock()
	c.data = data
	c.dataMux.Unlock()
}

func (c *Checker) Data() interface{} {
	return c.data
}

func (c *Checker) Policy() []byte {
	return c.rawPolicy
}

type CheckResult struct {
	Allow        bool
	Endpoint     string
	NormalizedCn string
}

func (c *Checker) createCheckResult(allow bool, in *CheckInput, endpoint string, cn *preparedCn) *CheckResult {
	var normalizedCn string
	if cn != nil {
		normalizedCn = cn.Prefix + cn.Name
	}

	checkResult := CheckResult{
		Allow:        false,
		NormalizedCn: normalizedCn,
	}
	checkResult.Allow = allow

	if c.logger == nil {
		return &checkResult
	}

	c.logger.Info(fmt.Sprintf("check result: %t, uri: %s, method: %s, headers: %s, policy endpoint: %s, parsed client: %s",
		allow,
		in.Uri,
		in.Method,
		in.Headers,
		endpoint,
		normalizedCn,
	))

	return &checkResult
}

func (c *Checker) Check(in CheckInput) (*CheckResult, error) {
	c.dataMux.RLock()
	defer c.dataMux.RUnlock()

	// define client prefix and name
	cn := c.defineCn(in)

	// check routes
	for _, policy := range c.prepCfg.Policies {
		if policy.RegexUri != nil {
			if policy.RegexUri.MatchString(in.Uri) {
				if policy.Method[0] == "*" || slices.Contains(policy.Method, in.Method) {
					isAllowed, err := c.isAllowed(policy.Allow, cn)
					if err != nil {
						return c.createCheckResult(false, &in, policy.RegexUri.String(), cn), err
					}

					return c.createCheckResult(isAllowed, &in, policy.RegexUri.String(), cn), nil
				}
			}
		}

		if policy.Uri == in.Uri && (policy.Method[0] == "*" || slices.Contains(policy.Method, in.Method)) {
			isAllowed, err := c.isAllowed(policy.Allow, cn)
			if err != nil {
				return c.createCheckResult(false, &in, policy.Uri, cn), err
			}

			return c.createCheckResult(isAllowed, &in, policy.Uri, cn), nil
		}
	}

	// apply default
	isAllowed, err := c.isAllowed(c.prepCfg.Default, cn)
	if err != nil {
		return c.createCheckResult(false, &in, "default", cn), err
	}

	return c.createCheckResult(isAllowed, &in, "default", cn), nil
}

func (c *Checker) isAllowed(allow preparedAllow, cn *preparedCn) (bool, error) {
	if cn == nil {
		return false, nil
	}

	for _, allowCn := range allow.clients {
		if cn.Prefix+cn.Name == allowCn || cn.Prefix+"*" == allowCn {
			return true, nil
		}
	}

	for _, allowJsonPath := range allow.jsonParsers {
		values, err := allowJsonPath.JsonParser.FindResults(c.data)
		if err != nil {
			return false, fmt.Errorf("jsonpath finding results failure: %s", err.Error())
		}

		if len(values) == 0 {
			break
		}

		for i := 0; i < len(values[0]); i++ {
			if values[0][i].Kind() != reflect.String {
				return false, fmt.Errorf("jsonpath result must by array of string, got: %s", values[0][i].Kind())
			}

			if cn.Prefix+cn.Name == allowJsonPath.Prefix+values[0][i].String() {
				return true, nil
			}
		}
	}

	return false, nil
}

func (c *Checker) defineCn(in CheckInput) *preparedCn {
	// todo: implement behavior for undefined cn
	for _, cn := range c.prepCfg.Cn {
		if len(cn.Header) > 0 {
			if val, ok := in.Headers[cn.Header]; ok {
				return &preparedCn{
					Prefix: cn.Prefix,
					Name:   val,
				}
			}
		}
	}

	return nil
}
