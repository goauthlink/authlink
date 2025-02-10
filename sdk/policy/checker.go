// Copyright 2025 The AuthLink Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package policy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"sync"

	"github.com/golang-jwt/jwt/v5"
)

const (
	errPayloadFieldDoesntExist    = "payload field `%s` doesn't exists in token `%s`"
	errPayloadFieldIsntStringType = "payload field `%s` isn't string type in token `%s`"
)

type ErrInvalidClientName struct {
	errMessage string
}

func (e ErrInvalidClientName) Error() string {
	return e.errMessage
}

type CheckInput struct {
	Uri     string
	Method  string
	Headers map[string]string
}

type preparedCn struct {
	Prefix string
	Name   string
}

type configItem struct {
	prepared preparedConfig
	orig     Config
}

type Checker struct {
	items     []configItem
	rawPolicy []byte
	data      interface{}
	dataMux   sync.RWMutex
	dataCache map[string][]string
}

func NewChecker() *Checker {
	return &Checker{
		items:   []configItem{},
		dataMux: sync.RWMutex{},
	}
}

func (c *Checker) SetConfigs(configs []Config) error {
	items := []configItem{}
	for _, c := range configs {
		prepConfig, err := PrepareConfig(c)
		if err != nil {
			return fmt.Errorf("parse policy: %s", err)
		}
		items = append(items, configItem{
			prepared: *prepConfig,
			orig:     c,
		})
	}

	c.dataMux.Lock()
	c.items = items
	c.dataMux.Unlock()

	return nil
}

func (c *Checker) SetData(data []byte) error {
	var newData interface{}
	err := json.Unmarshal([]byte(data), &newData)
	if err != nil {
		return fmt.Errorf("invalid json format: %w", err)
	}

	c.dataMux.Lock()
	c.data = newData
	c.dataCache = map[string][]string{}
	// todo: async warmup
	c.dataMux.Unlock()

	return nil
}

func (c *Checker) Data() interface{} {
	return c.data
}

func (c *Checker) Policy() []Config {
	c.dataMux.Lock()
	defer c.dataMux.Unlock()

	items := []Config{}
	for _, c := range c.items {
		items = append(items, c.orig)
	}

	return items
}

type CheckResult struct {
	Allow      bool
	ClientName string
	Endpoint   string
	Err        error
}

func newCheckResult(allow bool, cn *preparedCn, endpoint string, err error) *CheckResult {
	var clientName string
	if cn != nil {
		clientName = cn.Prefix + cn.Name
	}

	return &CheckResult{
		Allow:      allow,
		ClientName: clientName,
		Endpoint:   endpoint,
		Err:        err,
	}
}

func (c *Checker) checkConfig(in CheckInput, prepConfig *preparedConfig) (*CheckResult, error) {
	// define client prefix and name
	cn, err := defineCn(in, prepConfig)
	if err != nil {
		if invalidCnErr, ok := err.(ErrInvalidClientName); ok {
			return newCheckResult(false, nil, "", invalidCnErr), nil
		}
		return nil, fmt.Errorf("defining client name: %w", err)
	}

	// check routes
	for _, policy := range prepConfig.Policies {
		if policy.RegexUri != nil {
			if policy.RegexUri.MatchString(in.Uri) {
				if policy.Method[0] == "*" || slices.Contains(policy.Method, in.Method) {
					isAllowed, err := c.isAllowed(policy.Allow, cn)
					return newCheckResult(isAllowed, cn, policy.RegexUri.String(), err), nil
				}
			}
		}

		if policy.Uri == in.Uri && (policy.Method[0] == "*" || slices.Contains(policy.Method, in.Method)) {
			isAllowed, err := c.isAllowed(policy.Allow, cn)
			return newCheckResult(isAllowed, cn, policy.Uri, err), nil
		}
	}

	// apply default
	isAllowed, err := c.isAllowed(prepConfig.Default, cn)

	return newCheckResult(isAllowed, cn, "default", err), nil
}

func (c *Checker) Check(in CheckInput) (*CheckResult, error) {
	c.dataMux.RLock()
	defer c.dataMux.RUnlock()

	for _, item := range c.items {
		cres, err := c.checkConfig(in, &item.prepared)
		if err != nil {
			return nil, err
		}

		if cres.Err != nil || cres.Allow {
			return cres, nil
		}
	}

	return newCheckResult(false, nil, "", nil), nil
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

	for _, allowJsonPath := range allow.parsers {
		clients, ok := c.dataCache[allowJsonPath.Jsonpath]
		if !ok {
			values, err := allowJsonPath.JsonParser.FindResults(c.data)
			if err != nil {
				return false, fmt.Errorf("jsonpath finding results failure: %s", err.Error())
			}

			if len(values) == 0 {
				c.dataCache[allowJsonPath.Jsonpath] = []string{}
				break
			}

			for i := 0; i < len(values[0]); i++ {
				if values[0][i].Kind() != reflect.Interface {
					continue
				}
				if val, ok := values[0][i].Interface().(string); ok {
					clients = append(clients, val)
				}
			}

			c.dataCache[allowJsonPath.Jsonpath] = clients
		}

		for _, allowCn := range clients {
			if cn.Prefix+cn.Name == allowJsonPath.Prefix+allowCn {
				return true, nil
			}
		}
	}

	return false, nil
}

func defineCn(in CheckInput, prepConfig *preparedConfig) (*preparedCn, error) {
	for _, cn := range prepConfig.Cn {
		if cn.Header != nil {
			if val, ok := in.Headers[*cn.Header]; ok {
				return &preparedCn{
					Prefix: cn.Prefix,
					Name:   val,
				}, nil
			}
		}

		if cn.JWT != nil {
			var token string
			if cn.JWT.Header != nil {
				if t, ok := in.Headers[*cn.JWT.Header]; ok {
					token = t
				}
			}

			if cn.JWT.Cookie != nil {
				cookies, err := http.ParseCookie(in.Headers["Cookie"])
				if err != nil {
					return nil, ErrInvalidClientName{
						errMessage: fmt.Sprintf("parse cookie: %s", err),
					}
				}

				for _, ck := range cookies {
					if ck.Name == *cn.JWT.Cookie {
						token = ck.Value
						break
					}
				}
			}

			if len(token) == 0 {
				continue
			}

			var keyFunc jwt.Keyfunc
			if cn.JWT.KeyFile != nil {
				keyFunc = func(t *jwt.Token) (interface{}, error) {
					return cn.JWT.KeyFileData, nil
				}
			}

			claims := jwt.MapClaims{}
			_, err := jwt.ParseWithClaims(token, claims, keyFunc)
			if err != nil {
				if keyFunc == nil && strings.Contains(err.Error(), "no keyfunc was provided") {
				} else {
					return nil, ErrInvalidClientName{
						errMessage: fmt.Sprintf("parse jwt token: %s", err.Error()),
					}
				}
			}

			cnClaim, ok := claims[cn.JWT.Payload]
			if !ok {
				return nil, ErrInvalidClientName{
					errMessage: fmt.Sprintf(errPayloadFieldDoesntExist, cn.JWT.Payload, token),
				}
			}
			cnValue, ok := cnClaim.(string)
			if !ok {
				return nil, ErrInvalidClientName{
					errMessage: fmt.Sprintf(errPayloadFieldIsntStringType, cn.JWT.Payload, token),
				}
			}

			return &preparedCn{
				Prefix: cn.Prefix,
				Name:   cnValue,
			}, nil
		}
	}

	return nil, ErrInvalidClientName{
		errMessage: "undefined client name",
	}
}
