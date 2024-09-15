// Copyright 2024 The AuthRequestAgent Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package policy

import (
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

type Checker struct {
	prepCfg   *preparedConfig
	rawPolicy []byte
	data      interface{}
	dataMux   sync.RWMutex
}

func NewChecker() *Checker {
	// todo: default policy
	return &Checker{
		dataMux: sync.RWMutex{},
	}
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

func (c *Checker) Check(in CheckInput) (*CheckResult, error) {
	c.dataMux.RLock()
	defer c.dataMux.RUnlock()

	// define client prefix and name
	cn, err := c.defineCn(in)
	if err != nil {
		if invalidCnErr, ok := err.(ErrInvalidClientName); ok {
			return newCheckResult(false, nil, "", invalidCnErr), nil
		}
		return nil, fmt.Errorf("defining client name: %w", err)
	}

	// check routes
	for _, policy := range c.prepCfg.Policies {
		if policy.RegexUri != nil {
			if policy.RegexUri.MatchString(in.Uri) {
				if policy.Method[0] == "*" || slices.Contains(policy.Method, in.Method) {
					isAllowed, err := c.isAllowed(policy.Allow, cn)
					if err != nil {
						return newCheckResult(false, cn, policy.RegexUri.String(), nil), err
					}

					return newCheckResult(isAllowed, cn, policy.RegexUri.String(), nil), nil
				}
			}
		}

		if policy.Uri == in.Uri && (policy.Method[0] == "*" || slices.Contains(policy.Method, in.Method)) {
			isAllowed, err := c.isAllowed(policy.Allow, cn)
			if err != nil {
				return newCheckResult(false, cn, policy.Uri, nil), err
			}

			return newCheckResult(isAllowed, cn, policy.Uri, nil), nil
		}
	}

	// apply default
	isAllowed, err := c.isAllowed(c.prepCfg.Default, cn)
	if err != nil {
		return newCheckResult(false, cn, "default", nil), err
	}

	return newCheckResult(isAllowed, cn, "default", nil), nil
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

func (c *Checker) defineCn(in CheckInput) (*preparedCn, error) {
	for _, cn := range c.prepCfg.Cn {
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
