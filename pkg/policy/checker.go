package policy

import (
	"fmt"
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
}

func NewChecker() *Checker {
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

func (c *Checker) Check(in CheckInput) (bool, error) {
	// todo: decision logger

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
						return false, err
					}

					return isAllowed, nil
				}
			}
		}

		if policy.Uri == in.Uri && (policy.Method[0] == "*" || slices.Contains(policy.Method, in.Method)) {
			isAllowed, err := c.isAllowed(policy.Allow, cn)
			if err != nil {
				return false, err
			}

			return isAllowed, nil
		}
	}

	// apply default
	isAllowed, err := c.isAllowed(c.prepCfg.Default, cn)
	if err != nil {
		return false, err
	}

	return isAllowed, nil
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
