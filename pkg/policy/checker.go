package policy

import (
	"fmt"
	"reflect"
	"slices"
)

type CheckInput struct {
	Uri     string
	Method  string
	Headers map[string]string
	Tls     string
}

type preparedCn struct {
	Prefix string
	Name   string
}

type Checker struct {
	prepCfg *preparedConfig
	data    interface{}
}

func NewChecker(prepCfg *preparedConfig) *Checker {
	return &Checker{
		prepCfg: prepCfg,
	}
}

func (c *Checker) SetData(data interface{}) {
	c.data = data
}

func (c *Checker) Data() interface{} {
	return c.data
}

func (c *Checker) Check(in CheckInput) (bool, error) {
	// todo: decision logger

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

		// println("p", policy.Method[0])
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
	// todo: задать поведение для не попавших в cn
	for _, cn := range c.prepCfg.Cn {
		if len(cn.Header) > 0 {
			if val, ok := in.Headers[cn.Header]; ok {
				return &preparedCn{
					Prefix: cn.Prefix,
					Name:   val,
				}
			}
		}
		// todo: jwt
		// todo: tls
	}

	return nil
}
