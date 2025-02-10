// Copyright 2025 The AuthLink Authors. All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package policy

import (
	"encoding/json"
	"fmt"

	"gopkg.in/yaml.v3"
)

// +k8s:deepcopy-gen=true

type CnJWT struct {
	Payload     string  `yaml:"payload" json:"payload,omitempty"`
	Header      *string `yaml:"header,omitempty" json:"header,omitempty"`
	Cookie      *string `yaml:"cookie,omitempty" json:"cookie,omitempty"`
	KeyFile     *string `yaml:"keyFile,omitempty" json:"key_file,omitempty"`
	KeyFileData []byte  `yaml:"-" json:"key_file_data,omitempty"`
	// KeyCache string  `yaml:"keyCache"` todo: need to implement
}

// +k8s:deepcopy-gen=true

type Cn struct {
	Prefix string  `yaml:"prefix" json:"prefix,omitempty"`
	Header *string `yaml:"header,omitempty" json:"header,omitempty"`
	JWT    *CnJWT  `yaml:"jwt,omitempty" json:"jwt,omitempty"`
}

// +k8s:deepcopy-gen=true

type Policy struct {
	Uri     []string `yaml:"uri" json:"uri,omitempty"`
	Methods []string `yaml:"method" json:"methods,omitempty"`
	Allow   []string `yaml:"allow" json:"allow,omitempty"`
}

// +k8s:deepcopy-gen=true

type Variables map[string][]string

// +k8s:deepcopy-gen=true

type Config struct {
	Name     string    `yaml:"name" json:"name,omitempty"`
	Cn       []Cn      `yaml:"cn" json:"cn,omitempty"`
	Vars     Variables `yaml:"vars" json:"vars,omitempty"`
	Default  []string  `yaml:"default" json:"default,omitempty"`
	Policies []Policy  `yaml:"policies" json:"policies,omitempty"`
}

func YamlToPolicyConfig(policyYaml []byte) (*Config, error) {
	cfg := Config{}
	if err := yaml.Unmarshal(policyYaml, &cfg); err != nil {
		return nil, fmt.Errorf("parsing policy yaml: %w", err)
	}

	return &cfg, nil
}

func JsonToPolicyConfig(policyJson []byte) (*Config, error) {
	cfg := Config{}
	if err := json.Unmarshal(policyJson, &cfg); err != nil {
		return nil, fmt.Errorf("parsing policy json: %w", err)
	}

	return &cfg, nil
}
