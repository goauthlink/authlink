package models

type LabelSet map[string]string

type Policy struct {
	Name   string
	Raw    []byte
	Labels LabelSet
}
