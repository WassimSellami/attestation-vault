package policy

import "fmt"

type Policy struct {
	Name                string
	AllowedMeasurements map[string]bool
	AllowedConfigHashes map[string]bool
}

type Engine struct {
	policies map[string]*Policy
}

func NewEngine() *Engine {
	return &Engine{policies: map[string]*Policy{}}
}

func (e *Engine) Add(p *Policy) {
	e.policies[p.Name] = p
}

func (e *Engine) Authorize(secretName, measurement, configHash string) error {
	p, ok := e.policies[secretName]
	if !ok {
		return fmt.Errorf("no policy for secret %q", secretName)
	}
	if !p.AllowedMeasurements[measurement] {
		return fmt.Errorf("measurement %q not allowed", measurement)
	}
	if len(p.AllowedConfigHashes) > 0 && !p.AllowedConfigHashes[configHash] {
		return fmt.Errorf("config hash %q not allowed", configHash)
	}
	return nil
}
