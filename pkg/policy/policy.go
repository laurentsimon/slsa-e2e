package policy

import (
	internal "github.com/laurentsimon/slsa-e2e/pkg/policy/internal"
)

// Policy defineds a policy.
type Policy struct {
	policy *internal.Policy
}

// Build a policy fr an ordered list of files.
func FromFiles(files []string) (*Policy, error) {
	policy, err := internal.FromFiles(files)
	if err != nil {
		return nil, err
	}
	return &Policy{
		policy: policy,
	}, nil
}

// Evaluate evaluates the policy.
func (p *Policy) Evaluate() error {
	return nil
}
