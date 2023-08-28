package internal

import (
	"encoding/json"
	"fmt"
	"os"
)

type Builder struct {
	ID    string `json:"id"`
	Level int    `json:"level"`
}

type BuildTrack struct {
	Builders []Builder `json:"builders"`
}

type Sourcer struct {
	ID               string   `json:"id"`
	AuthoritativeFor []string `json:"authoritativeFor"`
}
type SourceTrack struct {
	Sourcers []Sourcer `json:"attestors"`
}

type Package struct {
	URI string `json:"uri"`
}

type Source struct {
	URI string `json:"uri"`
}

type EnforcementType string

const (
	EnforcementTypeAllow = "allow"
	EnforcementTypeDeny  = "deny"
)

type Overwrite struct {
	Default    EnforcementType `json:"default"`
	Exceptions []struct {
		Sources   []Source        `json:"sources"`
		Reason    string          `json:"reason"`
		Overwrite EnforcementType `json:"overwrite"`
	} `json:"exceptions"`
}

type Enforcement struct {
	OnViolation EnforcementType   `json:"onViolation"`
	Overwrite   Overwrite         `json:"overwrite"`
	LogOn       []EnforcementType `json:"logOn"`
}

type Tracks struct {
	SourceTrack SourceTrack `json:"source"`
	BuildTrack  BuildTrack  `json:"build"`
}

// type Entry struct {
// 	Tracks      Tracks      `json:"tracks"`
// 	Packages    []Package   `json:"packages"`
// 	Sources     []Source    `json:"sources"`
// 	Enforcement Enforcement `json:"enforcement"`
// }

// type Entries map[string]Entry

type PolicyElement struct {
	Version     int         `json:"version"`
	Tracks      Tracks      `json:"tracks"`
	Packages    []Package   `json:"packages"`
	Sources     []Source    `json:"sources"`
	Enforcement Enforcement `json:"enforcement"`
	//Entries Entries `json:"entries"`
}

type Policy struct {
	policies []PolicyElement
}

func FromFiles(files []string) (*Policy, error) {
	policies := make([]PolicyElement, len(files))
	for i := range files {
		pfile := &files[i]
		content, err := os.ReadFile(*pfile)
		if err != nil {
			return nil, fmt.Errorf("failed to read file: %w", err)
		}
		if err := json.Unmarshal(content, &policies[i]); err != nil {
			return nil, fmt.Errorf("failed to unmarshal: %w", err)
		}

		// var pol map[string]interface{}
		// if err := json.Unmarshal(content, &pol); err != nil {
		// 	return nil, fmt.Errorf("failed to unmarshal: %w", err)
		// }
		// if err := read(pol, &policies[i]); err != nil {
		// 	return nil, fmt.Errorf("failed to parse: %w", err)
		// }
	}

	// for i := range policies {
	// 	pol := &policies[i]
	// 	val, _ := json.MarshalIndent(pol.Entries, "", "  ")
	// 	fmt.Println(string(val))
	// }
	val, _ := json.MarshalIndent(policies, "", "  ")
	fmt.Println(string(val))
	return &Policy{
		policies: policies,
	}, nil
}

func (et *EnforcementType) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	if s != EnforcementTypeAllow && s != EnforcementTypeDeny {
		return fmt.Errorf("invalid value: %q", s)
	}
	*et = EnforcementType(s)
	return nil
}

/*
func read(pol map[string]interface{}, p *PolicyElement) error {
	var err error
	p.Version, err = readVersion(pol)
	if err != nil {
		return err
	}
	return readEntries(pol, p)
}

func readEntries(pol map[string]interface{}, p *PolicyElement) error {
	if len(pol) < 2 {
		return fmt.Errorf("innvalid map length %v", len(pol))
	}
	p.Entries = make(Entries, len(pol)-1)
	for k := range pol {
		if k == "version" {
			continue
		}
		v := pol[k]
		val, err := json.Marshal(v)
		if err != nil {
			return err
		}
		var entry Entry
		if err := json.Unmarshal(val, &entry); err != nil {
			return fmt.Errorf("failed to unmarshal: %w", err)
		}
		p.Entries[k] = entry
	}

	return nil
}*/

func readVersion(pol map[string]interface{}) (int, error) {
	val, exists := pol["version"]
	if !exists {
		return 0, fmt.Errorf("version missing")
	}
	valFloat, ok := val.(float64)
	if !ok {
		return 0, fmt.Errorf("version has invalid type: %q", val)
	}
	return int(valFloat), nil
}

func build(policies []PolicyElement) (*PolicyElement, error) {
	return &policies[0], nil
}
