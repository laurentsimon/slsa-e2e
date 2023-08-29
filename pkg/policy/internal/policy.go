package internal

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
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

type Image struct {
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
	Source SourceTrack `json:"source"`
	Build  BuildTrack  `json:"build"`
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
	Images      []Image     `json:"images"`
	Sources     []Source    `json:"sources"`
	Enforcement Enforcement `json:"enforcement"`
	//Entries Entries `json:"entries"`
}

type Policy struct {
	policies []PolicyElement
}

func FromBytes(content [][]byte) (*Policy, error) {
	if len(content) > 2 {
		return nil, fmt.Errorf("invalid level of policies %q", len(content))
	}
	policies := make([]PolicyElement, len(content))
	for i := range content {
		pcontent := &content[i]
		if err := json.Unmarshal(*pcontent, &policies[i]); err != nil {
			return nil, fmt.Errorf("failed to unmarshal: %w", err)
		}

		// var pol map[string]interface{}
		// if err := json.Unmarshal(content, &pol); err != nil {
		// 	return nil, fmt.Errorf("failed to unmarshal: %w", err)
		// }
		// if err := read(pol, &policies[i]); err != nil {
		// 	return nil, fmt.Errorf("failed to parse: %w", err)
		// }

		if err := validate(policies[i]); err != nil {
			return nil, err
		}
	}

	// var pol map[string]interface{}
	// if err := json.Unmarshal(content, &pol); err != nil {
	// 	return nil, fmt.Errorf("failed to unmarshal: %w", err)
	// }
	// if err := read(pol, &policies[i]); err != nil {
	// 	return nil, fmt.Errorf("failed to parse: %w", err)
	// }
	val, _ := json.MarshalIndent(policies, "", "  ")
	fmt.Println(string(val))
	return &Policy{
		policies: policies,
	}, nil
}

func FromFiles(files []string) (*Policy, error) {
	contents := make([][]byte, len(files))
	for i := range files {
		pfile := &files[i]
		content, err := os.ReadFile(*pfile)
		if err != nil {
			return nil, fmt.Errorf("failed to read file: %w", err)
		}
		contents[i] = content

	}

	return FromBytes(contents)
}

func validate(pe PolicyElement) error {
	if pe.Version != 1 {
		return fmt.Errorf("invalid version: %q", pe.Version)
	}
	// TODO: child cannot have source info.
	return nil
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

func (p *Policy) Evaluate(sourceURI, imageURI, builderID string) error {
	// Walk each policy component and see if it passes or not.
	// We keep some global state.
	if len(p.policies) == 0 {
		return fmt.Errorf("policy len is %q", len(p.policies))
	}

	if err := p.validateSources(sourceURI); err != nil {
		return err
	}

	// NOTE: sourceURI serves as an identifier.
	if err := p.validateImages(sourceURI, imageURI); err != nil {
		return err
	}

	if err := p.validateBuildTrack(sourceURI, builderID); err != nil {
		return err
	}

	// TODO: source track.

	return nil
}

func enforced(enforcement Enforcement, sourceURI string) bool {
	overwrite := enforcement.Overwrite
	// TODO: BUG: need to look at triplet onViolation, overwirite.default and
	// exceptions.overwrite.
	if overwrite.Default == EnforcementTypeAllow {
		// Ensure no exception to deny.
		return true
	}
	// default is to deny.
	for i := range overwrite.Exceptions {
		pException := overwrite.Exceptions[i]
		// If the exception does not allow, we fail.
		if pException.Overwrite != EnforcementTypeAllow {
			return false
		}
		// Check the source URIs.
		for j := range pException.Sources {
			pSource := &pException.Sources[j]
			if Glob(pSource.URI, sourceURI) {
				return true
			}
		}
	}
	return false
}

func (p *Policy) validateBuildTrack(sourceURI, builderID string) error {
	if strings.Contains(builderID, "*") {
		return fmt.Errorf("invalid builderID: %q", builderID)
	}

	for i := range p.policies {
		pBuildTrack := &p.policies[i].Tracks.Build
		var pass bool
		for j := range pBuildTrack.Builders {
			pBuilder := &pBuildTrack.Builders[j]
			id := pBuilder.ID
			fmt.Println(id)
			if id == builderID {
				pass = true
				break
			}
		}

		// Overwrites must be *explicit* at every level. They default to disallowed.
		// Every parent can set the overwrite.
		var deny bool
		if i < len(p.policies) {
			deny = enforced(p.policies[i].Enforcement, sourceURI)
		}

		// if not builders are defined, ignore the result.
		// TODO: do we want to force the child to provide builders
		// if they are allowed to overwrite? We're unlikely to support
		// the builers anyway for verification.
		if i > 0 && len(pBuildTrack.Builders) == 0 {
			continue
		}
		if !deny && !pass {
			return fmt.Errorf("build track failed: policy level %d for %q. Must be one of %q", i, builderID, pBuildTrack.Builders)
		}

		// TODO: test: p1 overwrite, p2 no overwrite
		// p1 not overwrite, p2 overwrite
		// p1 overwrite and p2 overwrite
		// no build tracks defined
		// no build tracks defined with parent overwrite
		// normal more constrained
		// normal less constrainted
		// normal fail / validate
	}
	return nil
}

func (p *Policy) validateImages(sourceURI, imageURI string) error {
	// TODO: support image tag *?
	if strings.Contains(imageURI, "*") {
		return fmt.Errorf("invalid imageURI: %q", imageURI)
	}

	for i := range p.policies {
		pImages := &p.policies[i].Images
		var pass bool
		for j := range *pImages {
			pImage := &(*pImages)[j]
			uri := pImage.URI
			fmt.Println(uri)
			if Glob(uri, imageURI) {
				pass = true
				break
			}
		}

		// Overwrites must be *explicit* at every level. They default to disallowed.
		// Every parent can set the overwrite.
		var deny bool
		if i < len(p.policies) {
			deny = enforced(p.policies[i].Enforcement, sourceURI)
		}

		// if not images are defined, ignore the result.
		// TODO: do we want to force the child to provide images
		// if they are allowed to overwrite?
		if i > 0 && len(*pImages) == 0 {
			continue
		}
		if !deny && !pass {
			return fmt.Errorf("image failed: policy level %d for %q. Must be one of %q", i, imageURI, *pImages)
		}

		// TODO: test: p1 overwrite, p2 no overwrite
		// p1 not overwrite, p2 overwrite
		// p1 overwrite and p2 overwrite
		// no images defined
		// no image defined with parent overwite
		// normal more constrained
		// normal less constrainted
		// normal fail / validate
		// default deny and exception allow
		// default allow and exeception deny
		// default X and exception X
		// onViolation
	}
	return nil
}

func (p *Policy) validateSources(sourceURI string) error {
	if strings.Contains(sourceURI, "*") {
		return fmt.Errorf("invalid sourceURI: %q", sourceURI)
	}

	// TODO: support ref as semver?
	for i := range p.policies {
		// The last child _cannot_ define their sources,
		// because it is taken from the workflow run automatically.
		if i == len(p.policies)-1 {
			continue
		}
		pSources := &p.policies[i].Sources
		var pass bool
		for j := range *pSources {
			pSource := &(*pSources)[j]
			uri := pSource.URI
			fmt.Println(uri)
			if Glob(uri, sourceURI) {
				pass = true
				break
			}
		}

		// Overwrites must be *explicit* at every level. They default to disallowed.
		// Every parent can set the overwrite.
		var deny bool
		if i < len(p.policies) {
			deny = enforced(p.policies[i].Enforcement, sourceURI)
		}

		if !deny && !pass {
			return fmt.Errorf("source failed: policy level %d for %q. Must be one of %q", i, sourceURI, *pSources)
		}
		// TODO: test: p1 overwrite, p2 no overwrite
		// p1 not overwrite, p2 overwrite
		// p1 overwrite and p2 overwrite
		// normal more constrained
		// normal less constrainted
		// normal fail / validate
		// default deny and exception allow
		// default allow and exeception deny
		// default X and exception X
		// onViolation
	}
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
}

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
*/
