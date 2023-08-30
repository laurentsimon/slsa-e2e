package internal

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/laurentsimon/slsa-e2e/pkg/policy/internal/utils/pointer"
	"github.com/laurentsimon/slsa-e2e/pkg/policy/results"
)

type Builder struct {
	ID    string `json:"id"`
	Level int    `json:"level"`
}

type BuildTrack struct {
	Builders []Builder `json:"builders"`
}

type Sourcer struct {
	ID string `json:"id"`
}
type SourceTrack struct {
	Sourcers []Sourcer `json:"attestors"`
}

type Resource struct {
	URI string `json:"uri"`
}

type Source Resource
type Image Resource

type Mode string

const (
	ModeAudit   = "audit"
	ModeEnforce = "enforce"
)

type Context string

const (
	ContextOrg  = "org"
	ContextRepo = "repo"
)

type Tracks struct {
	Source SourceTrack `json:"source"`
	Build  BuildTrack  `json:"build"`
}

type Images struct {
	Mode *Mode      `json:"mode"`
	List []Resource `json:"list"`
}

type Sources []Resource

type Entry struct {
	Tracks  Tracks  `json:"tracks"`
	Images  Images  `json:"images"`
	Sources Sources `json:"sources"`
	Mode    Mode    `json:"mode"`
}

type Exceptions struct {
	Mode *Mode   `json:"mode"`
	List []Entry `json:"list"`
}

type PolicyElement struct {
	Version    int         `json:"version"`
	Defaults   Entry       `json:"defaults"`
	Exceptions *Exceptions `json:"exceptions"`
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

		if err := validate(policies[i]); err != nil {
			return nil, err
		}
	}

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
	// exception cannot have enforcement

	return nil
}

func (p *Policy) Evaluate(sourceURI, imageURI, builderID string) results.Verification {
	// Walk each policy component and see if it passes or not.
	// We keep some global state.
	if len(p.policies) == 0 {
		return results.VerificationFail(fmt.Errorf("policy len is %q", len(p.policies)))
	}

	//TOTEST: combination of enforce / audit in parent / child. Also empty sources.
	result := p.verifySources(sourceURI)
	if !result.Pass() {
		return result
	}

	// NOTE: sourceURI serves as an identifier.
	// result = p.verifyImages(sourceURI, imageURI)
	// if !result.Pass() {
	// 	return result
	// }

	// if err := p.validateBuildTrack(sourceURI, builderID); err != nil {
	// 	return err
	// }

	// TODO: source track.

	return results.VerificationPass()
}

// func (p *Policy) verifyImages(sourceURI, imageURI string) results.Verification {
// 	if strings.Contains(imageURI, "*") {
// 		return results.VerificationFail(fmt.Errorf("invalid imageURI: %q", imageURI))
// 	}

// 	result, effectiveMode := verifyImage(sourceURI, imageURI, "org", nil, p.policies[0])
// 	if result.Fail() {
// 		return result
// 	}
// 	result, _ = verifyImage(sourceURI, imageURI, "repo", &effectiveMode, p.policies[1])

// 	return result
// }

// func verifyImage(sourceURI, imageURI string, context Context, effectiveMode *Mode, policy PolicyElement) (results.Verification, Mode) {
// 	failedResult := results.VerificationFail(fmt.Errorf("%q policy: image uri mismatch: %q", context, imageURI))
// 	result := failedResult
// 	// Update the effective mode only if it further restricts the policy (audit -> enforce).
// 	if effectiveMode == nil || *effectiveMode == ModeAudit {
// 		effectiveMode = pointer.To(Mode(policy.Defaults.Mode))
// 	}

// 	// Try the default policy first.
// 	images := policy.Defaults.Images.List
// 	exist := contains(images, imageURI)
// 	if exist {
// 		result = results.VerificationPass()
// 	} else {
// 		result = failedResult
// 	}

// 	// // Verification failed. Try the exception list.
// 	// if policy.Exceptions != nil {
// 	// 	exceptions := policy.Exceptions.List
// 	// 	for i := range exceptions {
// 	// 		exception := &exceptions[i]
// 	// 		sources := exception.Sources
// 	// 		exist := contains(sources, sourceURI)
// 	// 		if exist {
// 	// 			// We found a match. Update the result and the effctive mode.
// 	// 			result = results.VerificationPass()
// 	// 			effectiveMode = pointer.To(Mode(mode(policy.Defaults.Mode, policy.Exceptions.Mode)))
// 	// 		}
// 	// 	}
// 	// }

// 	// // Handle failure.
// 	// if result.Fail() {
// 	// 	// If the mode is audit, we pass but as an audit result.
// 	// 	if policy.Defaults.Mode == ModeAudit {
// 	// 		if *effectiveMode != ModeAudit {
// 	// 			result = results.VerificationInvalid(fmt.Errorf("%q policy: cannot overwrite %q", context, "mode"))
// 	// 		} else if policy.Defaults.Mode == ModeAudit {
// 	// 			result = results.VerificationAudit(fmt.Sprintf("%q policy: source uri mismatch: %q", context, sourceURI))
// 	// 		}
// 	// 	}
// 	// 	return result, *effectiveMode
// 	// }
// 	return result, *effectiveMode
// }

func (p *Policy) verifySources(sourceURI string) results.Verification {
	if strings.Contains(sourceURI, "*") {
		return results.VerificationFail(fmt.Errorf("invalid sourceURI: %q", sourceURI))
	}

	orgResult, effectiveMode := verifySource(sourceURI, ContextOrg, nil, p.policies[0])
	if orgResult.Fail() {
		return orgResult
	}
	repoResult, _ := verifySource(sourceURI, ContextRepo, &effectiveMode, p.policies[1])
	if repoResult.Fail() {
		return repoResult
	}
	// If the policy does not pass, return it.
	if !repoResult.Pass() {
		return repoResult
	}
	if !orgResult.Pass() {
		return orgResult
	}
	return results.VerificationPass()
}

func verifySource(sourceURI string, context Context, effectiveMode *Mode, policy PolicyElement) (results.Verification, Mode) {
	failedResult := results.VerificationFail(fmt.Errorf("%q policy: source uri mismatch: %q", context, sourceURI))
	invalidResult := results.VerificationInvalid(fmt.Errorf("%q policy: cannot overwrite %q", context, "mode"))
	result := failedResult
	// Update the effective mode only if it further restricts the policy (audit -> enforce).
	if !canUpdateMode(effectiveMode, policy.Defaults.Mode) {
		return invalidResult, *effectiveMode
	}
	effectiveMode = pointer.To(Mode(policy.Defaults.Mode))

	// Try the default policy first.
	sources := policy.Defaults.Sources
	exist := contains(sources, sourceURI)
	// Repo policy need not populate the field.
	if exist || (len(sources) == 0 && context == ContextRepo) {
		result = results.VerificationPass()
	} else {
		result = failedResult
	}

	// Verification failed. Try the exception list.
	if policy.Exceptions != nil {
		exceptions := policy.Exceptions.List
		for i := range exceptions {
			exception := &exceptions[i]
			sources := exception.Sources
			exist := contains(sources, sourceURI)
			if exist {
				// We found a match. Update the result and the effective mode.
				newMode := pointer.To(Mode(mode(policy.Defaults.Mode, policy.Exceptions.Mode)))
				if context == ContextRepo && !canUpdateMode(effectiveMode, *newMode) {
					result = results.VerificationInvalid(fmt.Errorf("%q policy: cannot overwrite %q", context, "mode"))
				} else {
					result = results.VerificationPass()
					*effectiveMode = *newMode
				}
			}
		}
	}

	// Handle failure.
	if result.Fail() && *effectiveMode == ModeAudit {
		result = results.VerificationAudit(fmt.Sprintf("%q policy: source uri mismatch: %q", context, sourceURI))
		return result, *effectiveMode
	}
	return result, *effectiveMode
}

func canUpdateMode(cur *Mode, n Mode) bool {
	if cur != nil && *cur == ModeEnforce && n == ModeAudit {
		return false
	}
	return true
}

func mode(def Mode, exc *Mode) Mode {
	if exc != nil {
		return *exc
	}
	return def
}

func contains(resources []Resource, resourceURI string) bool {
	for j := range resources {
		resource := &resources[j]
		uri := resource.URI
		fmt.Println(uri, resourceURI)
		if Glob(uri, resourceURI) {
			return true
		}
	}
	return false
}

/*
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

		var enforce bool
		if i < len(p.policies) {
			enforce = enforced(p.policies[i].Enforcement, sourceURI)
		}

		// if no builders are defined, ignore the result.
		// TODO: do we want to force the child to provide builders
		// if they are allowed to overwrite? We're unlikely to support
		// the builers anyway for verification.
		if i > 0 && len(pBuildTrack.Builders) == 0 {
			continue
		}
		// TODO: if !pass, we need to return the log level and message.
		// We need PASS, FAIL, PASS_WITH_EXCEPTION?
		if enforce && !pass {
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


*/
