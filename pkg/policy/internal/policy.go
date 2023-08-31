package internal

import (
	"encoding/json"
	"fmt"
	"os"

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

type Mode string

const (
	ModeAudit   = "audit"
	ModeEnforce = "enforce"
)

type context string

const (
	contextOrg  context = "org"
	contextRepo context = "repo"
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

type Projects struct {
	Mode *Mode   `json:"mode"`
	List []Entry `json:"list"`
}

type OrgPolicy struct {
	Version  int       `json:"version"`
	Defaults *Entry    `json:"defaults"`
	Projects *Projects `json:"projects"`
}

type Project struct {
	Mode   *Mode    `json:"mode"`
	Source Resource `json:"source"`
	Image  Resource `json:"image"`
}

type RepoPolicy struct {
	Version  int       `json:"version"`
	Mode     *Mode     `json:"mode"`
	Projects []Project `json:"projects"`
}

type Policy struct {
	orgPolicy  OrgPolicy
	repoPolicy RepoPolicy
}

func FromBytes(content [][]byte) (*Policy, error) {
	if len(content) > 2 {
		return nil, fmt.Errorf("invalid level of policies %q", len(content))
	}

	pcontent := &content[0]
	var orgPolicy OrgPolicy
	if err := json.Unmarshal(*pcontent, &orgPolicy); err != nil {
		return nil, fmt.Errorf("failed to unmarshal: %w", err)
	}
	if err := validateOrgPolicy(orgPolicy); err != nil {
		return nil, err
	}

	pcontent = &content[1]
	var repoPolicy RepoPolicy
	if err := json.Unmarshal(*pcontent, &repoPolicy); err != nil {
		return nil, fmt.Errorf("failed to unmarshal: %w", err)
	}
	if err := validateRepoPolicy(repoPolicy); err != nil {
		return nil, err
	}

	// val, _ := json.MarshalIndent(policies, "", "  ")
	// fmt.Println(string(val))
	return &Policy{
		orgPolicy:  orgPolicy,
		repoPolicy: repoPolicy,
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

func (m *Mode) UnmarshalJSON(data []byte) error {
	var s string
	err := json.Unmarshal(data, &s)
	if err != nil {
		return err
	}
	switch s {
	case ModeEnforce, ModeAudit:
		*m = Mode(s)
	default:
		return fmt.Errorf("invalid mode: %q", s)
	}

	return nil
}

func validateOrgPolicy(p OrgPolicy) error {
	if p.Version != 1 {
		return fmt.Errorf("%q policy: invalid %q", contextRepo, "source")
	}
	if len(p.Defaults.Sources) == 0 {
		return fmt.Errorf("%q policy: empty %q", contextRepo, "sources")
	}
	return nil
}

func validateRepoPolicy(p RepoPolicy) error {
	if p.Version != 1 {
		return fmt.Errorf("%q policy: invalid %q", contextRepo, "source")
	}
	for i := range p.Projects {
		project := &p.Projects[i]
		if project.Source.URI == "" {
			return fmt.Errorf("%q policy: empty %q", contextRepo, "source")
		}
	}
	return nil
}

func (p *Policy) Evaluate(sourceURI, imageURI, builderID string) results.Verification {
	// Try the default policy first.
	orgDefault := p.verifyOrgDefault(sourceURI, imageURI)
	return orgDefault
	// if orgDefault.Pass() || orgDefault.Invalid() {
	// 	return orgDefault
	// }

	// // Try org projects.
	// orgProjects := p.verifyOrgProjects(sourceURI, imageURI)
	// if orgProjects.Pass() || orgProjects.Invalid() {
	// 	return orgProjects
	// }

	// // It's either fail or audit.

	// // Start with failures.
	// if orgDefault.Fail() {
	// 	return orgDefault
	// }

	// if orgProjects.Fail() {
	// 	return orgProjects
	// }

	// // Return auits.
	// if orgDefault.Audit() {
	// 	return orgDefault
	// }
	// if orgProjects.Audit() {
	// 	return orgProjects
	// }
	// return results.VerificationPass()
}

func (p *Policy) verifyOrgDefault(sourceURI, imageURI string) results.Verification {
	// Sources are validated and are non-empty.
	for i := range p.orgPolicy.Defaults.Sources {
		orgSource := &p.orgPolicy.Defaults.Sources[i]
		orgURI := orgSource.URI
		fmt.Println(orgURI, sourceURI)
		if !Glob(orgURI, sourceURI) {
			continue
		}

		// We have a match on the source.

		// 1. Verify the org images.
		orgImageMode := mode(p.orgPolicy.Defaults.Mode, p.orgPolicy.Defaults.Images.Mode)
		ok := verifyEntryResource(p.orgPolicy.Defaults.Images.List, imageURI)
		// NOTE: we do not return audit result, because the repositry config
		// may contain a enforcement result. We do return it later in the loop if not
		// enforce other failed results occur.
		if !ok && orgImageMode == ModeEnforce {
			return results.VerificationFail(fmt.Errorf("%q: image uri mismatch: %q", contextOrg, imageURI))
		}

		// Verify the repo policy.
		ok, err := verifyRepoProjects(p.repoPolicy, sourceURI, imageURI, orgImageMode)
		fmt.Println(ok, err)
		if err != nil {
			return results.VerificationInvalid(err)
		}
		if ok {
			return results.VerificationPass()
		}

	}

	return results.VerificationFail(fmt.Errorf("policy failure"))
}

func verifyResult(mode Mode, context context, field, uri string) results.Verification {
	if mode == ModeEnforce {
		return results.VerificationFail(fmt.Errorf("%q policy: %s uri mismatch: %q", context, field, uri))
	}

	return results.VerificationAudit(fmt.Sprintf("%q policy: %s uri mismatch: %q", context, field, uri))
}

func modeAllowed(orgLevel, repoLevel Mode) bool {
	return !(orgLevel == ModeEnforce && repoLevel == ModeAudit)
}

func verifyRepoProjects(repoPolicy RepoPolicy, sourceURI, imageURI string, orgMode Mode) (bool, error) {
	ok := len(repoPolicy.Projects) == 0
	for i := range repoPolicy.Projects {
		repoProject := &repoPolicy.Projects[i]

		m := orgMode
		if repoProject.Mode != nil {
			if !modeAllowed(orgMode, *repoProject.Mode) {
				return false, fmt.Errorf("%q policy: cannot overwrite %q", contextRepo, "mode")
			}
			m = mode(orgMode, repoProject.Mode)
		}

		ok := verifyRepoEntry(*repoProject, sourceURI, imageURI)
		if ok || m == ModeAudit {
			return ok, nil
		}
	}
	return ok, nil
}

func verifyRepoEntry(project Project, sourceURI, imageURI string) bool {
	sourceMatch := project.Source.URI == "" || Glob(project.Source.URI, sourceURI)
	imageMatch := Glob(project.Image.URI, imageURI)
	return sourceMatch && imageMatch
}

func verifyRepoEntryImages(entry Entry, repoImageMode Mode, imageURI string) bool {
	repoImages := entry.Images.List
	if len(repoImages) == 0 {
		return true
	}

	for j := range repoImages {
		repoImage := &repoImages[j]
		repoURI := repoImage.URI
		if Glob(repoURI, imageURI) {
			return true
		}
	}

	return false
}

func verifyEntryResource(resources []Resource, resourceURI string) bool {
	if len(resources) == 0 {
		return true
	}
	if len(resources) != 0 {
		for j := range resources {
			r := &resources[j]
			rURI := r.URI
			if Glob(rURI, resourceURI) {
				return true
			}
		}
	}
	return false
}

// func (p *Policy) verifyImages(sourceURI, imageURI string) results.Verification {
// 	if strings.Contains(imageURI, "*") {
// 		return results.VerificationFail(fmt.Errorf("invalid imageURI: %q", imageURI))
// 	}
// 	orgResult, effectiveMode := verifyImage(sourceURI, imageURI, ContextOrg, nil, p.policies[0])
// 	if orgResult.Fail() {
// 		return orgResult
// 	}

// 	repoResult, _ := verifyImage(sourceURI, imageURI, ContextRepo, &effectiveMode, p.policies[1])
// 	if repoResult.Fail() {
// 		return repoResult
// 	}
// 	// If the policy does not pass, return it.
// 	if !repoResult.Pass() {
// 		return repoResult
// 	}
// 	if !orgResult.Pass() {
// 		return orgResult
// 	}
// 	return results.VerificationPass()
// }

// func verifyImage(sourceURI, imageURI string, context Context, effectiveMode *Mode, policy PolicyElement) (results.Verification, Mode) {
// 	failedResult := results.VerificationFail(fmt.Errorf("%q policy: image uri mismatch: %q", context, imageURI))
// 	invalidModeResult := results.VerificationInvalid(fmt.Errorf("%q policy: cannot overwrite %q", context, "mode"))
// 	invalidSourcesResult := results.VerificationInvalid(fmt.Errorf("%q policy: wources is empty %q", context))
// 	result := failedResult
// 	// Update the effective mode only if it further restricts the policy (audit -> enforce).
// 	if !canUpdateMode(effectiveMode, policy.Defaults.Mode) {
// 		return invalidModeResult, *effectiveMode
// 	}
// 	callerMode := effectiveMode
// 	effectiveMode = pointer.To(Mode(policy.Defaults.Mode))

// 	// Try the default policy first.
// 	// We match on the source URIs to find an entry match.
// 	sources := policy.Defaults.Sources
// 	if len(sources) == 0 {
// 		fmt.Println(context, "no source")
// 		if context == ContextOrg {
// 			return invalidSourcesResult, *effectiveMode
// 		}
// 	} else {
// 		exist := contains(sources, sourceURI)
// 		if exist {
// 			images := policy.Defaults.Images.List
// 			exist := contains(images, imageURI)
// 			if exist || (len(images) == 0 && context == ContextRepo) {
// 				result = results.VerificationPass()
// 			} else {
// 				fmt.Println("failed2:", context, *effectiveMode)
// 				result = failedResult
// 				if policy.Projects == nil && policy.Defaults.Images.Mode != nil {
// 					if !canUpdateMode(effectiveMode, *policy.Defaults.Images.Mode) {
// 						return invalidModeResult, *effectiveMode
// 					}
// 					effectiveMode = pointer.To(Mode(mode(*effectiveMode, policy.Defaults.Images.Mode)))
// 				}
// 			}
// 		} else {
// 			fmt.Println("failed3:", context, *effectiveMode)
// 			result = failedResult
// 		}
// 	}

// 	// Verification failed. Try the exception list.
// 	if policy.Projects != nil {
// 		// Update the mode if it des not violate the caller's mode.
// 		fmt.Println(context, *effectiveMode)
// 		effectiveMode = pointer.To(Mode(mode(*effectiveMode, callerMode)))
// 		exceptions := policy.Projects.List
// 		for i := range exceptions {
// 			exception := &exceptions[i]
// 			images := exception.Images.List
// 			exist := contains(images, imageURI)
// 			if exist {
// 				// We found a match. Update the result and the effective mode.
// 				defaultMode := pointer.To(Mode(mode(*effectiveMode, policy.Projects.Mode)))
// 				newMode := pointer.To(Mode(mode(*defaultMode, exception.Images.Mode)))
// 				// The org policy can overwrite the mode.
// 				if context == ContextOrg {
// 					result = results.VerificationPass()
// 					*effectiveMode = *newMode
// 					continue
// 				}
// 				// The repo policy cannot overwrite an org policy.
// 				if context == ContextRepo && !canUpdateMode(effectiveMode, *defaultMode) {
// 					result = invalidModeResult
// 				} else {
// 					result = results.VerificationPass()
// 					*effectiveMode = *newMode
// 				}
// 			}
// 		}
// 	}

// 	fmt.Println(context, *effectiveMode)
// 	// Handle failure.
// 	if result.Fail() && *effectiveMode == ModeAudit {
// 		result = results.VerificationAudit(fmt.Sprintf("%q policy: source uri mismatch: %q", context, imageURI))
// 		return result, *effectiveMode
// 	}
// 	return result, *effectiveMode
// }

// func (p *Policy) verifySources(sourceURI string) results.Verification {
// 	if strings.Contains(sourceURI, "*") {
// 		return results.VerificationFail(fmt.Errorf("invalid sourceURI: %q", sourceURI))
// 	}

// 	orgResult, effectiveMode := verifySource(sourceURI, ContextOrg, nil, p.policies[0])
// 	if orgResult.Fail() {
// 		return orgResult
// 	}
// 	repoResult, _ := verifySource(sourceURI, ContextRepo, &effectiveMode, p.policies[1])
// 	if repoResult.Fail() {
// 		return repoResult
// 	}
// 	// If the policy does not pass, return it.
// 	if !repoResult.Pass() {
// 		return repoResult
// 	}
// 	if !orgResult.Pass() {
// 		return orgResult
// 	}
// 	return results.VerificationPass()
// }

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
