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

type context string

const (
	contextOrg  context = "org"
	contextRepo context = "repo"
)

type Tracks struct {
	Source SourceTrack `json:"source"`
	Build  BuildTrack  `json:"build"`
}

type Entry struct {
	Tracks  Tracks     `json:"tracks"`
	Images  []Resource `json:"images"`
	Sources []Resource `json:"sources"`
}

type OrgPolicy struct {
	Version  int     `json:"version"`
	Defaults *Entry  `json:"defaults"`
	Projects []Entry `json:"projects"`
}

type Project struct {
	Source Resource `json:"source"`
	Image  Resource `json:"image"`
}

type RepoPolicy struct {
	Version  int       `json:"version"`
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

func validateOrgPolicy(p OrgPolicy) error {
	if p.Version != 1 {
		return fmt.Errorf("%q policy: invalid %q", contextOrg, "source")
	}
	if len(p.Defaults.Sources) == 0 {
		return fmt.Errorf("%q policy: empty %q", contextOrg, "sources")
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
	orgDefault := p.verifyOrgDefault(sourceURI, imageURI, builderID)
	if orgDefault.Pass() {
		return orgDefault
	}
	return p.verifyOrgProjects(sourceURI, imageURI, builderID)
}

func (p *Policy) verifyOrgProjects(sourceURI, imageURI, builderID string) results.Verification {
	if len(p.orgPolicy.Projects) == 0 {
		return results.VerificationPass()
	}
	for i := range p.orgPolicy.Projects {
		project := &p.orgPolicy.Projects[i]
		result := p.verifyOrgEntry(*project, sourceURI, imageURI, builderID)
		if result.Pass() {
			return result
		}
	}
	return results.VerificationFail(fmt.Errorf("policy failure"))
}
func (p *Policy) verifyOrgDefault(sourceURI, imageURI, builderID string) results.Verification {
	return p.verifyOrgEntry(*p.orgPolicy.Defaults, sourceURI, imageURI, builderID)
}

func (p *Policy) verifyOrgEntry(entry Entry, sourceURI, imageURI, builderID string) results.Verification {
	// Sources are validated and are non-empty.
	for i := range entry.Sources {
		orgSource := &entry.Sources[i]
		orgURI := orgSource.URI
		if !Glob(orgURI, sourceURI) {
			continue
		}

		// We have a match on the source.

		// 1. Verify the org images.
		ok := verifyEntryResource(entry.Images, imageURI)
		if !ok {
			return results.VerificationFail(fmt.Errorf("%q: image uri mismatch: %q", contextOrg, imageURI))
		}

		// 2. verify org build track.
		ok = verifyBuildTrack(entry.Tracks.Build.Builders, builderID)
		if !ok {
			return results.VerificationFail(fmt.Errorf("%q: builder ID mismatch: %q", contextOrg, builderID))
		}

		// Verify the repo policy.
		ok, err := verifyRepoProjects(p.repoPolicy, sourceURI, imageURI)
		if err != nil {
			return results.VerificationInvalid(err)
		}
		if ok {
			return results.VerificationPass()
		}

	}

	return results.VerificationFail(fmt.Errorf("policy failure"))
}

func verifyRepoProjects(repoPolicy RepoPolicy, sourceURI, imageURI string) (bool, error) {
	if len(repoPolicy.Projects) == 0 {
		return true, nil
	}
	for i := range repoPolicy.Projects {
		repoProject := &repoPolicy.Projects[i]
		ok := verifyRepoEntry(*repoProject, sourceURI, imageURI)
		if ok {
			return true, nil
		}
	}
	return false, nil
}

func verifyRepoEntry(project Project, sourceURI, imageURI string) bool {
	sourceMatch := project.Source.URI == "" || Glob(project.Source.URI, sourceURI)
	imageMatch := project.Image.URI == "" || Glob(project.Image.URI, imageURI)
	return sourceMatch && imageMatch
}

func verifyBuildTrack(builders []Builder, builderID string) bool {
	if len(builders) == 0 {
		return true
	}
	for j := range builders {
		b := &builders[j]
		bid := b.ID
		if Glob(bid, builderID) {
			return true
		}
	}

	return false

}
func verifyEntryResource(resources []Resource, resourceURI string) bool {
	if len(resources) == 0 {
		return true
	}
	for j := range resources {
		r := &resources[j]
		rURI := r.URI
		if Glob(rURI, resourceURI) {
			return true
		}
	}

	return false
}
