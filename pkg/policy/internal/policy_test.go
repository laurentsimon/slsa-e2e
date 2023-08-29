package internal

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/laurentsimon/slsa-e2e/pkg/policy/internal/utils/pointer"
)

func Test_enforced(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		enforcement Enforcement
		sourceURI   string
		expected    bool
	}{
		{
			name:      "enforced: all deny with repo match",
			sourceURI: "git+https://github.com/org/repo",
			expected:  true,
			enforcement: Enforcement{
				OnViolation: EnforcementTypeDeny,
				Overwrite: Overwrite{
					Default: EnforcementTypeDeny,
					Exceptions: []Exception{
						{
							Sources: []Source{
								{
									URI: "git+https://github.com/org/repo",
								},
							},
							Overwrite:   pointer.To(EnforcementType(EnforcementTypeDeny)),
							OnViolation: pointer.To(EnforcementType(EnforcementTypeDeny)),
						},
					},
				},
			},
		},
		{
			name:      "enforced: (violation, overwrite) = (deny, deny), e.(violation, overwrite) = (nil, deny)",
			sourceURI: "git+https://github.com/org/repo",
			expected:  true,
			enforcement: Enforcement{
				OnViolation: EnforcementTypeDeny,
				Overwrite: Overwrite{
					Default: EnforcementTypeDeny,
					Exceptions: []Exception{
						{
							Sources: []Source{
								{
									URI: "git+https://github.com/org/repo",
								},
							},
							Overwrite: pointer.To(EnforcementType(EnforcementTypeDeny)),
						},
					},
				},
			},
		},
		{
			name:      "not enforced: (violation, overwrite) = (deny, deny), e.(violation, overwrite) = (nil, allow)",
			sourceURI: "git+https://github.com/org/repo",
			expected:  false,
			enforcement: Enforcement{
				OnViolation: EnforcementTypeDeny,
				Overwrite: Overwrite{
					Default: EnforcementTypeDeny,
					Exceptions: []Exception{
						{
							Sources: []Source{
								{
									URI: "git+https://github.com/org/repo",
								},
							},
							Overwrite: pointer.To(EnforcementType(EnforcementTypeAllow)),
						},
					},
				},
			},
		},
		{
			name:      "enforced: (violation, overwrite) = (deny, allow), e.(violation, overwrite) = (nil, deny)",
			sourceURI: "git+https://github.com/org/repo",
			expected:  true,
			enforcement: Enforcement{
				OnViolation: EnforcementTypeDeny,
				Overwrite: Overwrite{
					Default: EnforcementTypeAllow,
					Exceptions: []Exception{
						{
							Sources: []Source{
								{
									URI: "git+https://github.com/org/repo",
								},
							},
							Overwrite: pointer.To(EnforcementType(EnforcementTypeDeny)),
						},
					},
				},
			},
		},
		{
			name:      "not enforced: (violation, overwrite) = (deny, allow), e.(violation, overwrite) = (nil, allow)",
			sourceURI: "git+https://github.com/org/repo",
			expected:  false,
			enforcement: Enforcement{
				OnViolation: EnforcementTypeDeny,
				Overwrite: Overwrite{
					Default: EnforcementTypeAllow,
					Exceptions: []Exception{
						{
							Sources: []Source{
								{
									URI: "git+https://github.com/org/repo",
								},
							},
							Overwrite: pointer.To(EnforcementType(EnforcementTypeAllow)),
						},
					},
				},
			},
		},
		{
			name:      "not enforced: (violation, overwrite) = (deny, allow), e.(violation, overwrite) = (allow, allow)",
			sourceURI: "git+https://github.com/org/repo",
			expected:  false,
			enforcement: Enforcement{
				OnViolation: EnforcementTypeDeny,
				Overwrite: Overwrite{
					Default: EnforcementTypeAllow,
					Exceptions: []Exception{
						{
							Sources: []Source{
								{
									URI: "git+https://github.com/org/repo",
								},
							},
							Overwrite:   pointer.To(EnforcementType(EnforcementTypeAllow)),
							OnViolation: pointer.To(EnforcementType(EnforcementTypeAllow)),
						},
					},
				},
			},
		},
		{
			name:      "not enforced: (violation, overwrite) = (deny, allow), e.(violation, overwrite) = (deny, allow)",
			sourceURI: "git+https://github.com/org/repo",
			expected:  false,
			enforcement: Enforcement{
				OnViolation: EnforcementTypeDeny,
				Overwrite: Overwrite{
					Default: EnforcementTypeAllow,
					Exceptions: []Exception{
						{
							Sources: []Source{
								{
									URI: "git+https://github.com/org/repo",
								},
							},
							Overwrite:   pointer.To(EnforcementType(EnforcementTypeAllow)),
							OnViolation: pointer.To(EnforcementType(EnforcementTypeDeny)),
						},
					},
				},
			},
		},
		{
			name:      "enforced: (violation, overwrite) = (deny, allow), e.(violation, overwrite) = (deny, deny)",
			sourceURI: "git+https://github.com/org/repo",
			expected:  true,
			enforcement: Enforcement{
				OnViolation: EnforcementTypeDeny,
				Overwrite: Overwrite{
					Default: EnforcementTypeAllow,
					Exceptions: []Exception{
						{
							Sources: []Source{
								{
									URI: "git+https://github.com/org/repo",
								},
							},
							Overwrite:   pointer.To(EnforcementType(EnforcementTypeDeny)),
							OnViolation: pointer.To(EnforcementType(EnforcementTypeDeny)),
						},
					},
				},
			},
		},
		{
			name:      "not enforced: (violation, overwrite) = (deny, allow), e.(violation, overwrite) = (allow, deny)",
			sourceURI: "git+https://github.com/org/repo",
			expected:  false,
			enforcement: Enforcement{
				OnViolation: EnforcementTypeDeny,
				Overwrite: Overwrite{
					Default: EnforcementTypeAllow,
					Exceptions: []Exception{
						{
							Sources: []Source{
								{
									URI: "git+https://github.com/org/repo",
								},
							},
							Overwrite:   pointer.To(EnforcementType(EnforcementTypeDeny)),
							OnViolation: pointer.To(EnforcementType(EnforcementTypeAllow)),
						},
					},
				},
			},
		},
		{
			name:      "enforced: (violation, overwrite) = (allow, allow), e.(violation, overwrite) = (deny, deny)",
			sourceURI: "git+https://github.com/org/repo",
			expected:  true,
			enforcement: Enforcement{
				OnViolation: EnforcementTypeAllow,
				Overwrite: Overwrite{
					Default: EnforcementTypeAllow,
					Exceptions: []Exception{
						{
							Sources: []Source{
								{
									URI: "git+https://github.com/org/repo",
								},
							},
							Overwrite:   pointer.To(EnforcementType(EnforcementTypeDeny)),
							OnViolation: pointer.To(EnforcementType(EnforcementTypeDeny)),
						},
					},
				},
			},
		},
		{
			name:      "not enforced: (violation, overwrite) = (allow, deny), e.(violation, overwrite) = (nil, deny)",
			sourceURI: "git+https://github.com/org/repo",
			expected:  false,
			enforcement: Enforcement{
				OnViolation: EnforcementTypeAllow,
				Overwrite: Overwrite{
					Default: EnforcementTypeAllow,
					Exceptions: []Exception{
						{
							Sources: []Source{
								{
									URI: "git+https://github.com/org/repo",
								},
							},
							Overwrite: pointer.To(EnforcementType(EnforcementTypeDeny)),
						},
					},
				},
			},
		},
		{
			name:      "not enforced: (violation, overwrite) = (allow, deny), e.(violation, overwrite) = (nil, allow)",
			sourceURI: "git+https://github.com/org/repo",
			expected:  false,
			enforcement: Enforcement{
				OnViolation: EnforcementTypeAllow,
				Overwrite: Overwrite{
					Default: EnforcementTypeDeny,
					Exceptions: []Exception{
						{
							Sources: []Source{
								{
									URI: "git+https://github.com/org/repo",
								},
							},
							Overwrite: pointer.To(EnforcementType(EnforcementTypeAllow)),
						},
					},
				},
			},
		},
		{
			name:      "not enforced: (violation, overwrite) = (allow, deny), e.(violation, overwrite) = (deny, allow)",
			sourceURI: "git+https://github.com/org/repo",
			expected:  false,
			enforcement: Enforcement{
				OnViolation: EnforcementTypeAllow,
				Overwrite: Overwrite{
					Default: EnforcementTypeDeny,
					Exceptions: []Exception{
						{
							Sources: []Source{
								{
									URI: "git+https://github.com/org/repo",
								},
							},
							Overwrite:   pointer.To(EnforcementType(EnforcementTypeAllow)),
							OnViolation: pointer.To(EnforcementType(EnforcementTypeDeny)),
						},
					},
				},
			},
		},
		{
			name:      "not enforced: (violation, overwrite) = (allow, deny), e.(violation, overwrite) = (nil, deny)",
			sourceURI: "git+https://github.com/org/repo",
			expected:  false,
			enforcement: Enforcement{
				OnViolation: EnforcementTypeAllow,
				Overwrite: Overwrite{
					Default: EnforcementTypeDeny,
					Exceptions: []Exception{
						{
							Sources: []Source{
								{
									URI: "git+https://github.com/org/repo",
								},
							},
							Overwrite: pointer.To(EnforcementType(EnforcementTypeDeny)),
						},
					},
				},
			},
		},
		{
			name:      "not enforced: (violation, overwrite) = (allow, deny), e.(violation, overwrite) = (allow, deny)",
			sourceURI: "git+https://github.com/org/repo",
			expected:  false,
			enforcement: Enforcement{
				OnViolation: EnforcementTypeAllow,
				Overwrite: Overwrite{
					Default: EnforcementTypeDeny,
					Exceptions: []Exception{
						{
							Sources: []Source{
								{
									URI: "git+https://github.com/org/repo",
								},
							},
							Overwrite:   pointer.To(EnforcementType(EnforcementTypeDeny)),
							OnViolation: pointer.To(EnforcementType(EnforcementTypeAllow)),
						},
					},
				},
			},
		},
		{
			name:      "enforced: (violation, overwrite) = (allow, deny), e.(violation, overwrite) = (deny, deny)",
			sourceURI: "git+https://github.com/org/repo",
			expected:  true,
			enforcement: Enforcement{
				OnViolation: EnforcementTypeAllow,
				Overwrite: Overwrite{
					Default: EnforcementTypeDeny,
					Exceptions: []Exception{
						{
							Sources: []Source{
								{
									URI: "git+https://github.com/org/repo",
								},
							},
							Overwrite:   pointer.To(EnforcementType(EnforcementTypeDeny)),
							OnViolation: pointer.To(EnforcementType(EnforcementTypeDeny)),
						},
					},
				},
			},
		},
		{
			name:      "not enforced: (violation, overwrite) = (allow, deny), e.(violation, overwrite) = (nil, nil)",
			sourceURI: "git+https://github.com/org/repo",
			expected:  false,
			enforcement: Enforcement{
				OnViolation: EnforcementTypeAllow,
				Overwrite: Overwrite{
					Default: EnforcementTypeDeny,
					Exceptions: []Exception{
						{
							Sources: []Source{
								{
									URI: "git+https://github.com/org/repo",
								},
							},
						},
					},
				},
			},
		},
		{
			name:      "enforced: (violation, overwrite) = (allow, deny), e.(violation, overwrite) = (nil, deny)",
			sourceURI: "git+https://github.com/org/repo",
			expected:  true,
			enforcement: Enforcement{
				OnViolation: EnforcementTypeAllow,
				Overwrite: Overwrite{
					Default: EnforcementTypeDeny,
					Exceptions: []Exception{
						{
							Sources: []Source{
								{
									URI: "git+https://github.com/org/repo",
								},
							},
							OnViolation: pointer.To(EnforcementType(EnforcementTypeDeny)),
						},
					},
				},
			},
		},
		{
			name:      "not enforced: (violation, overwrite) = (deny, allow), e.(violation, overwrite) = (nil, nil)",
			sourceURI: "git+https://github.com/org/repo",
			expected:  false,
			enforcement: Enforcement{
				OnViolation: EnforcementTypeDeny,
				Overwrite: Overwrite{
					Default: EnforcementTypeAllow,
					Exceptions: []Exception{
						{
							Sources: []Source{
								{
									URI: "git+https://github.com/org/repo",
								},
							},
						},
					},
				},
			},
		},
		{
			name:      "not enforced: (violation, overwrite) = (deny, allow), e.(violation, overwrite) = (allow, nil)",
			sourceURI: "git+https://github.com/org/repo",
			expected:  false,
			enforcement: Enforcement{
				OnViolation: EnforcementTypeDeny,
				Overwrite: Overwrite{
					Default: EnforcementTypeAllow,
					Exceptions: []Exception{
						{
							Sources: []Source{
								{
									URI: "git+https://github.com/org/repo",
								},
							},
							OnViolation: pointer.To(EnforcementType(EnforcementTypeAllow)),
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := enforced(tt.enforcement, tt.sourceURI)
			if diff := cmp.Diff(tt.expected, result); diff != "" {
				t.Fatalf("unexpected result (-want +got): \n%s", diff)
			}
		})
	}
}
