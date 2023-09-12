#!/bin/bash

set -euo pipefail

if [[ -z "${GH_TOKEN}" ]]; then
    echo "GH_TOKEN not set"
    exit 1
fi

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 image@digest [prod|staging]"
    echo "example: $0 ghcr.io/test-organization-ls/demo-a@sha256:4778b974bec2a5332cafebd3a2280d4c4cc7b8e51079646e164568a806484bd4"
    exit 1
fi

image_and_digest="$1"
image=$(echo "${image_and_digest}" | cut -d@ -f1)
digest=$(echo "${image_and_digest}" | cut -d@ -f2)

# deploy-staging.yml workflow has ID 68687147
# gh api   -H "Accept: application/vnd.github+json"   -H "X-GitHub-Api-Version: 2022-11-28"   /repos/test-organization-ls/demo-a/actions/workflows
build_type="$2"
case "${build_type}" in
  prod)
    workflow_id=69072956
    ;;

  staging)
    workflow_id=68687147
    ;;

  *)
    echo "unknown build_type: ${build_type}"
    exit 1
    ;;
esac

# NOTE: ref: main is optional.
curl -L \
  -X POST \
  -H "Accept: application/vnd.github+json" \
  -H "Authorization: Bearer ${GH_TOKEN}" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  https://api.github.com/repos/test-organization-ls/demo-a/actions/workflows/${workflow_id}/dispatches \
  -d "{\"ref\":\"main\",\"inputs\":{\"image\":\"${image}\",\"digest\":\"${digest}\"}}"

# Verify the VSA via:
# cosign verify-attestation ghcr.io/test-organization-ls/demo-a@sha256:4778b974bec2a5332cafebd3a2280d4c4cc7b8e51079646e164568a806484bd4 \
#           --certificate-oidc-issuer https://token.actions.githubusercontent.com \
#           --certificate-identity-regexp https://github.com/laurentsimon/slsa-policy/.github/workflows/verify-slsa.yml@refs/tags/v[0-9].[0-9].[0-9] \
#           --type https://slsa.dev/verification_summary/v1 | jq