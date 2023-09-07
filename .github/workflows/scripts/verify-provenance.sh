#!/bin/bash

#set -euo pipefail disabled on purpose.
source .github/workflows/scripts/common.sh


# slsa-verifier only supports GH and GCB builders.
# For simplicity, let's try both and see which passes.
# TODO: we need an 'inspect' feature in slsa-verifier that
# verifies provenance and output a JSON verification summary
# containing repository, ref and builder ID.

tag_args=()
if [[ "${GITHUB_REF}" = "refs/tags/"* ]]; then
    source_tag=$(echo "${GITHUB_REF}" | cut -d/ -f3)
    tag_args=("--source-tag ${source_tag}")
fi

builder_id=https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml
provenance=$(slsa-verifier verify-image "${IMMUTABLE_IMAGE}" \
            --source-uri "github.com/${GITHUB_REPOSITORY}"  "${tag_args[@]}" \
            --builder-id "${builder_id}" \
            --print-provenance)

if [[ "${provenance}" != "" ]]; then
    echo "builder_id=${builder_id}" >> "$GITHUB_OUTPUT"
    echo "source_uri=git+https://github.com/${GITHUB_REPOSITORY}" >> "$GITHUB_OUTPUT"
    exit 0
fi

builder_id=https://cloudbuild.googleapis.com/GoogleHostedWorker
provenance=$(slsa-verifier verify-image "${IMMUTABLE_IMAGE}" \
            --source-uri "github.com/${GITHUB_REPOSITORY}"  "${tag_args[@]}" \
            --builder-id "${builder_id}" \
            --print-provenance)

if [[ "${provenance}" != "" ]]; then
    echo "builder_id=${builder_id}" >> "$GITHUB_OUTPUT"
    echo "source_uri=git+https://github.com/${GITHUB_REPOSITORY}" >> "$GITHUB_OUTPUT"
    exit 0
fi

# Failure
log_error "provenance verification failed"