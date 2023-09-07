#!/bin/bash

#set -euo pipefail disabled on purpose.
source .github/workflows/common.sh


# slsa-verifier only supports GH and GCB builders.
# For simplicity, let's try both and see which passes.
# TODO: we need an 'inspect' feature in slsa-verifier that
# verifies provenance and output a JSON verification summary
# containing repository, ref and builder ID.
TAG_ARGS=""
if [[ "${GITHUB_REF}" = "refs/tags/"* ]]; then
    TAG_ARGS=$(echo "${GITHUB_REF}" | cut -d/ -f3)
    TAG_FLAG="--source-tag"
fi

builder_id=https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml
provenance=$(slsa-verifier verify-image "${IMMUTABLE_IMAGE}" \
            --source "github.com/${GITHUB_REPOSITORY}"  "${TAG_FLAG}" "${TAG_ARGS}" \
            --builder "${builder_id}" \
            --print-provenance)

if [[ "${provenance}" != "" ]]; then
    echo "builder_id=${builder_id}" >> "$GITHUB_OUTPUT"
    echo "source_uri=git+https://github.com/${GITHUB_REPOSITORY}" >> "$GITHUB_OUTPUT"
    exit 0
fi

builder_id=https://cloudbuild.googleapis.com/GoogleHostedWorker
provenance=$(slsa-verifier verify-image "${IMMUTABLE_IMAGE}" \
            --source "github.com/${GITHUB_REPOSITORY}"  "${TAG_FLAG}" "${TAG_ARGS}" \
            --builder "${builder_id}" \
            --print-provenance)

if [[ "${provenance}" != "" ]]; then
    echo "builder_id=${builder_id}" >> "$GITHUB_OUTPUT"
    echo "source_uri=git+https://github.com/${GITHUB_REPOSITORY}" >> "$GITHUB_OUTPUT"
    exit 0
fi

# Failure
log_error "provenance verification failed"