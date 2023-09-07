#!/bin/bash

set -euo pipefail

source .github/workflows/scripts/common.sh

if [[ "${UNTRUSTED_BUILDER_ID}" == "" ]]; then
    log_error "internal error: no builder ID"
fi

validate_path "${UNTRUSTED_USER_POLICY}"
trusted_path="${UNTRUSTED_USER_POLICY}"

"${POLICY_BINARY}" eval \
    --files "__THIS_REPO__/.slsa/policy.json,${trusted_path}" \
    --source-uri "${UNTRUSTED_REPOSITORY}" \
    --image-uri "${UNTRUSTED_MUTABLE_IMAGE}" \
    --builder-id "${UNTRUSTED_BUILDER_ID}"

#go run . eval --labels 'key1=val1, key2=val2' --files 'pkg/policy/testdata/org.json,pkg/policy/testdata/repo.json' --source-uri git+https://github.com/googlenot/repo1  