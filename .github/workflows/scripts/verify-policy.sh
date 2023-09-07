#!/bin/bash

set -euo pipefail

source .github/workflows/scripts/common.sh

if [[ "${UNTRUSTED_BUILDER_ID}" == "" ]]; then
    log_error "internal error: no builder ID"
fi

validate_path "${UNTRUSTED_USER_POLICY}"
trusted_path="${UNTRUSTED_USER_POLICY}"

./policy-verifier eval \
    --files ".slsa/policy.json,${trusted_path}" \
    --source-uri "${UNTRUSTED_REPOSITORY}" \
    --image-uri "${UNTRUSTED_MUTABLE_IMAGE}" \
    --builder-id "${UNTRUSTED_BUILDER_ID}"
