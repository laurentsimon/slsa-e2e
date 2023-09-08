#!/bin/bash

set -euo pipefail

source .github/workflows/scripts/common.sh

digest_type=$(echo "${UNTRUSTED_DIGEST}" | cut -d: -f1)
digest_value=$(echo "${UNTRUSTED_DIGEST}" | cut -d: -f2)
time_verified=$(date)

verification_result="FAILED"
if [[ "${SUCCESS}" == "true" ]]; then
    verification_result="PASSED"
fi

cat <<EOF | jq > vsa.json
"verifier": {
    "id": "${TRUSTED_VERIFIER}"
},
"time_verified": "${time_verified}",
    "policy": {
    "uri": "${UNTRUSTED_USER_POLICY}"
},
"verificationResult": "${verification_result}"
EOF

if [[ -n "${UNTRUSTED_NAMESPACE:-}" ]]; then
   jq <vsa.json ".predicate.metadata.namespace = \"${UNTRUSTED_NAMESPACE}\"" > tmp.json
    mv tmp.json vsa.json
fi

if [[ -n "${UNTRUSTED_LABELS:-}" ]]; then
    # TODO: validate that UNTRUSTED_LABELS is a map.
    jq <vsa.json ".predicate.metadata.labels = ${UNTRUSTED_LABELS}" > tmp.json
    mv tmp.json vsa.json
fi

jq <vsa.json

# TODO: sign with cosign and store in file https://fig.io/manual/cosign/sign
# WARNING: this does not include Rekor information.
# https://github.com/sigstore/cosign/issues/3110
# https://github.com/sigstore/cosign/pull/2994 
cosign attest --yes --type https://slsa.dev/verification_summary/v1 --predicate vsa.json "${UNTRUSTED_IMAGE}@${UNTRUSTED_DIGEST}"

# caller will use attach
