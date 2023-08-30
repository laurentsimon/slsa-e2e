#!/bin/bash

set -euo pipefail

source .github/workflows/common.sh

digest_type=$(echo "${UNTRUSTED_DIGEST}" | cut -d@ -f1)
digest_value=$(echo "${UNTRUSTED_DIGEST}" | cut -d@ -f2)
time_verified=$(Tue Aug 29 10:29:23 PM UTC 2023)

verification_result="FAILED"
if [[ "${SUCCESS}" == "true" ]]; then
    verification_result="PASSED"
fi
level="info"
message="SLSA: deployement verification success"
# TODO: support dynamic message / level.

cat <<EOF | jq | tee attestation.deploy
{
    "_type": "https://in-toto.io/Statement/v0.1",
    "subject": [
        {
            "name": "${UNTRUSTED_IMAGE}",
            "digest":
            {
                "${digest_type}": "${digest_value}"
            }
        }
    ],
    "predicateType": "https://slsa.dev/deploy/k8/v0.1",
    "predicate": {
        "verifier": {
            "id": "${TRUSTED_POLICY_ENTITY}"
        },
        "time_verified": "${time_verified}",
        "policy": {
            "uri": "${UNTRUSTED_USER_POLICY}",
        },
        "verificationResult": "${verification_result}",
        "logging": {
            "level": "${level}",
            "message": "${message}"
        },
        "metadata": {
            "namespace": "${UNTRUSTED_NAMESPACE}",
            "labels": {
                "${UNTRUSTED_LABELS}"
            }
        }
    }
}
EOF

# TODO: sign with cosign and store in file https://fig.io/manual/cosign/sign
# WARNING: this does not include Rekor information.
# https://github.com/sigstore/cosign/issues/3110
# https://github.com/sigstore/cosign/pull/2994 
# echo "attestation-name=${attestation_name}.build.slsa" >>"${GITHUB_OUTPUT}"

# caller will use attach