#!/bin/bash

#set -euo pipefail

go run . eval --labels 'key1=val1, key2=val2' --files 'pkg/policy/testdata/org.json,pkg/policy/testdata/repo.json' --source-uri git+https://github.com/googlenot/repo1 --image-uri docker://googlenot/myimage:v1.2.3 --builder-id https://github.com/another/org/.github/workflows/generator_container_slsa3.ym
echo $?

export GITHUB_REF=refs/tags/v1.2.3

if [[ "${GITHUB_REF}" = "refs/tags/"* ]]; then
    echo yes
    TAG_ARGS=$(echo "${GITHUB_REF}" | cut -d/ -f3)
    TAG_FLAG="--source-tag"
    echo $TAG_FLAG $TAG_ARGS
else
    echo no
fi