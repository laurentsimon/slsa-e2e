#!/bin/bash

log_error() {
    local msg="$1"
    echo "::error::${msg}"
    exit 1
}

validate_path() {
    local untrusted_path="$1"
    resolved_dir=$(readlink -m "${untrusted_path}")
    wd=$(readlink -m "${GITHUB_WORKSPACE}")
    if [[ "${wd}" != "" ]] && [[ "${resolved_dir}" != "${wd}"/* ]] && [[ "${resolved_dir}" != "${wd}" ]]; then
        if [[ "${RUNNER_TEMP}" != "" ]] && [[ "${resolved_dir}" != "${RUNNER_TEMP}"/* ]] && [[ "${resolved_dir}" != "${RUNNER_TEMP}" ]]; then
        if [[ "${resolved_dir}" != /tmp/* ]] && [[ "${resolved_dir}" != "/tmp" ]]; then
            log_error "Path is not in the current directory: ${untrusted_path}"
        fi
        fi
    fi
}