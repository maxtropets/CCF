#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -ex
set -o pipefail

# Detect Azure Linux version
AZL_VERSION_ID="$(. /etc/os-release && echo "$VERSION_ID")"
case "$AZL_VERSION_ID" in
    3.*) AZL_MAJOR=3 ;;
    4.*) AZL_MAJOR=4 ;;
    *)
        echo "ERROR: Unsupported Azure Linux version '$AZL_VERSION_ID'."
        exit 1
        ;;
esac

if [[ "$AZL_MAJOR" -eq 3 ]]; then
    tdnf -y install  \
        clang-tools-extra  \
        python-pip \
        jq \
        tar \
        npm \
        build-essential
else
    tdnf -y install  \
        clang-tools-extra  \
        python3-pip \
        jq \
        tar \
        nodejs-npm \
        gcc \
        gcc-c++ \
        make \
        binutils
fi

# For LTS test to extract binaries from rpms
tdnf -y install cpio

pip install gersemi

# For shellcheck
curl -L https://github.com/koalaman/shellcheck/releases/download/stable/shellcheck-stable.linux.x86_64.tar.xz  \
    --output shellcheck.tar.gz
mkdir -p shellcheck-dir
tar -xvf shellcheck.tar.gz -C shellcheck-dir
mv shellcheck-dir/shellcheck-stable/shellcheck /usr/local/bin/shellcheck
rm -rf shellcheck-dir shellcheck.tar.gz
