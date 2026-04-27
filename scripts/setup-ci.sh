#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -ex
set -o pipefail

H2SPEC_VERSION="v2.6.0"

export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(date +%s)}
echo "Using SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}"

# Detect Azure Linux version
AZL_VERSION_ID="$(. /etc/os-release && echo "$VERSION_ID")"
AZL_ID="$(. /etc/os-release && echo "$ID")"

if [[ "$AZL_ID" != "azurelinux" && "$AZL_ID" != "mariner" ]]; then
    echo "ERROR: Unsupported distro '$AZL_ID'. Expected 'azurelinux' or 'mariner'."
    exit 1
fi

case "$AZL_VERSION_ID" in
    3.*)
        AZL_MAJOR=3
        ;;
    4.*)
        AZL_MAJOR=4
        ;;
    *)
        echo "ERROR: Unsupported Azure Linux version '$AZL_VERSION_ID'."
        exit 1
        ;;
esac

echo "Detected Azure Linux $AZL_MAJOR ($AZL_VERSION_ID)"

# Package install wrapper: AzL3 supports --snapshottime, AzL4 (dnf5) does not.
pkg_install() {
    if [[ "$AZL_MAJOR" -eq 3 ]]; then
        tdnf --snapshottime="$SOURCE_DATE_EPOCH" -y install "$@"
    else
        tdnf -y install "$@"
    fi
}

# Source control
pkg_install  \
    git  \
    ca-certificates

# To build CCF — package names differ between AzL3 and AzL4.
if [[ "$AZL_MAJOR" -eq 3 ]]; then
    pkg_install  \
        build-essential  \
        clang  \
        cmake  \
        ninja-build  \
        which  \
        openssl-devel  \
        libuv-devel  \
        nghttp2-devel  \
        curl-devel  \
        libarrow-devel  \
        parquet-libs-devel  \
        doxygen  \
        clang-tools-extra-devel
else
    # AzL4 native equivalents
    # - build-essential meta-package does not exist; install its components
    # - nghttp2-devel / curl-devel renamed to libnghttp2-devel / libcurl-devel
    # - clang-tools-extra-devel not needed (only the clang-tidy binary is used)
    # - libarrow-devel / parquet-libs-devel not yet available on AzL4;
    #   the perf submitter build is skipped via ENABLE_PERF_SUBMITTER=OFF
    pkg_install  \
        gcc  \
        gcc-c++  \
        make  \
        binutils  \
        clang  \
        cmake  \
        ninja-build  \
        which  \
        openssl-devel  \
        libuv-devel  \
        libnghttp2-devel  \
        libcurl-devel  \
        doxygen  \
        clang-tools-extra
fi

# To run standard tests
if [[ "$AZL_MAJOR" -eq 3 ]]; then
    pkg_install lldb expect npm jq
else
    pkg_install lldb expect nodejs-npm jq
fi

# Extra-dependency for CDDL schema checker
pkg_install rubygems
gem install cddl

# Release (extended) tests
if [[ "$AZL_MAJOR" -eq 3 ]]; then
    pkg_install procps
else
    pkg_install procps-ng
fi

# protocoltest
pkg_install bind-utils
curl -L --output h2spec_linux_amd64.tar.gz https://github.com/summerwind/h2spec/releases/download/$H2SPEC_VERSION/h2spec_linux_amd64.tar.gz
tar -xvf h2spec_linux_amd64.tar.gz
mkdir -p /opt/h2spec
mv h2spec /opt/h2spec/h2spec
rm h2spec_linux_amd64.tar.gz

# partitions test
if [[ "$AZL_MAJOR" -eq 3 ]]; then
    pkg_install iptables
else
    pkg_install iptables-nft
fi
pkg_install strace

# For packaging
pkg_install rpm-build

# For end to end tests and scripts
pkg_install python3-pip
pip install uv==0.10.8

# Rust
pkg_install rust cargo
