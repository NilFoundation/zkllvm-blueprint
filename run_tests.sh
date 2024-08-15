#!/usr/bin/env bash
set -e

echo "building ${TEST_LIST[*]}"
ninja -k 0 -j $NIX_BUILD_CORES

echo "finish"
