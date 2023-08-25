#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
REPO_ROOT="$SCRIPT_DIR/.."
SUITE_ROOT="$REPO_ROOT/../.."

DOCKER="docker"
DOCKER_OPTS=""

run_compile() {
    if [ "$USE_DOCKER" = true ]; then
        $DOCKER build -t tests-env "$SCRIPT_DIR/docker"

        $DOCKER run $DOCKER_OPTS \
            --rm \
            --user $(id -u ${USER}):$(id -g ${USER}) \
            --volume ${SUITE_ROOT}:/home:Z -w /home \
            tests-env \
            sh -c "bash ./ci.sh compile"
        cd -
    else
        cd "$SUITE_ROOT"
        ls -la
        mkdir build && cd build
        CMAKE_ARGS="-DCMAKE_BUILD_TYPE=Debug -DBUILD_SHARED_LIBS=FALSE -DBUILD_TESTS=TRUE"
        cmake $CMAKE_ARGS ..
        cd -
    fi
}

USE_DOCKER=false

while [[ "$#" -gt 0 ]]; do
    case $1 in
    -d | --docker) USE_DOCKER=true ;;
    -v|--verbose) set -x ;;
    compile) SUBCOMMAND=run_compile ;;
    *)
        echo "Unknown parameter passed: $1"
        exit 1
        ;;
    esac
    shift
done

$SUBCOMMAND
