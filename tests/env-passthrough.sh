#!/bin/bash

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
FSTRACE="$SCRIPT_DIR/../build/fstrace"

function test_env_passthrough() {
    FSTRACE_ENV=$($FSTRACE bash -c "env")
    BASH_ENV=$(bash -c "env")

    if [ "$FSTRACE_ENV" == "$BASH_ENV" ]; then
        echo "Environment passthrough test passed"
    else
        echo "Environment passthrough test failed"
        exit 1
    fi
}

test_env_passthrough
