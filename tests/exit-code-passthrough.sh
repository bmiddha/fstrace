#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
FSTRACE="$SCRIPT_DIR/../build/fstrace"

function test_exit_code_passthrough() {
    local exit_code=$1

    $FSTRACE bash -c "exit $exit_code"
    FSTRACE_EXIT_CODE=$?

    bash -c "exit $exit_code"
    BASH_EXIT_CODE=$?

    if [ $FSTRACE_EXIT_CODE -eq $BASH_EXIT_CODE ]; then
        echo "Exit code passthrough test passed"
    else
        echo "Exit code passthrough test failed"
        exit 1
    fi
}

test_exit_code_passthrough 100
