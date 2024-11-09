#!/bin/bash

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
FSTRACE="$SCRIPT_DIR/../build/fstrace"

function test_signal_passthrough() {
    local signal=$1
    local expected_exit_code=$2
    $FSTRACE bash -c "
sleep 10
" &
    FSTRACE_PID=$!

    sleep 1
    kill -$signal $FSTRACE_PID
    wait $FSTRACE_PID 2>/dev/null
    FSTRACE_EXIT_CODE=$?

    if [ $FSTRACE_EXIT_CODE -eq $expected_exit_code ]; then
        echo "Signal passthrough test passed. Signal $signal was passed. Exit code: $FSTRACE_EXIT_CODE"
    else
        echo "Signal passthrough test failed. Expected $expected_exit_code, got $FSTRACE_EXIT_CODE"
        exit 1
    fi
}

test_signal_passthrough 15 143 # SIGTERM
test_signal_passthrough 9 137  # SIGKILL
