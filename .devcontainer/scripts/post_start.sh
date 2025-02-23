#!/bin/bash
set -ev
sudo mount -t tracefs nodev /sys/kernel/tracing
sudo mount -t debugfs nodev /sys/kernel/debug
