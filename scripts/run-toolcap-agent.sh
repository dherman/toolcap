#!/bin/bash
# Wrapper script to run Claude Code ACP with Toolcap proxy
# This is needed because Zed's settings.json can't properly quote multi-word commands

exec /Users/dherman/.cargo/bin/sacp-conductor \
    --debug \
    agent \
    /Users/dherman/Code/toolcap/target/release/toolcap-proxy \
    -- \
    "npx -y @zed-industries/claude-code-acp"
