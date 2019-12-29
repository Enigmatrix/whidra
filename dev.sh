#!/usr/bin/env bash
tmux neww -n whidra-dev
tmux splitw -v
tmux splitw -h

tmux send-keys -t 1 "cd server" Enter "./gradlew run --no-daemon" Enter
tmux send-keys -t 2 "cd webapp" Enter "yarn serve" Enter
tmux send-keys -t 3 "docker-compose -f docker-compose.dev.yml up" Enter
