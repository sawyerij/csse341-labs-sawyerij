#!/bin/bash

# attacker is top left running poison
tmux new-window "./poison.sh"

# attacker running sniff is top right
tmux split-window -h "./sniff.sh"

# attacker running netcat is bottom left
tmux select-pane -t 0
tmux split-window -v "./run_attacker.sh 'nc -n -l 9090'"

# host A is bottom right and runs telnet
tmux select-pane -t 2
tmux split-window -v "./run_hostA.sh 'telnet hostB'"

# Select the first pane
tmux select-pane -t 3
