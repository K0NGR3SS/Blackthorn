#!/bin/bash
# Legacy wrapper around the unified Blackthorn CLI.
# New scripts should use the installed `blackthorn` command or blackthorn.sh.
cd "$(dirname "$0")"
python3 -m wafpierce "$@"
