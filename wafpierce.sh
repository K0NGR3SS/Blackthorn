#!/bin/bash
# Thin wrapper around the unified WAFPierce CLI.
#   ./wafpierce.sh scan https://target -t 20 --impersonate chrome
#   ./wafpierce.sh chain https://target
#   ./wafpierce.sh doctor
#   ./wafpierce.sh https://target            # defaults to `scan`
cd "$(dirname "$0")"
python3 -m wafpierce "$@"
