#!/usr/bin/env bash
set -euo pipefail

# Default behavior is handled in Python script:
# - no args => generate MAS/LLM/API all
python3 .qa/security/scripts/run_attack_security_review.py "$@"
