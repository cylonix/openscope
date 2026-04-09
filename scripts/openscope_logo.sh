#!/usr/bin/env bash
set -euo pipefail

reset=$'\033[0m'
ink=$'\033[38;5;255m'
teal=$'\033[38;5;87m'
cyan=$'\033[38;5;51m'
blue=$'\033[38;5;39m'
slate=$'\033[38;5;245m'

# Simplified terminal mark: a clean scope aperture plus a compact wordmark.
cat <<EOF
${slate}              ${teal}████████████${reset}
${slate}           ${teal}████${cyan}████████${teal}████${reset}
${slate}         ${teal}███${cyan}███${ink}██████${cyan}███${teal}███${reset}
${slate}        ${teal}██${cyan}██${ink}██${blue}█    █${ink}██${cyan}██${teal}██${reset}
${slate}        ${teal}██${cyan}██${ink}██${blue}█    █${ink}██${cyan}██${teal}██${reset}
${slate}        ${teal}██${cyan}██${ink}██${blue}█    █${ink}██${cyan}██${teal}██${reset}
${slate}         ${teal}███${cyan}███${ink}██████${cyan}███${teal}███${reset}
${slate}           ${teal}████${cyan}████████${teal}████${reset}
${slate}              ${teal}████████████${reset}

${ink}                open${cyan}Scope${reset}
${slate}             scoped, not open-ended${reset}
EOF
