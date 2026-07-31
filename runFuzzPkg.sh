#!/usr/bin/bash

# ./runFuzzPkg.sh targets.txt ./fuzz_pkg.sh

set -uo pipefail

TARGETS_FILE="${1:-targets.txt}"
FUZZ_SCRIPT="${2:-./fuzz_pkg.sh}"

OUTPUT_DIR="./fuzzOutput"
SUMMARY_LOG="${OUTPUT_DIR}/summary.log"

# TIME_LIMIT="60s"
TIME_LIMIT="59m"

checkInputsExist() {
    if [[ ! -f "$TARGETS_FILE" ]]; then
        echo "targets file not found: $TARGETS_FILE" >&2
        exit 1
    fi

    if [[ ! -x "$FUZZ_SCRIPT" ]]; then
        echo "fuzz script not found or not executable: $FUZZ_SCRIPT" >&2
        exit 1
    fi
}

runOnePackage() {
    local pkg="$1"
    local pkgDir="${OUTPUT_DIR}/${pkg}"
    local logFile="${pkgDir}/output.log"

    mkdir -p "$pkgDir"

    echo "========================================"
    echo "Starting: $pkg (limit: $TIME_LIMIT)"
    echo "========================================"

    local startTS endTS elapsed status exitCode

    startTS=$(date +%s)

    timeout --kill-after=10s "$TIME_LIMIT" \
        "$FUZZ_SCRIPT" "$pkg" > "$logFile" 2>&1 &
    local runPid=$!

    while kill -0 "$runPid" 2>/dev/null; do
        elapsed=$(( $(date +%s) - startTS))
        # printf "\r %ds elapsed..." "$elapsed"
        sleep 1
    done
    printf "\n"

    wait "$runPid"
    exitCode=$?

    endTS=$(date +%s)
    elapsed=$((endTS - startTS))

    if [[ "$exitCode" -eq 124 ]]; then
        status="TIMEOUT"
    elif [[ "$exitCode" -eq 0 ]]; then
        status="OK"
    else
        status="FAILED"
    fi

    echo "${pkg}: ${status} (${elapsed}s)" | tee -a "$SUMMARY_LOG"
}

runAllPackages() {
    while IFS= read -r pkg || [[ -n "$pkg" ]]; do
        pkg="$(echo "$pkg" | xargs)"  # trim whitespace
        [[ -z "$pkg" ]] && continue  # skip blank lines

        runOnePackage "$pkg"
    done < "$TARGETS_FILE"
}

main() {
    checkInputsExist

    mkdir -p "$OUTPUT_DIR"
    : > "$SUMMARY_LOG"

    runAllPackages

    echo ""
    echo "All done. Summary:"
    cat "$SUMMARY_LOG"
}

main

