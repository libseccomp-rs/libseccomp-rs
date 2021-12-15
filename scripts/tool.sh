#!/bin/bash
#
# SPDX-License-Identifier: Apache-2.0 or MIT
#

set -eo pipefail

# Print usage information
usage() {
	cat <<-EOM
	USAGE:
	  ./tool.sh [-h] -i <seccomp.h> -o <seccomp.h.rs>

	-h  Show this help and exit.
	-i  path to seccomp.h
	-o  path to seccomp.h.rs
	EOM
}

# Parse commandline arguments
while getopts "hi:o:" opt; do
	case $opt in
		h)
			usage
			exit 0
		;;
		i)
			INPUT="$OPTARG"
		;;
		o)
			OUTPUT="$OPTARG"
		;;
		*)
			exit 2
		;;
	esac
done

# Input and Output file are required.
if [[ -z "$INPUT" || -z "$OUTPUT" ]]; then
	usage
	exit 2
fi

# bindgen is maybe not installed, print a helpful message in this case
if ! command -v bindgen >/dev/null; then
	echo "Please install bindgen: cargo install bindgen"
	exit 5
fi

bindgen \
	--default-enum-style=rust \
	--no-layout-tests \
	--no-doc-comments \
	--allowlist-type="SCMP_.*" \
	--allowlist-type="scmp_.*" \
	--allowlist-type="seccomp_.*" \
	--allowlist-function="seccomp_.*" \
	--allowlist-var=".*SCMP_.*" \
	--allowlist-var="SECCOMP_.*" \
	--output "$OUTPUT"  \
	"$INPUT"
