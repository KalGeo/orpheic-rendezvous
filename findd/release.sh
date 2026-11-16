#!/bin/sh
# The ONE way to build findd for the VPS (DNS/supply-chain audit 5/11 #3): the lockfile as committed, the pinned toolchain,
# NEVER the bench feature, and a sha256 written down so the box can be checked against what was built.
#   server/findd/release.sh          → target/release/findd + a line in server/findd/RELEASES.tsv
set -eu
cd "$(dirname "$0")"
TOOLCHAIN=$(sed -n 's/^channel *= *"\(.*\)"/\1/p' rust-toolchain.toml)
cargo +"$TOOLCHAIN" build --release --locked --bins
BIN=target/release/findd
# the switch that lifts the per-host limits exists only with --features bench: refuse a binary that carries it
if grep -a -q FINDD_BENCH "$BIN"; then echo "REFUSED: $BIN was built with the bench feature" >&2; exit 1; fi
SUM=$(sha256sum "$BIN" | cut -d' ' -f1)
COMMIT=$(git rev-parse --short HEAD)$(git diff --quiet -- . || echo "-dirty")
printf '%s\t%s\t%s\t%s\n' "$(date -u +%Y-%m-%dT%H:%MZ)" "$COMMIT" "$TOOLCHAIN" "$SUM" >> RELEASES.tsv
echo "findd $COMMIT ($TOOLCHAIN) sha256 $SUM"
echo "on the VPS, after copying: sha256sum /opt/orpheic-findd/findd   must print the same"
