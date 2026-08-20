#!/bin/sh
# Install the REQUIRED release-binary scanners (subfinder, httpx, nuclei, ffuf)
# with PINNED versions and SHA-256 checksum verification.
#
# Shared by BOTH the API image (backend/Dockerfile) and the worker image
# (backend/Dockerfile.worker) so the two can never drift: whichever process runs
# the pipeline (inline in the API, or out-of-process in the worker) has the same
# verified toolchain. `nmap` and `whois` are installed via apt in the Dockerfiles
# (they are not release binaries).
#
# Required env: SUBFINDER_VERSION, HTTPX_VERSION, NUCLEI_VERSION, FFUF_VERSION.
# Optional env: TARGETARCH (default "amd64"; Docker buildx sets this per target).
#
# The build FAILS (non-zero exit) if any download, checksum, or post-install
# version check fails — a broken or tampered artifact can never ship silently.
set -eux

: "${SUBFINDER_VERSION:?SUBFINDER_VERSION is required}"
: "${HTTPX_VERSION:?HTTPX_VERSION is required}"
: "${NUCLEI_VERSION:?NUCLEI_VERSION is required}"
: "${FFUF_VERSION:?FFUF_VERSION is required}"

ARCH="${TARGETARCH:-amd64}"
BIN=/usr/local/bin
PD=https://github.com/projectdiscovery
work="$(mktemp -d)"
cd "$work"

# verify <artifact> <checksums-file>: fail CLOSED if the artifact's line is
# missing from the publisher's checksums file (an empty grep must never pass).
verify() {
    want="$(grep " $1\$" "$2")" || { echo "FATAL: no checksum entry for $1 in $2"; exit 1; }
    printf '%s\n' "$want" | sha256sum -c -
}

# --- ProjectDiscovery tools: <tool>_<ver>_linux_<arch>.zip + checksums.txt ---- #
for entry in "subfinder:${SUBFINDER_VERSION}" "httpx:${HTTPX_VERSION}" "nuclei:${NUCLEI_VERSION}"; do
    tool="${entry%%:*}"
    ver="${entry##*:}"
    arc="${tool}_${ver}_linux_${ARCH}.zip"
    curl -fsSL -o "$arc"           "${PD}/${tool}/releases/download/v${ver}/${arc}"
    curl -fsSL -o "checks_${tool}" "${PD}/${tool}/releases/download/v${ver}/${tool}_${ver}_checksums.txt"
    verify "$arc" "checks_${tool}"
    unzip -o "$arc" "$tool" -d "$BIN"
    chmod 0755 "$BIN/$tool"
done

# --- ffuf: ffuf_<ver>_linux_<arch>.tar.gz + ffuf_<ver>_checksums.txt ---------- #
farc="ffuf_${FFUF_VERSION}_linux_${ARCH}.tar.gz"
curl -fsSL -o "$farc"     "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/${farc}"
curl -fsSL -o checks_ffuf "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_checksums.txt"
verify "$farc" checks_ffuf
tar -xzf "$farc" -C "$BIN" ffuf
chmod 0755 "$BIN/ffuf"

cd /
rm -rf "$work"

# --- Fail the build unless every REQUIRED binary is present and runnable ------ #
subfinder -version
httpx -version
nuclei -version
ffuf -V
echo "[install-scanners] OK: subfinder ${SUBFINDER_VERSION}, httpx ${HTTPX_VERSION}, nuclei ${NUCLEI_VERSION}, ffuf ${FFUF_VERSION} installed + checksum-verified"
