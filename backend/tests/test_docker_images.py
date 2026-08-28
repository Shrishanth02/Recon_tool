"""P0-6 regression tests — Docker image scanner-toolchain configuration (static).

Docker is not required to run these: they assert the build *configuration* is
correct so the required scanner binaries are installed, checksum-verified, and
version-checked in BOTH the API image (inline execution default) and the worker
image. Actually building the images is a separate manual/CI step.
"""

from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
BACKEND = REPO / "backend"

# Release binaries the shared installer must fetch + verify.
REQUIRED_RELEASE_BINS = ["subfinder", "httpx", "nuclei", "ffuf"]
VERSION_ARGS = ["SUBFINDER_VERSION", "HTTPX_VERSION", "NUCLEI_VERSION", "FFUF_VERSION"]


def _read(p: Path) -> str:
    return p.read_text(encoding="utf-8", errors="ignore") if p.exists() else ""


def test_install_script_verifies_checksums_and_fails_closed():
    s = _read(BACKEND / "install-scanners.sh")
    assert s, "install-scanners.sh is missing"
    assert "set -eux" in s, "installer must fail-closed"
    assert "sha256sum -c" in s, "installer must verify checksums"
    # A missing checksum line must abort (fail closed), not silently pass.
    assert "no checksum entry" in s
    for tool in REQUIRED_RELEASE_BINS:
        assert tool in s, f"installer does not handle {tool}"


def test_install_script_version_checks_every_required_binary():
    s = _read(BACKEND / "install-scanners.sh")
    for check in ["subfinder -version", "httpx -version", "nuclei -version", "ffuf -V"]:
        assert check in s, f"installer missing post-install check: {check}"


def test_both_images_run_the_shared_installer_with_pinned_versions():
    for name in ("Dockerfile", "Dockerfile.worker"):
        d = _read(BACKEND / name)
        assert d, f"{name} missing"
        assert "install-scanners.sh" in d, f"{name} must run the shared installer"
        for arg in VERSION_ARGS:
            assert arg in d, f"{name} missing pinned {arg}"


def test_both_images_install_apt_scanners():
    # nmap (REQUIRED) + whois (OPTIONAL recon, but provisioned) come from apt.
    for name in ("Dockerfile", "Dockerfile.worker"):
        d = _read(BACKEND / name)
        assert "nmap" in d, f"{name} must install nmap"
        assert "whois" in d, f"{name} must install whois"
        assert "nmap --version" in d, f"{name} must verify nmap"


def test_installer_reaches_the_build_context():
    """The installer must not be excluded by .dockerignore (nor a blanket *.sh)."""
    di = _read(BACKEND / ".dockerignore")
    assert "*.sh" not in di, ".dockerignore must not exclude shell scripts"
    assert "install-scanners.sh" not in di


def test_ci_builds_scanner_image_under_configured_default_tag():
    """The advertised Docker-isolation mode runs ``SCANNER_IMAGE``; CI must build it.

    The scanner image is the worker toolchain image — ``Dockerfile.worker`` carries
    the scanners and has no ``ENTRYPOINT``, so ``docker run <img> nmap ...`` runs the
    scanner directly. CI builds it under the exact tag the app defaults to, so the
    isolation mode always has an image to run (previously nothing built that tag).
    """
    from app.config import settings

    assert settings.SCANNER_IMAGE == "reconx-scanner:latest"
    ci = _read(REPO / ".github" / "workflows" / "ci.yml")
    assert ci, "ci.yml missing"
    assert (
        "docker build -t reconx-scanner:latest -f ./backend/Dockerfile.worker ./backend"
        in ci
    ), "CI must build the scanner image under the configured default tag"
    # An ENTRYPOINT would swallow the scanner argv instead of running it as the cmd.
    dw = _read(BACKEND / "Dockerfile.worker")
    assert not any(
        line.strip().startswith("ENTRYPOINT") for line in dw.splitlines()
    ), "Dockerfile.worker must have no ENTRYPOINT so the scanner argv runs directly"
