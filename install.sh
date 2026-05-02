#!/usr/bin/env bash
# install.sh — set up cra-sbom-cli on macOS or Linux.
#
# What this does (in order):
#   1. Detects your OS / package manager.
#   2. Verifies python3 (>= 3.10).
#   3. Installs the Python package 'reportlab' for the current user.
#   4. Optionally installs grype, sbomqs, jq (asks first — never silent).
#   5. Symlinks bin/cra-sbom-report into a directory on your PATH
#      (default: ~/.local/bin; --system uses /usr/local/bin via sudo).
#   6. Verifies the install with `cra-sbom-report --help`.
#
# Usage:
#   ./install.sh                   # user-local install (no sudo)
#   ./install.sh --system          # system-wide install (uses sudo for symlink)
#   ./install.sh --no-symlink      # install deps but skip the PATH symlink
#   ./install.sh --yes             # answer 'yes' to all prompts (CI-friendly)
#
# Re-running install.sh is safe — every step is idempotent.

set -euo pipefail

# ---------- color helpers ----------
if [[ -t 1 ]]; then
  C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'; C_GREEN=$'\033[32m'; C_RED=$'\033[31m'
  C_YELLOW=$'\033[33m'; C_CYAN=$'\033[36m'; C_RESET=$'\033[0m'
else
  C_BOLD=''; C_DIM=''; C_GREEN=''; C_RED=''; C_YELLOW=''; C_CYAN=''; C_RESET=''
fi
say()  { printf "${C_BOLD}==>${C_RESET} %s\n" "$*"; }
ok()   { printf "  ${C_GREEN}✓${C_RESET} %s\n" "$*"; }
warn() { printf "  ${C_YELLOW}!${C_RESET} %s\n" "$*"; }
err()  { printf "  ${C_RED}✗${C_RESET} %s\n" "$*" >&2; }
ask()  {
  local q="$1"
  if [[ "${ASSUME_YES}" == "1" ]]; then printf "  ${C_DIM}[--yes]${C_RESET} %s ... yes\n" "$q"; return 0; fi
  read -r -p "  ${q} [y/N] " answer
  [[ "${answer,,}" == "y" || "${answer,,}" == "yes" ]]
}

# ---------- args ----------
INSTALL_MODE="user"        # user | system | no-symlink
ASSUME_YES="0"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --system)      INSTALL_MODE="system" ;;
    --no-symlink)  INSTALL_MODE="no-symlink" ;;
    --yes|-y)      ASSUME_YES="1" ;;
    -h|--help)
      sed -n '/^# Usage:/,/^$/p' "$0" | sed 's/^# \?//'
      exit 0 ;;
    *) err "unknown arg: $1"; exit 1 ;;
  esac
  shift
done

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
SCRIPT="${REPO_ROOT}/bin/cra-sbom-report"

# ---------- detect OS / package manager ----------
say "Detecting platform"
OS_KIND=""
PKG_MGR=""
PKG_INSTALL_HINT=""
case "$(uname -s)" in
  Darwin)
    OS_KIND="macos"
    if command -v brew >/dev/null 2>&1; then
      PKG_MGR="brew"; PKG_INSTALL_HINT="brew install"
    fi ;;
  Linux)
    if   command -v apt-get >/dev/null 2>&1; then OS_KIND="debian"; PKG_MGR="apt-get"; PKG_INSTALL_HINT="sudo apt-get install -y"
    elif command -v dnf >/dev/null 2>&1;     then OS_KIND="fedora"; PKG_MGR="dnf";     PKG_INSTALL_HINT="sudo dnf install -y"
    elif command -v yum >/dev/null 2>&1;     then OS_KIND="rhel";   PKG_MGR="yum";     PKG_INSTALL_HINT="sudo yum install -y"
    elif command -v pacman >/dev/null 2>&1;  then OS_KIND="arch";   PKG_MGR="pacman";  PKG_INSTALL_HINT="sudo pacman -S --noconfirm"
    elif command -v zypper >/dev/null 2>&1;  then OS_KIND="suse";   PKG_MGR="zypper";  PKG_INSTALL_HINT="sudo zypper install -y"
    else                                          OS_KIND="linux"
    fi ;;
  *)
    err "Unsupported OS: $(uname -s). Only macOS and Linux are tested."
    exit 1 ;;
esac
ok "OS: ${OS_KIND}${PKG_MGR:+ (package manager: ${PKG_MGR})}"

# ---------- python3 check ----------
say "Checking Python"
if ! command -v python3 >/dev/null 2>&1; then
  err "python3 is not on PATH."
  case "${OS_KIND}" in
    macos)  warn "Install with: brew install python  (or download from python.org)" ;;
    debian) warn "Install with: sudo apt-get install -y python3 python3-pip" ;;
    fedora) warn "Install with: sudo dnf install -y python3 python3-pip" ;;
    rhel)   warn "Install with: sudo yum install -y python3 python3-pip" ;;
    arch)   warn "Install with: sudo pacman -S python python-pip" ;;
    suse)   warn "Install with: sudo zypper install python3 python3-pip" ;;
  esac
  exit 1
fi

PY_VERSION="$(python3 -c 'import sys; print("{}.{}".format(*sys.version_info[:2]))')"
PY_MAJOR="${PY_VERSION%.*}"; PY_MINOR="${PY_VERSION#*.}"
if [[ "${PY_MAJOR}" -lt 3 ]] || { [[ "${PY_MAJOR}" -eq 3 ]] && [[ "${PY_MINOR}" -lt 10 ]]; }; then
  err "python3 ${PY_VERSION} is too old. Need 3.10+."
  exit 1
fi
ok "python3 ${PY_VERSION}"

# ---------- pip + reportlab ----------
say "Installing the Python dependency (reportlab)"
PIP_CMD=""
if   python3 -m pip --version >/dev/null 2>&1;     then PIP_CMD="python3 -m pip"
elif command -v pip3 >/dev/null 2>&1;              then PIP_CMD="pip3"
elif command -v pip >/dev/null 2>&1;               then PIP_CMD="pip"
else
  err "pip is not available."
  case "${OS_KIND}" in
    debian) warn "Install with: sudo apt-get install -y python3-pip" ;;
    fedora) warn "Install with: sudo dnf install -y python3-pip" ;;
    *)      warn "Install pip for python3, then re-run." ;;
  esac
  exit 1
fi

if python3 -c "import reportlab" >/dev/null 2>&1; then
  ok "reportlab already installed"
else
  # PEP 668 systems (newer Debian/Ubuntu, Homebrew Python) refuse a plain
  # pip install. Use --user when available; if even that's blocked, suggest
  # a venv as a last resort.
  if ${PIP_CMD} install --user reportlab >/dev/null 2>&1; then
    ok "installed reportlab (--user)"
  elif ${PIP_CMD} install --user --break-system-packages reportlab >/dev/null 2>&1; then
    warn "installed reportlab with --break-system-packages (PEP 668 environment)"
  else
    err "Could not install reportlab. Suggested alternatives:"
    cat >&2 <<EOF
       Option A — virtualenv (recommended):
         python3 -m venv ~/.cra-sbom-cli-venv
         source ~/.cra-sbom-cli-venv/bin/activate
         pip install reportlab
         ./install.sh --no-symlink     # then re-run as needed

       Option B — system pip with override (use only if you understand PEP 668):
         ${PIP_CMD} install --user --break-system-packages reportlab
EOF
    exit 1
  fi
fi

# ---------- optional tools ----------
say "Checking optional tools (grype, sbomqs, jq)"

_offer_install() {
  local tool="$1" install_cmd="$2"
  if command -v "${tool}" >/dev/null 2>&1; then
    ok "${tool} found ($(command -v "${tool}"))"
    return 0
  fi
  warn "${tool} not found"
  if [[ -z "${install_cmd}" ]]; then
    printf "       (no auto-install command for this OS — see ${C_BOLD}docs/INSTALLATION.md${C_RESET})\n"
    return 0
  fi
  if ask "Install ${tool} now? (${install_cmd})"; then
    if eval "${install_cmd}"; then ok "installed ${tool}"
    else err "install command failed; skipping"
    fi
  else
    printf "       skipped — feature will report 'unavailable' in reports\n"
  fi
}

# Per-OS install commands. None of these run without confirmation.
case "${OS_KIND}" in
  macos)
    if [[ "${PKG_MGR}" == "brew" ]]; then
      _offer_install grype  "brew install anchore/grype/grype"
      _offer_install sbomqs "brew install interlynk/sbomqs/sbomqs"
      _offer_install jq     "brew install jq"
    else
      warn "Homebrew not found — install it from https://brew.sh, then re-run."
    fi
    ;;
  debian)
    _offer_install grype  "curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo sh -s -- -b /usr/local/bin"
    _offer_install sbomqs "curl -sSfL https://raw.githubusercontent.com/interlynk-io/sbomqs/main/install.sh | sudo sh -s -- -b /usr/local/bin"
    _offer_install jq     "sudo apt-get install -y jq"
    ;;
  fedora|rhel)
    _offer_install grype  "curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo sh -s -- -b /usr/local/bin"
    _offer_install sbomqs "curl -sSfL https://raw.githubusercontent.com/interlynk-io/sbomqs/main/install.sh | sudo sh -s -- -b /usr/local/bin"
    _offer_install jq     "${PKG_INSTALL_HINT} jq"
    ;;
  arch)
    _offer_install grype  "sudo pacman -S --noconfirm grype || curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo sh -s -- -b /usr/local/bin"
    _offer_install sbomqs "curl -sSfL https://raw.githubusercontent.com/interlynk-io/sbomqs/main/install.sh | sudo sh -s -- -b /usr/local/bin"
    _offer_install jq     "sudo pacman -S --noconfirm jq"
    ;;
  *)
    _offer_install grype  ""
    _offer_install sbomqs ""
    _offer_install jq     ""
    ;;
esac

# ---------- PATH symlink ----------
chmod +x "${SCRIPT}"

if [[ "${INSTALL_MODE}" == "no-symlink" ]]; then
  say "Symlink step skipped (--no-symlink)"
  warn "You'll need to invoke the script directly: ${SCRIPT}"
else
  say "Linking cra-sbom-report onto your PATH"
  if [[ "${INSTALL_MODE}" == "system" ]]; then
    DEST_DIR="/usr/local/bin"
    if [[ ! -w "${DEST_DIR}" ]]; then
      warn "Need sudo to write to ${DEST_DIR}"
      sudo ln -sf "${SCRIPT}" "${DEST_DIR}/cra-sbom-report"
    else
      ln -sf "${SCRIPT}" "${DEST_DIR}/cra-sbom-report"
    fi
  else
    DEST_DIR="${HOME}/.local/bin"
    mkdir -p "${DEST_DIR}"
    ln -sf "${SCRIPT}" "${DEST_DIR}/cra-sbom-report"
  fi
  ok "linked → ${DEST_DIR}/cra-sbom-report"

  # PATH check (only relevant for --user)
  if [[ "${INSTALL_MODE}" == "user" ]]; then
    case ":${PATH}:" in
      *":${DEST_DIR}:"*) ok "${DEST_DIR} is on your PATH" ;;
      *)
        warn "${DEST_DIR} is NOT on your PATH."
        printf "       Add it with one of:\n"
        printf "         echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.zshrc   # zsh\n"
        printf "         echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.bashrc  # bash\n"
        printf "       Then open a new shell.\n"
        ;;
    esac
  fi
fi

# ---------- verify ----------
say "Verifying install"
if "${SCRIPT}" --help >/dev/null 2>&1; then
  ok "cra-sbom-report --help works"
else
  err "cra-sbom-report --help did not exit cleanly"
  exit 1
fi

echo
say "${C_GREEN}Done.${C_RESET}"
echo "  Try it on the bundled module's example, or any SBOM you have:"
echo
echo "    cra-sbom-report path/to/sbom.json --no-enrich"
echo
