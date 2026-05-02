# Installation

The fastest path is `./install.sh` from the repo root. This file documents
the underlying steps for environments where the auto-installer doesn't fit
(custom Linux distros, locked-down CI, virtualenvs, etc.).

## Hard requirements

| Requirement     | Why                                |
|---|---|
| Python ≥ 3.10   | Runs the compliance engine + helper |
| `reportlab` ≥ 4 | Renders the PDF                     |

## Optional tools

These augment the report; they are not required to produce a verdict.

| Tool      | What it adds                   | Install (per-OS hints below) |
|---|---|---|
| `grype`   | Known-vulnerability counts     | Anchore install script |
| `sbomqs`  | SBOM quality score             | Interlynk install script |
| `jq`      | Faster shell-side JSON parsing | OS package manager |

If a tool is missing, the report shows `unavailable` for that section. The
verdict is unaffected.

---

## Install per OS

### macOS

```bash
# Python (Apple-supplied is fine; otherwise:)
brew install python

# Python dep
python3 -m pip install --user reportlab

# Optional tooling
brew install jq
brew install anchore/grype/grype
brew install interlynk/sbomqs/sbomqs

# Symlink so it's on PATH
mkdir -p ~/.local/bin
ln -sf "$(pwd)/bin/cra-sbom-report" ~/.local/bin/cra-sbom-report
# Add ~/.local/bin to PATH if it isn't already (zsh):
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
```

### Ubuntu / Debian

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-pip jq
python3 -m pip install --user reportlab

# grype + sbomqs (Anchore + Interlynk install scripts)
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
    | sudo sh -s -- -b /usr/local/bin
curl -sSfL https://raw.githubusercontent.com/interlynk-io/sbomqs/main/install.sh \
    | sudo sh -s -- -b /usr/local/bin

mkdir -p ~/.local/bin
ln -sf "$(pwd)/bin/cra-sbom-report" ~/.local/bin/cra-sbom-report
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
```

> **PEP 668 note**: on newer Debian/Ubuntu, `pip install --user reportlab`
> may refuse with an "externally-managed-environment" error. Two ways out:
> 1. Use a venv (recommended): `python3 -m venv .venv && source .venv/bin/activate && pip install reportlab`
> 2. Override (only if you accept the risk): `pip install --user --break-system-packages reportlab`

### Fedora / RHEL / CentOS

```bash
sudo dnf install -y python3 python3-pip jq
python3 -m pip install --user reportlab

curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
    | sudo sh -s -- -b /usr/local/bin
curl -sSfL https://raw.githubusercontent.com/interlynk-io/sbomqs/main/install.sh \
    | sudo sh -s -- -b /usr/local/bin
```

(Replace `dnf` with `yum` on older RHEL/CentOS.)

### Arch / Manjaro

```bash
sudo pacman -S python python-pip jq grype
python3 -m pip install --user reportlab
curl -sSfL https://raw.githubusercontent.com/interlynk-io/sbomqs/main/install.sh \
    | sudo sh -s -- -b /usr/local/bin
```

### openSUSE

```bash
sudo zypper install python3 python3-pip jq
python3 -m pip install --user reportlab
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
    | sudo sh -s -- -b /usr/local/bin
curl -sSfL https://raw.githubusercontent.com/interlynk-io/sbomqs/main/install.sh \
    | sudo sh -s -- -b /usr/local/bin
```

### Windows (WSL2 only)

Native Windows is not supported. Install
[WSL2](https://learn.microsoft.com/windows/wsl/install) and follow the
Ubuntu instructions inside it.

---

## Virtualenv install (any OS)

```bash
python3 -m venv .venv
source .venv/bin/activate    # Windows: .venv\Scripts\activate (in WSL: same as Linux)
pip install -r requirements.txt
# Run directly:
./bin/cra-sbom-report --help
# Or pip-install the package itself:
pip install .
cra-sbom-report --help
```

---

## Verify

```bash
cra-sbom-report --help
python3 -c "import cra_sbom_cli; print(cra_sbom_cli.__version__)"
```

If `cra-sbom-report` isn't found, your `~/.local/bin` (or wherever you
symlinked it) probably isn't on PATH. The installer prints the exact line
to add.

## Uninstall

```bash
# Drop the symlink
rm -f ~/.local/bin/cra-sbom-report   # or /usr/local/bin/cra-sbom-report

# Drop the Python dep (if you don't use reportlab elsewhere)
python3 -m pip uninstall reportlab

# Drop the repo
rm -rf cra-sbom-cli
```

Optional tools (`grype`, `sbomqs`, `jq`) stay where they are — uninstall
them via your OS package manager if you no longer need them.
