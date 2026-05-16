#!/usr/bin/env bash
set -e

BOLD="\033[1m"
GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
RESET="\033[0m"

info()    { echo -e "${BOLD}[*]${RESET} $1"; }
success() { echo -e "${GREEN}[✓]${RESET} $1"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $1"; }
error()   { echo -e "${RED}[✗]${RESET} $1"; exit 1; }

echo -e "${BOLD}"
echo "  ██╗  ██╗ ██████╗ ███╗   ██╗██████╗ "
echo "  ██║ ██╔╝██╔═══██╗████╗  ██║██╔══██╗"
echo "  █████╔╝ ██║   ██║██╔██╗ ██║██████╔╝"
echo "  ██╔═██╗ ██║   ██║██║╚██╗██║██╔══██╗"
echo "  ██║  ██╗╚██████╔╝██║ ╚████║██║  ██║"
echo "  ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝"
echo -e "${RESET}"
echo "  AI Penetration Testing System"
echo ""

# ── Check Python ────────────────────────────────────────────────────
info "Checking Python version..."
if ! command -v python3 &>/dev/null; then
    error "Python 3.12+ is required but not found."
fi

PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
REQUIRED="3.12"
if [ "$(printf '%s\n' "$REQUIRED" "$PYTHON_VERSION" | sort -V | head -n1)" != "$REQUIRED" ]; then
    error "Python $REQUIRED+ required, found $PYTHON_VERSION"
fi
success "Python $PYTHON_VERSION found"

# ── Install uv if missing ────────────────────────────────────────────
if ! command -v uv &>/dev/null && ! [ -f "$HOME/.local/bin/uv" ]; then
    info "Installing uv..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.local/bin:$PATH"
    success "uv installed"
else
    export PATH="$HOME/.local/bin:$PATH"
    success "uv already installed"
fi

# ── Create venv and install dependencies ────────────────────────────
info "Creating virtual environment..."
uv venv
success ".venv created"

info "Installing dependencies..."
uv pip install -e ".[dev]"
success "Dependencies installed"

# ── Done ─────────────────────────────────────────────────────────────
echo ""
success "KonR is ready"
echo ""
echo "  Activate your environment:"
echo "    source .venv/bin/activate"
echo ""
echo "  Then launch:"
echo "    konr --help"
echo ""
