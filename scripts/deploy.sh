#!/bin/bash
# substrate-guard Combo A — Deploy to AI Research Agency
# Server: ai-research-agency (89.167.66.225)
# Architecture: ARM64 (aarch64), Ubuntu 24.04, Kernel 6.8
# RAM: 3.7 GB (2.1 GB free), CPU: 2 vCPU
# Stack: Docker (11 containers), FastAPI backend, PostgreSQL, Redis
#
# Usage:
#   ./deploy.sh test       # dry run — verify deps only
#   ./deploy.sh install    # install on host (Option C: hybrid mock)
#   ./deploy.sh docker     # build Docker container (Option A)
#   ./deploy.sh full       # install with real eBPF + OPA (Option B)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${CYAN}[deploy]${NC} $1"; }
ok()   { echo -e "${GREEN}[  ok  ]${NC} $1"; }
warn() { echo -e "${YELLOW}[ warn ]${NC} $1"; }
fail() { echo -e "${RED}[ fail ]${NC} $1"; }

# ============================================
# Detect architecture
# ============================================

detect_arch() {
    ARCH=$(uname -m)
    case "$ARCH" in
        aarch64|arm64)
            ARCH_LABEL="arm64"
            OPA_ARCH="linux_arm64_static"
            ;;
        x86_64|amd64)
            ARCH_LABEL="amd64"
            OPA_ARCH="linux_amd64_static"
            ;;
        *)
            fail "Unsupported architecture: $ARCH"
            exit 1
            ;;
    esac
    ok "Architecture: $ARCH ($ARCH_LABEL)"
}

# ============================================
# Step 1: Check dependencies
# ============================================

check_deps() {
    log "Checking dependencies..."
    
    detect_arch
    
    # Python 3.10+
    python3 --version 2>/dev/null | grep -qE "3\.(1[0-9]|[2-9][0-9])" \
        && ok "Python $(python3 --version 2>&1 | cut -d' ' -f2)" \
        || { fail "Python 3.10+ required"; exit 1; }
    
    # z3-solver (has aarch64 wheels)
    python3 -c "import z3" 2>/dev/null \
        && ok "z3-solver installed" \
        || { warn "z3-solver not installed"; }
    
    # pytest
    python3 -c "import pytest" 2>/dev/null \
        && ok "pytest installed" \
        || { warn "pytest not installed"; }
    
    # Kernel version for eBPF
    KERNEL_MAJOR=$(uname -r | cut -d. -f1)
    KERNEL_MINOR=$(uname -r | cut -d. -f2)
    if [ "$KERNEL_MAJOR" -ge 5 ] && [ "$KERNEL_MINOR" -ge 4 ] || [ "$KERNEL_MAJOR" -ge 6 ]; then
        ok "Kernel $(uname -r) — eBPF supported"
    else
        warn "Kernel $(uname -r) — eBPF may not work"
    fi
    
    # Docker (expected on this server)
    if command -v docker &>/dev/null; then
        ok "Docker $(docker --version 2>&1 | cut -d' ' -f3 | tr -d ',')"
    else
        warn "Docker not found"
    fi
    
    # RAM check
    TOTAL_MEM=$(free -m | awk '/^Mem:/{print $2}')
    AVAIL_MEM=$(free -m | awk '/^Mem:/{print $7}')
    if [ "$AVAIL_MEM" -lt 400 ]; then
        fail "RAM critically low: ${AVAIL_MEM}MB available of ${TOTAL_MEM}MB"
        fail "substrate-guard needs ~300-500MB. Free memory first."
        exit 1
    elif [ "$AVAIL_MEM" -lt 800 ]; then
        warn "RAM tight: ${AVAIL_MEM}MB available of ${TOTAL_MEM}MB"
    else
        ok "RAM: ${AVAIL_MEM}MB available of ${TOTAL_MEM}MB"
    fi
    
    echo ""
}

# ============================================
# Step 2a: Install on host (Option C — hybrid mock)
# ============================================

install_host() {
    log "Installing substrate-guard on host (hybrid mock mode)..."
    
    INSTALL_DIR="/opt/substrate-guard"
    
    # Install Python deps
    pip3 install z3-solver --break-system-packages -q 2>/dev/null \
        && ok "z3-solver installed" \
        || warn "z3-solver install failed — Layer 3 will be disabled"
    
    pip3 install pytest --break-system-packages -q 2>/dev/null
    
    # Copy project
    mkdir -p "$INSTALL_DIR"
    cp -r "$PROJECT_DIR/substrate_guard" "$INSTALL_DIR/"
    cp -r "$PROJECT_DIR/tests" "$INSTALL_DIR/"
    
    # Config for this server
    mkdir -p "$INSTALL_DIR/config"
    cat > "$INSTALL_DIR/config/substrate.json" << 'CONFIG'
{
    "ecosystem": "SUBSTRATE",
    "platform": "untilaoctavian.com",
    "server": {
        "hostname": "ai-research-agency",
        "arch": "aarch64",
        "ram_mb": 3700,
        "vcpus": 2
    },
    "clusters": {
        "backend": {
            "agents": 125,
            "role": "production",
            "services": ["SessionTrace", "MarketJudge", "AgentObs", "Guardian"]
        }
    },
    "policy": {
        "workspace": "/workspace/",
        "budget_per_agent_usd": 5.0,
        "rate_limit_per_minute": 100,
        "allowed_domains": [
            "api.openai.com",
            "api.anthropic.com",
            "aisophical.com",
            "untilaoctavian.com",
            "github.com",
            "pypi.org"
        ]
    },
    "observe": {
        "mode": "mock",
        "log_path": "/var/log/substrate-guard/",
        "retain_days": 7
    },
    "resources": {
        "max_memory_mb": 400,
        "max_cpu_percent": 25,
        "z3_timeout_ms": 5000
    }
}
CONFIG

    # CLI wrapper
    cat > /usr/local/bin/substrate-guard << WRAPPER
#!/bin/bash
export PYTHONPATH=$INSTALL_DIR
exec python3 -m substrate_guard.combo_cli "\$@"
WRAPPER
    chmod +x /usr/local/bin/substrate-guard
    
    mkdir -p /var/log/substrate-guard
    
    ok "Installed to $INSTALL_DIR"
    ok "CLI: substrate-guard"
}

# ============================================
# Step 2b: Install with real eBPF + OPA (Option B)
# ============================================

install_full() {
    install_host  # base install first
    
    log "Installing eBPF + OPA for full pipeline..."
    
    # BCC tools for ARM64
    apt-get update -qq
    apt-get install -y -qq bpfcc-tools python3-bpfcc linux-headers-$(uname -r) 2>/dev/null \
        && ok "bpfcc-tools installed (ARM64)" \
        || warn "bpfcc-tools failed — eBPF stays in mock mode"
    
    # OPA binary for ARM64
    OPA_VERSION="v0.71.0"
    log "Downloading OPA ${OPA_VERSION} for ${ARCH_LABEL}..."
    curl -sL "https://openpolicyagent.org/downloads/${OPA_VERSION}/opa_${OPA_ARCH}" -o /usr/local/bin/opa \
        && chmod +x /usr/local/bin/opa \
        && ok "OPA installed: $(opa version 2>&1 | head -1)" \
        || warn "OPA download failed — using built-in Python evaluator"
    
    # Update config to use real eBPF
    sed -i 's/"mode": "mock"/"mode": "auto"/' /opt/substrate-guard/config/substrate.json
    
    ok "Full install complete"
}

# ============================================
# Step 2c: Docker container (Option A)
# ============================================

build_docker() {
    log "Building Docker container..."
    
    if [ ! -f "$PROJECT_DIR/Dockerfile" ]; then
        fail "Dockerfile not found. Create it first."
        exit 1
    fi
    
    cd "$PROJECT_DIR"
    docker build -t substrate-guard:latest . \
        && ok "Docker image built: substrate-guard:latest" \
        || { fail "Docker build failed"; exit 1; }
    
    echo ""
    log "Add to docker-compose.yml:"
    echo ""
    echo "  substrate-guard:"
    echo "    image: substrate-guard:latest"
    echo "    environment:"
    echo "      - GUARD_MODE=mock"
    echo "    deploy:"
    echo "      resources:"
    echo "        limits:"
    echo "          memory: 512M"
    echo "          cpus: '0.5'"
    echo "    networks:"
    echo "      - internal"
    echo "    restart: unless-stopped"
    echo ""
}

# ============================================
# Step 3: Run tests
# ============================================

run_tests() {
    log "Running test suite..."
    cd "$PROJECT_DIR"
    python3 -m pytest tests/ -q --tb=short 2>&1
    if [ $? -eq 0 ]; then
        ok "All tests passed"
    else
        fail "Tests failed"
        exit 1
    fi
    echo ""
}

# ============================================
# Step 4: Verify integration
# ============================================

verify_integration() {
    log "Verifying integration with existing services..."
    
    # Check SessionTrace vendor package
    if [ -d "/opt/ai-research-agency/backend/vendor/sessiontrace" ]; then
        ok "SessionTrace found: /opt/ai-research-agency/backend/vendor/sessiontrace/"
        ls /opt/ai-research-agency/backend/vendor/sessiontrace/*.py 2>/dev/null | while read f; do
            echo "       $(basename $f)"
        done
    else
        warn "SessionTrace not found at expected path"
    fi
    
    # Check MarketJudge vendor package
    if [ -d "/opt/ai-research-agency/backend/vendor/marketjudge" ]; then
        ok "MarketJudge found: /opt/ai-research-agency/backend/vendor/marketjudge/"
    else
        warn "MarketJudge not found at expected path"
    fi
    
    # Check AgentObs
    if [ -d "/opt/ai-research-agency/backend/vendor/agentobs" ]; then
        ok "AgentObs found: /opt/ai-research-agency/backend/vendor/agentobs/"
    else
        warn "AgentObs not found at expected path"
    fi
    
    # Check Guardian meta-agent
    if [ -d "/opt/ai-research-agency/backend/meta_agents/guardian" ]; then
        ok "Guardian meta-agent found"
    else
        warn "Guardian meta-agent not found"
    fi
    
    echo ""
}

# ============================================
# Main
# ============================================

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║  substrate-guard — Deploy to AI Research Agency      ║"
echo "║  Server: ai-research-agency (ARM64, 2vCPU, 3.7GB)   ║"
echo "║  eBPF observes → OPA decides → Z3 proves             ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

TARGET="${1:-test}"

case "$TARGET" in
    test)
        check_deps
        run_tests
        verify_integration 2>/dev/null || true
        ok "Dry run complete — ready to deploy"
        ;;
    install)
        check_deps
        run_tests
        install_host
        echo ""
        ok "Option C install complete (hybrid mock)"
        log "Test: substrate-guard demo --scenario malicious"
        log "Bench: substrate-guard benchmark"
        ;;
    full)
        check_deps
        run_tests
        install_full
        echo ""
        ok "Full install complete (eBPF + OPA + Z3)"
        log "Test: substrate-guard demo --scenario malicious"
        ;;
    docker)
        check_deps
        build_docker
        ;;
    *)
        echo "Usage: ./deploy.sh [test|install|full|docker]"
        echo ""
        echo "  test    — check deps, run tests, verify integration (dry run)"
        echo "  install — Option C: hybrid mock, zero risk, guaranteed to work"
        echo "  full    — Option B: real eBPF + OPA ARM64 binaries"
        echo "  docker  — Option A: build Docker container"
        ;;
esac
