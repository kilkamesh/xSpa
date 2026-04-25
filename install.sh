#!/usr/bin/env bash
# =============================================================================
#  xSpa Installer
#  Single Packet Authorization via eBPF/XDP
#  https://github.com/kilkamesh/xSpa
# =============================================================================
set -euo pipefail

REPO="kilkamesh/xSpa"
BINARY_NAME="xspa"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/xspa"
DATA_DIR="/var/lib/xspa"
SERVICE_NAME="xspa"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
MODULES_FILE="/etc/modules-load.d/xspa.conf"
MIN_KERNEL_MAJOR=5
MIN_KERNEL_MINOR=8

if [[ -t 1 ]]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; BOLD=''; NC=''
fi


info()    { echo -e "${GREEN}✓${NC} $*"; }
warn()    { echo -e "${YELLOW}⚠${NC} $*"; }
error()   { echo -e "${RED}✗${NC} $*" >&2; exit 1; }
step()    { echo -e "\n${BOLD}${BLUE}▶${NC}${BOLD} $*${NC}"; }
die()     { echo -e "${RED}✗ Fatal:${NC} $*" >&2; exit 1; }

usage() {
    cat <<EOF
${BOLD}xSpa Installer${NC}

Usage:
  sudo $0 [options]

Options:
  --upgrade       Upgrade xSpa to the latest release
  --uninstall     Remove xSpa completely
  --version VER   Install specific version (e.g. v0.0.1)
  --no-service    Install binary and config only, skip systemd setup
  --help          Show this help

Examples:
  sudo $0                        # Install latest
  sudo $0 --version v0.0.1      # Install specific version
  sudo $0 --upgrade              # Upgrade to latest
  sudo $0 --uninstall            # Remove everything
EOF
    exit 0
}

MODE="install"
SPECIFIC_VERSION=""
SETUP_SERVICE=true

while [[ $# -gt 0 ]]; do
    case "$1" in
        --upgrade)    MODE="upgrade"    ;;
        --uninstall)  MODE="uninstall"  ;;
        --no-service) SETUP_SERVICE=false ;;
        --version)    shift; SPECIFIC_VERSION="$1" ;;
        --help|-h)    usage ;;
        *) die "Unknown option: $1. Use --help for usage." ;;
    esac
    shift
done

[[ $EUID -ne 0 ]] && die "Must be run as root. Try: sudo $0"

detect_os() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS_ID="${ID:-unknown}"
        OS_ID_LIKE="${ID_LIKE:-}"
        OS_NAME="${PRETTY_NAME:-unknown}"
    else
        die "Cannot detect OS: /etc/os-release not found"
    fi

    case "$OS_ID" in
        ubuntu|debian|raspbian)   PKG_FAMILY="apt" ;;
        fedora|coreos)            PKG_FAMILY="rpm-ostree-or-dnf" ;;
        rhel|centos|rocky|alma)   PKG_FAMILY="dnf" ;;
        arch|manjaro|endeavouros) PKG_FAMILY="pacman" ;;
        alpine)                   PKG_FAMILY="apk" ;;
        *)
            # Try ID_LIKE fallback
            if [[ "$OS_ID_LIKE" =~ debian ]]; then PKG_FAMILY="apt"
            elif [[ "$OS_ID_LIKE" =~ fedora|rhel ]]; then PKG_FAMILY="dnf"
            elif [[ "$OS_ID_LIKE" =~ arch ]]; then PKG_FAMILY="pacman"
            else die "Unsupported OS: $OS_NAME. Supported: Debian/Ubuntu, Fedora, RHEL, Arch, Alpine"
            fi
        ;;
    esac

    info "Detected OS: $OS_NAME (${PKG_FAMILY})"
}


check_kernel() {
    local ver major minor
    ver=$(uname -r)
    major=$(echo "$ver" | cut -d. -f1)
    minor=$(echo "$ver" | cut -d. -f2 | tr -dc '0-9')

    if [[ $major -lt $MIN_KERNEL_MAJOR ]] || \
       [[ $major -eq $MIN_KERNEL_MAJOR && $minor -lt $MIN_KERNEL_MINOR ]]; then
        die "Kernel ${MIN_KERNEL_MAJOR}.${MIN_KERNEL_MINOR}+ required for eBPF Ring Buffer. Current: $ver"
    fi

    info "Kernel: $ver (OK)"
}


check_deps() {
    local missing=()
    for cmd in curl openssl; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        warn "Missing dependencies: ${missing[*]}"
        install_deps "${missing[@]}"
    fi
}

install_deps() {
    local pkgs=("$@")
    info "Installing dependencies: ${pkgs[*]}"
    case "$PKG_FAMILY" in
        apt)         apt-get install -y -q "${pkgs[@]}" ;;
        dnf)         dnf install -y -q "${pkgs[@]}" ;;
        pacman)      pacman -Sy --noconfirm "${pkgs[@]}" ;;
        apk)         apk add --quiet "${pkgs[@]}" ;;
        rpm-ostree-or-dnf)
            if command -v rpm-ostree &>/dev/null; then
                warn "CoreOS detected: cannot install packages at runtime via rpm-ostree"
                warn "Please ensure curl and openssl are available"
            else
                dnf install -y -q "${pkgs[@]}"
            fi
        ;;
    esac
}

get_latest_version() {
    local version
    version=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep '"tag_name"' \
        | cut -d'"' -f4)
    [[ -z "$version" ]] && die "Failed to fetch latest version from GitHub"
    echo "$version"
}


get_installed_version() {
    if [[ -x "${INSTALL_DIR}/${BINARY_NAME}" ]]; then
        "${INSTALL_DIR}/${BINARY_NAME}" version 2>/dev/null | grep -oP 'v[\d.]+' | head -1 || echo "unknown"
    else
        echo "none"
    fi
}


download_binary() {
    local version="$1"
    local arch
    arch=$(uname -m)

    case "$arch" in
        x86_64)  arch_str="amd64" ;;
        aarch64) arch_str="arm64" ;;
        armv7l)  arch_str="armv7" ;;
        *) die "Unsupported architecture: $arch" ;;
    esac

    local filename="xSpa_${version#v}_linux_${arch_str}.tar.gz"
    local url="https://github.com/${REPO}/releases/download/${version}/${filename}"
    local tmpdir
    tmpdir=$(mktemp -d)
    trap "rm -rf $tmpdir" EXIT

    info "Downloading xSpa ${version} (${arch_str})..."
    curl -fsSL --progress-bar "$url" -o "${tmpdir}/${filename}" \
        || die "Download failed. Check: https://github.com/${REPO}/releases"

    info "Extracting..."
    tar -xzf "${tmpdir}/${filename}" -C "${tmpdir}/"

    # Find binary (name might vary)
    local binary
    binary=$(find "$tmpdir" -maxdepth 2 -type f \( -name "xspa" -o -name "xSpa" \) | head -1)
    [[ -z "$binary" ]] && die "Binary not found in archive"

    DOWNLOADED_BINARY="$binary"
    DOWNLOAD_TMPDIR="$tmpdir"
    trap - EXIT
}


install_binary() {
    local src="$1"
    install -m 755 "$src" "${INSTALL_DIR}/${BINARY_NAME}"
    info "Binary installed: ${INSTALL_DIR}/${BINARY_NAME}"
}


setup_kernel_module() {
    if ! lsmod | grep -q nf_conntrack; then
        modprobe nf_conntrack && info "Loaded kernel module: nf_conntrack" \
            || warn "Failed to load nf_conntrack — may already be built-in"
    else
        info "Kernel module nf_conntrack already loaded"
    fi

    echo "nf_conntrack" > "$MODULES_FILE"
    info "Module persistence configured: $MODULES_FILE"
}


generate_config() {
    mkdir -p "$CONFIG_DIR"
    chmod 750 "$CONFIG_DIR"

    if [[ -f "${CONFIG_DIR}/config.json" ]]; then
        warn "Config already exists at ${CONFIG_DIR}/config.json — skipping generation"
        return
    fi

    local sign_key cipher_key iface
    sign_key=$(openssl rand -hex 16)
    cipher_key=$(openssl rand -hex 32)

    # Auto-detect primary network interface
    iface=$(ip route show default 2>/dev/null | awk '/default/ {print $5}' | head -1)
    iface="${iface:-eth0}"

    cat > "${CONFIG_DIR}/config.json" <<EOF
{
  "server": {
    "iface": "${iface}",
    "spa_port": 55555,
    "sign_key": "${sign_key}",
    "cipher_key": "${cipher_key}"
  },
  "profiles": {
    "default": {
      "ipv4": "CHANGE_ME",
      "spa_port": 55555,
      "sign_key": "${sign_key}",
      "cipher_key": "${cipher_key}"
    }
  }
}
EOF
    chmod 600 "${CONFIG_DIR}/config.json"
    info "Config generated: ${CONFIG_DIR}/config.json"
    warn "Set your server IP in profiles.default.ipv4 before sending knocks"
}


install_service() {
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=xSpa Single Packet Authorization (eBPF/XDP)
Documentation=https://github.com/${REPO}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/${BINARY_NAME} run -c ${CONFIG_DIR}/config.json
Restart=on-failure
RestartSec=5s

# eBPF/XDP requires elevated capabilities
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_ADMIN CAP_BPF
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_ADMIN CAP_BPF
NoNewPrivileges=false

# Hardening
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=${CONFIG_DIR}

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "${SERVICE_NAME}.service"
    info "Service installed and enabled: ${SERVICE_NAME}.service"
}

do_uninstall() {
    step "Uninstalling xSpa"

    if systemctl is-active --quiet "${SERVICE_NAME}" 2>/dev/null; then
        systemctl stop "${SERVICE_NAME}"
        info "Service stopped"
    fi

    if systemctl is-enabled --quiet "${SERVICE_NAME}" 2>/dev/null; then
        systemctl disable "${SERVICE_NAME}"
        info "Service disabled"
    fi

    local removed=()
    for f in "$SERVICE_FILE" "${INSTALL_DIR}/${BINARY_NAME}" "$MODULES_FILE"; do
        if [[ -f "$f" ]]; then
            rm -f "$f"
            removed+=("$f")
        fi
    done

    systemctl daemon-reload

    info "Removed: ${removed[*]:-nothing}"
    warn "Config preserved at ${CONFIG_DIR} — remove manually if needed:"
    warn "  sudo rm -rf ${CONFIG_DIR}"
}


do_install() {
    local version="${SPECIFIC_VERSION}"
    [[ -z "$version" ]] && version=$(get_latest_version)

    step "Installing xSpa ${version}"

    local installed
    installed=$(get_installed_version)
    if [[ "$installed" != "none" && "$MODE" != "upgrade" ]]; then
        warn "xSpa ${installed} is already installed"
        warn "Use --upgrade to update or --uninstall to remove"
        exit 0
    fi

    detect_os
    check_kernel
    check_deps

    step "Downloading"
    download_binary "$version"
    install_binary "$DOWNLOADED_BINARY"
    rm -rf "$DOWNLOAD_TMPDIR"

    step "Configuring"
    setup_kernel_module
    generate_config

    if $SETUP_SERVICE; then
        step "Setting up service"
        install_service
    fi

    step "Done"
    echo ""
    echo -e "${BOLD}xSpa ${version} installed successfully${NC}"
    echo ""
    echo "  Next steps:"
    echo "  1. Edit config:       ${CONFIG_DIR}/config.json"
    echo -e "     ${YELLOW}Set profiles.default.ipv4 to your server's public IP${NC}"
    echo "  2. Start server:      systemctl start xspa"
    echo "  3. Check status:      systemctl status xspa"
    echo "  4. Send knock:        xspa knock default -i <your_ip> -c ${CONFIG_DIR}/config.json"
    echo ""
    warn "Ensure UDP port 55555 is reachable (used for SPA packets)"
}

do_upgrade() {
    local latest installed
    latest=$(get_latest_version)
    installed=$(get_installed_version)

    step "Upgrading xSpa"
    info "Installed: ${installed}"
    info "Latest:    ${latest}"

    if [[ "$installed" == "$latest" ]]; then
        info "Already up to date"
        exit 0
    fi

    local was_active=false
    systemctl is-active --quiet "${SERVICE_NAME}" 2>/dev/null && was_active=true

    $was_active && systemctl stop "${SERVICE_NAME}" && info "Service stopped"

    local binary
    download_binary "$latest"
    install_binary "$DOWNLOADED_BINARY"
    rm -rf "$DOWNLOAD_TMPDIR"

    $was_active && systemctl start "${SERVICE_NAME}" && info "Service restarted"

    info "Upgraded: ${installed} → ${latest}"
}

case "$MODE" in
    install)   do_install ;;
    upgrade)   do_upgrade ;;
    uninstall) do_uninstall ;;
esac
