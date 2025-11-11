#!/bin/bash

# Ubuntu Server 24.04 Security Hardening Script
# Version: 2.0
# Run as root or with sudo

set -euo pipefail

# ============================================================================
# CONFIGURATION - CUSTOMIZE THESE VALUES BEFORE RUNNING
# ============================================================================
NEW_USER="YOUR_USERNAME"
SSH_PORT="22"  # Use 22 or choose 1024-65535 for non-standard
SSH_PUBLIC_KEY="YOUR_SSH_PUBLIC_KEY_HERE"
USER_PASSWORD="${USER_PASSWORD:-}"  # Optional: set via environment variable

# ============================================================================
# CONSTANTS
# ============================================================================
readonly SCRIPT_VERSION="2.0"
readonly PROGRESS_FILE="/var/log/hardening-progress.log"
readonly STEP_FILE="/var/tmp/hardening-step"
readonly LOCK_FILE="/var/lock/hardening-script.lock"
readonly TOTAL_STEPS=15

# Color codes
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m'

# Global variables
LAST_STEP=0
START_FROM_STEP=0
DOCKER_INSTALLED=false

# Step names for error reporting
declare -a STEP_NAMES=(
    ""
    "System Updates"
    "Create New User"
    "SSH Hardening"
    "Fail2ban"
    "UFW Firewall"
    "Docker + ufw-docker"
    "Auditd"
    "File Permissions"
    "Lynis"
    "Rkhunter"
    "Secure Shared Memory"
    "Persistent Logging"
    "AIDE"
    "Additional Security"
    "Cleanup"
)

# ============================================================================
# INITIALIZATION
# ============================================================================

# Initialize logging
init_logging() {
    if ! touch "$PROGRESS_FILE" 2>/dev/null; then
        echo "ERROR: Cannot write to $PROGRESS_FILE, using /tmp"
        PROGRESS_FILE="/tmp/hardening-progress.log"
        touch "$PROGRESS_FILE"
    fi
    chmod 644 "$PROGRESS_FILE"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
       echo -e "${RED}[ERROR]${NC} This script must be run as root or with sudo"
       exit 1
    fi
}

# Initialize
init_logging
check_root

# ============================================================================
# LOGGING FUNCTIONS
# ============================================================================

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] INFO: $1" >> "$PROGRESS_FILE"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] WARN: $1" >> "$PROGRESS_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1" >> "$PROGRESS_FILE"
}

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

# Save progress
save_progress() {
    echo "LAST_COMPLETED_STEP=$1" > "$STEP_FILE"
    LAST_STEP=$1
    log_info "Completed step $1: ${STEP_NAMES[$1]}"
}

# Load last completed step
load_progress() {
    if [ -f "$STEP_FILE" ]; then
        source "$STEP_FILE"
        return $LAST_COMPLETED_STEP
    fi
    return 0
}

# Error handler
error_handler() {
    local line_no=$1
    local step_name="${STEP_NAMES[$LAST_STEP]:-Unknown}"

    log_error "Script failed at line $line_no during Step $LAST_STEP: $step_name"
    log_error "Check the log file: $PROGRESS_FILE"
    log_error ""
    log_error "To resume from step $((LAST_STEP + 1)), run:"
    log_error "  sudo $0 --continue $((LAST_STEP + 1))"
    log_error ""
    log_error "To start over from the beginning, run:"
    log_error "  sudo $0 --restart"

    # Release lock
    flock -u 200 2>/dev/null || true

    exit 1
}

# Set error trap
trap 'error_handler ${LINENO}' ERR

# Validate step number
validate_step() {
    local step=$1
    if ! [[ "$step" =~ ^[0-9]+$ ]] || [ "$step" -lt 1 ] || [ "$step" -gt $TOTAL_STEPS ]; then
        log_error "Invalid step number. Must be between 1 and $TOTAL_STEPS."
        exit 1
    fi
}

# Check OS compatibility
check_os() {
    if [ ! -f /etc/os-release ]; then
        log_error "Cannot detect OS. /etc/os-release not found."
        exit 1
    fi

    source /etc/os-release

    if [[ ! "$ID" =~ ^(ubuntu|debian)$ ]]; then
        log_error "This script is for Ubuntu/Debian only. Detected: $ID"
        exit 1
    fi

    if [[ "$ID" == "ubuntu" ]] && [[ ! "$VERSION_ID" =~ ^24\. ]]; then
        log_warn "Script designed for Ubuntu 24.04. You have: $VERSION_ID"
        if [ -t 0 ]; then
            read -p "Continue anyway? [y/N] " -n 1 -r
            echo
            [[ ! $REPLY =~ ^[Yy]$ ]] && exit 1
        else
            log_warn "Non-interactive mode, proceeding with caution..."
        fi
    fi

    log_info "Detected: $PRETTY_NAME"
}

# Check network connectivity
check_network() {
    log_info "Checking network connectivity..."
    if ! ping -c 1 -W 2 8.8.8.8 &>/dev/null; then
        log_error "No network connectivity detected"
        exit 1
    fi
}

# Backup existing file
backup_file() {
    local file=$1
    if [ -f "$file" ]; then
        local backup="${file}.backup-$(date +%Y%m%d-%H%M%S)"
        cp "$file" "$backup"
        log_info "Backed up $file to $backup"
    fi
}

# Display help
show_help() {
    cat << EOF
Ubuntu Server 24.04 Security Hardening Script v${SCRIPT_VERSION}

Usage: $0 [OPTIONS]

Options:
  --continue N    Continue from step N (1-${TOTAL_STEPS})
  --restart       Start from beginning, ignore previous progress
  --help, -h      Show this help message

Steps:
  1  - System updates
  2  - Create new user
  3  - SSH hardening
  4  - Fail2ban
  5  - UFW firewall
  6  - Docker + ufw-docker (optional)
  7  - Auditd
  8  - File permissions
  9  - Lynis
  10 - Rkhunter
  11 - Secure shared memory
  12 - Persistent logging
  13 - AIDE
  14 - Additional hardening
  15 - Cleanup

Environment Variables:
  USER_PASSWORD   - Optional: Password for new user (for automation)

Examples:
  sudo $0                    # Run normally
  sudo $0 --continue 5       # Continue from step 5
  sudo $0 --restart          # Start over
  sudo USER_PASSWORD='secret' $0  # Non-interactive

EOF
    exit 0
}

# ============================================================================
# ARGUMENT PARSING
# ============================================================================

if [[ "${1:-}" == "--continue" ]]; then
    START_FROM_STEP=${2:-0}
    validate_step "$START_FROM_STEP"
    log_info "Continuing from step $START_FROM_STEP"
elif [[ "${1:-}" == "--restart" ]]; then
    rm -f "$STEP_FILE"
    log_info "Starting from beginning (restart mode)"
elif [[ "${1:-}" == "--help" ]] || [[ "${1:-}" == "-h" ]]; then
    show_help
else
    # Check if there's incomplete progress
    if load_progress; then
        LAST_COMPLETED=$?
        if [ $LAST_COMPLETED -gt 0 ]; then
            log_warn "Previous incomplete run detected."
            log_warn "Last completed step: $LAST_COMPLETED (${STEP_NAMES[$LAST_COMPLETED]})"

            if [ -t 0 ]; then
                echo ""
                echo "Options:"
                echo "  1) Continue from step $((LAST_COMPLETED + 1))"
                echo "  2) Start over from beginning"
                echo "  3) Exit"
                echo ""
                read -p "Choose [1-3]: " -n 1 -r choice
                echo ""
                case $choice in
                    1)
                        START_FROM_STEP=$((LAST_COMPLETED + 1))
                        log_info "Continuing from step $START_FROM_STEP"
                        ;;
                    2)
                        rm -f "$STEP_FILE"
                        log_info "Starting from beginning"
                        ;;
                    *)
                        exit 0
                        ;;
                esac
            else
                log_info "Non-interactive mode: continuing from step $((LAST_COMPLETED + 1))"
                START_FROM_STEP=$((LAST_COMPLETED + 1))
            fi
        fi
    fi
fi

# ============================================================================
# PRE-FLIGHT CHECKS
# ============================================================================

# Acquire lock to prevent parallel execution
exec 200>"$LOCK_FILE"
if ! flock -n 200; then
    log_error "Another instance is already running"
    exit 1
fi

# Validate configuration
if [[ "$NEW_USER" == "YOUR_USERNAME" ]] || [[ "$SSH_PUBLIC_KEY" == "YOUR_SSH_PUBLIC_KEY_HERE" ]]; then
    log_error "You must customize NEW_USER and SSH_PUBLIC_KEY before running this script!"
    log_error "Edit this script and replace the placeholder values in the CONFIGURATION section."
    exit 1
fi

# Run pre-flight checks
check_os
check_network

log_info "Starting Ubuntu Server security hardening v${SCRIPT_VERSION}..."
log_info "Configuration: User=$NEW_USER, SSH Port=$SSH_PORT"

# Create common directories
mkdir -p /etc/ssh/sshd_config.d \
         /run/sshd \
         /etc/systemd/journald.conf.d \
         /var/log/journal

# ============================================================================
# STEP 1: SYSTEM UPDATES
# ============================================================================
if [ $START_FROM_STEP -le 1 ]; then
    LAST_STEP=1
    log_info "Step 1/$TOTAL_STEPS: Updating system packages..."

    export DEBIAN_FRONTEND=noninteractive
    apt update
    apt full-upgrade -y
    apt install -y unattended-upgrades apt-listchanges
    dpkg-reconfigure --priority=low unattended-upgrades

    # Configure unattended-upgrades
    cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}";
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-Time "03:00";
EOF

    apt autoremove --purge -y
    save_progress 1
fi

# ============================================================================
# STEP 2: CREATE NEW USER
# ============================================================================
if [ $START_FROM_STEP -le 2 ]; then
    LAST_STEP=2
    log_info "Step 2/$TOTAL_STEPS: Creating user '$NEW_USER'..."

    if id "$NEW_USER" &>/dev/null; then
        log_warn "User '$NEW_USER' already exists. Skipping creation."
    else
        adduser --disabled-password --gecos "" "$NEW_USER"
        usermod -aG sudo "$NEW_USER"
        log_info "User '$NEW_USER' created and added to sudo group."

        # Set password
        if [ -n "$USER_PASSWORD" ]; then
            echo "$NEW_USER:$USER_PASSWORD" | chpasswd
            log_info "Password set from environment variable."
        elif [ -t 0 ]; then
            log_info "Please set a password for '$NEW_USER' (required for sudo):"
            passwd "$NEW_USER"
        else
            log_warn "Running non-interactively. Set password later with: passwd $NEW_USER"
        fi
    fi

    save_progress 2
fi

# ============================================================================
# STEP 3: SSH HARDENING
# ============================================================================
if [ $START_FROM_STEP -le 3 ]; then
    LAST_STEP=3
    log_info "Step 3/$TOTAL_STEPS: Hardening SSH configuration..."

    # Backup existing config if it exists
    backup_file /etc/ssh/sshd_config.d/99-custom.conf

    # Create SSH privilege separation directory
    mkdir -p /run/sshd
    chmod 0755 /run/sshd

    # Create custom SSH configuration in temp file first
    cat > /tmp/sshd-custom.conf << EOF
# Custom SSH Security Configuration - Generated by hardening script v${SCRIPT_VERSION}
Port $SSH_PORT
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
AuthenticationMethods publickey
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding no
PrintMotd no
AcceptEnv LANG LC_*
AllowUsers $NEW_USER
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 60
Protocol 2
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256
EOF

    # Set up SSH keys for new user
    USER_HOME="/home/$NEW_USER"
    SSH_DIR="$USER_HOME/.ssh"
    AUTH_KEYS="$SSH_DIR/authorized_keys"

    mkdir -p "$SSH_DIR"
    touch "$AUTH_KEYS"

    # Add SSH key (avoid duplicates)
    if ! grep -qF "$SSH_PUBLIC_KEY" "$AUTH_KEYS" 2>/dev/null; then
        echo "$SSH_PUBLIC_KEY" >> "$AUTH_KEYS"
    fi

    # Set correct permissions
    chown -R "$NEW_USER:$NEW_USER" "$SSH_DIR"
    chmod 700 "$SSH_DIR"
    chmod 600 "$AUTH_KEYS"

    # Validate SSH configuration before applying
    if sshd -t -f /tmp/sshd-custom.conf 2>/dev/null; then
        mv /tmp/sshd-custom.conf /etc/ssh/sshd_config.d/99-custom.conf
        chmod 600 /etc/ssh/sshd_config.d/99-custom.conf

        # Validate full config
        if sshd -t; then
            systemctl restart ssh
            save_progress 3
            log_info "SSH configuration updated. New port: $SSH_PORT"
            log_info "Enhanced cipher restrictions applied."
            log_warn "IMPORTANT: Test SSH connection on new port before logging out!"
            log_warn "Test command: ssh -p $SSH_PORT $NEW_USER@<server-ip>"
        else
            log_error "Full SSH configuration validation failed."
            exit 1
        fi
    else
        rm -f /tmp/sshd-custom.conf
        log_error "SSH configuration validation failed. Not applying changes."
        exit 1
    fi
fi

# ============================================================================
# STEP 4: FAIL2BAN
# ============================================================================
if [ $START_FROM_STEP -le 4 ]; then
    LAST_STEP=4
    log_info "Step 4/$TOTAL_STEPS: Installing and configuring fail2ban..."

    apt install -y fail2ban

    backup_file /etc/fail2ban/jail.local

    cat > /etc/fail2ban/jail.local << EOF
# Fail2ban configuration - Generated by hardening script v${SCRIPT_VERSION}
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5
destemail = root@localhost
sendername = Fail2Ban
action = %(action_mwl)s

[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
bantime = 1h
EOF

    systemctl enable fail2ban
    systemctl restart fail2ban

    # Verify service started
    if systemctl is-active --quiet fail2ban; then
        save_progress 4
        log_info "Fail2ban configured and running."
    else
        log_error "Fail2ban failed to start. Check logs: journalctl -u fail2ban"
        exit 1
    fi
fi

# ============================================================================
# STEP 5: UFW FIREWALL
# ============================================================================
if [ $START_FROM_STEP -le 5 ]; then
    LAST_STEP=5
    log_info "Step 5/$TOTAL_STEPS: Configuring UFW firewall..."

    apt install -y ufw

    # Check if UFW is already active
    if ufw status 2>/dev/null | grep -q "Status: active"; then
        log_warn "UFW is already active. Updating rules without full reset."
        log_warn "To completely reset UFW, run: sudo ufw --force reset"

        # Ensure our SSH rule exists
        ufw allow "$SSH_PORT"/tcp 2>/dev/null || true
        ufw limit "$SSH_PORT"/tcp comment 'SSH rate limited' 2>/dev/null || true
    else
        log_info "Configuring UFW for first time..."

        # Reset UFW to default state
        ufw --force reset

        # Set default policies
        ufw default deny incoming
        ufw default allow outgoing

        # Allow SSH on custom port with rate limiting
        ufw allow "$SSH_PORT"/tcp
        ufw limit "$SSH_PORT"/tcp comment 'SSH rate limited'

        # Enable UFW
        echo "y" | ufw enable
    fi

    ufw status verbose
    save_progress 5
    log_info "UFW firewall configured."
fi

# ============================================================================
# STEP 6: DOCKER + UFW-DOCKER (OPTIONAL)
# ============================================================================
if [ $START_FROM_STEP -le 6 ]; then
    LAST_STEP=6
    log_info "Step 6/$TOTAL_STEPS: Docker + ufw-docker (optional)..."

    INSTALL_DOCKER=false

    if [ -t 0 ]; then
        read -p "Do you want to install Docker and ufw-docker? [y/N] " -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            INSTALL_DOCKER=true
        fi
    else
        log_info "Non-interactive mode: skipping Docker installation."
    fi

    if [ "$INSTALL_DOCKER" = true ]; then
        log_info "Installing Docker Engine using official convenience script..."

        # Install Docker using official convenience script
        curl -fsSL https://get.docker.com | sh

        log_info "Docker Engine installed successfully."

        # Add user to docker group
        usermod -aG docker "$NEW_USER"
        log_info "User '$NEW_USER' added to docker group."

        # Install ufw-docker
        log_info "Installing ufw-docker..."
        curl -fsSL https://github.com/chaifeng/ufw-docker/raw/master/ufw-docker -o /usr/local/bin/ufw-docker
        chmod +x /usr/local/bin/ufw-docker

        # Run ufw-docker install
        /usr/local/bin/ufw-docker install

        # Restart UFW
        systemctl restart ufw

        log_info "ufw-docker installed and configured."
        log_info ""
        log_info "Usage example:"
        log_info "  # Allow external access to a container's port:"
        log_info "  sudo ufw-docker allow <container-name> 80"
        log_info ""
        log_info "  # Delete a rule:"
        log_info "  sudo ufw-docker delete allow <container-name> 80"
        log_info ""

        DOCKER_INSTALLED=true
    else
        log_info "Skipping Docker installation."
    fi

    save_progress 6
fi

# ============================================================================
# STEP 7: AUDITD
# ============================================================================
if [ $START_FROM_STEP -le 7 ]; then
    LAST_STEP=7
    log_info "Step 7/$TOTAL_STEPS: Installing and configuring auditd..."

    apt install -y auditd audispd-plugins

    backup_file /etc/audit/rules.d/custom.rules

    # Add custom audit rules
    cat > /etc/audit/rules.d/custom.rules << 'EOF'
# Audit rules - Generated by hardening script
# Monitor authentication events
-w /var/log/auth.log -p wa -k auth_log
-w /etc/passwd -p wa -k passwd_changes
-w /etc/group -p wa -k group_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/sudoers -p wa -k sudoers_changes

# Monitor SSH configuration
-w /etc/ssh/sshd_config -p wa -k sshd_config_changes

# Monitor system calls
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time_change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time_change

# Monitor network changes
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k network_modifications
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k network_modifications
EOF

    # Restart auditd
    systemctl restart auditd

    if systemctl is-active --quiet auditd; then
        save_progress 7
        log_info "Auditd configured with custom rules."
    else
        log_warn "Auditd may not have started properly. Check: systemctl status auditd"
        save_progress 7
    fi
fi

# ============================================================================
# STEP 8: FILE PERMISSIONS
# ============================================================================
if [ $START_FROM_STEP -le 8 ]; then
    LAST_STEP=8
    log_info "Step 8/$TOTAL_STEPS: Setting secure file permissions..."

    # Critical system files
    chmod 700 /root
    chmod 644 /etc/passwd /etc/group
    chmod 600 /etc/shadow /etc/gshadow

    # Secure SSH directory
    if [ -d /etc/ssh ]; then
        chmod 755 /etc/ssh
        find /etc/ssh -name "ssh*_key" -type f -exec chmod 600 {} \; 2>/dev/null || true
        find /etc/ssh -name "*.pub" -type f -exec chmod 644 {} \; 2>/dev/null || true
        chmod 644 /etc/ssh/sshd_config 2>/dev/null || true
        find /etc/ssh/sshd_config.d -type f -exec chmod 600 {} \; 2>/dev/null || true
    fi

    save_progress 8
    log_info "File permissions secured."
fi

# ============================================================================
# STEP 9: LYNIS
# ============================================================================
if [ $START_FROM_STEP -le 9 ]; then
    LAST_STEP=9
    log_info "Step 9/$TOTAL_STEPS: Installing Lynis security audit tool..."

    apt install -y lynis

    save_progress 9
    log_info "Lynis installed. Run 'sudo lynis audit system' to perform security audit."
fi

# ============================================================================
# STEP 10: RKHUNTER
# ============================================================================
if [ $START_FROM_STEP -le 10 ]; then
    LAST_STEP=10
    log_info "Step 10/$TOTAL_STEPS: Installing and configuring rkhunter..."

    apt install -y rkhunter

    backup_file /etc/rkhunter.conf

    # Fix rkhunter configuration for Ubuntu 24.04
    sed -i 's|^WEB_CMD=.*|WEB_CMD=""|' /etc/rkhunter.conf
    sed -i 's|^MIRRORS_MODE=.*|MIRRORS_MODE=0|' /etc/rkhunter.conf
    sed -i 's|^ALLOWHIDDENDIR=.*|ALLOWHIDDENDIR=/dev/.lxc|' /etc/rkhunter.conf
    sed -i 's|^#ALLOWHIDDENDIR=/dev/.udev|ALLOWHIDDENDIR=/dev/.udev|' /etc/rkhunter.conf

    # Update rkhunter database
    rkhunter --update 2>&1 | grep -v "Warning:" || true
    rkhunter --propupd 2>&1 | grep -v "Warning:" || true

    save_progress 10
    log_info "Rkhunter installed and configured."
fi

# ============================================================================
# STEP 11: SECURE SHARED MEMORY
# ============================================================================
if [ $START_FROM_STEP -le 11 ]; then
    LAST_STEP=11
    log_info "Step 11/$TOTAL_STEPS: Securing shared memory..."

    if ! grep -q "tmpfs.*\/run\/shm" /etc/fstab; then
        backup_file /etc/fstab
        echo "tmpfs /run/shm tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab
        log_info "Shared memory secured in /etc/fstab"
    else
        log_warn "Shared memory entry already exists in /etc/fstab"
    fi

    save_progress 11
fi

# ============================================================================
# STEP 12: PERSISTENT LOGGING
# ============================================================================
if [ $START_FROM_STEP -le 12 ]; then
    LAST_STEP=12
    log_info "Step 12/$TOTAL_STEPS: Enabling persistent journald logging..."

    mkdir -p /var/log/journal
    systemd-tmpfiles --create --prefix /var/log/journal

    backup_file /etc/systemd/journald.conf.d/persistent.conf

    cat > /etc/systemd/journald.conf.d/persistent.conf << 'EOF'
# Journald configuration - Generated by hardening script
[Journal]
Storage=persistent
Compress=yes
SystemMaxUse=500M
SystemMaxFileSize=100M
EOF

    systemctl restart systemd-journald
    save_progress 12
    log_info "Persistent logging enabled."
fi

# ============================================================================
# STEP 13: AIDE
# ============================================================================
if [ $START_FROM_STEP -le 13 ]; then
    LAST_STEP=13
    log_info "Step 13/$TOTAL_STEPS: Installing AIDE (this may take several minutes)..."

    apt install -y aide aide-common

    # Only initialize if database doesn't exist
    if [ ! -f /var/lib/aide/aide.db ] && [ ! -f /var/lib/aide/aide.db.gz ]; then
        log_info "Initializing AIDE database (this may take 10-15 minutes)..."
        aideinit

        # Move database to correct location
        if [ -f /var/lib/aide/aide.db.new ]; then
            mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
        fi
        log_info "AIDE database initialized."
    else
        log_info "AIDE database already exists. Skipping initialization."
    fi

    # Set up weekly AIDE checks
    cat > /etc/cron.weekly/aide-check << 'EOF'
#!/bin/bash
/usr/bin/aide --check | mail -s "AIDE Report for $(hostname)" root
EOF
    chmod +x /etc/cron.weekly/aide-check

    save_progress 13
    log_info "AIDE configured."
fi

# ============================================================================
# STEP 14: ADDITIONAL SECURITY
# ============================================================================
if [ $START_FROM_STEP -le 14 ]; then
    LAST_STEP=14
    log_info "Step 14/$TOTAL_STEPS: Applying additional security hardening..."

    # Disable core dumps
    cat > /etc/security/limits.d/disable-coredumps.conf << 'EOF'
* hard core 0
EOF

    backup_file /etc/sysctl.d/99-security.conf

    # Kernel hardening
    cat > /etc/sysctl.d/99-security.conf << 'EOF'
# Kernel hardening - Generated by hardening script
# IP Forwarding
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Disable source packet routing
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Disable ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Enable IP spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP ping requests (set to 1 to disable ping)
net.ipv4.icmp_echo_ignore_all = 0

# Ignore broadcast pings
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Enable TCP SYN cookies
net.ipv4.tcp_syncookies = 1

# Log martian packets
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
EOF

    sysctl -p /etc/sysctl.d/99-security.conf >/dev/null

    save_progress 14
fi

# ============================================================================
# STEP 15: CLEANUP
# ============================================================================
if [ $START_FROM_STEP -le 15 ]; then
    LAST_STEP=15
    log_info "Step 15/$TOTAL_STEPS: Cleaning up temporary files..."

    # Remove temporary files
    rm -f /tmp/sshd-custom.conf 2>/dev/null || true
    rm -f /var/tmp/hardening-apt-updated 2>/dev/null || true

    # Clean up old backup files older than 30 days
    find /etc -name "*.backup-*" -type f -mtime +30 -delete 2>/dev/null || true

    # Clean apt cache
    apt clean
    apt autoclean

    # Remove lock file
    rm -f "$LOCK_FILE" 2>/dev/null || true

    log_info "Cleanup completed."
    save_progress 15
fi

# ============================================================================
# COMPLETION
# ============================================================================

# Clean up
rm -f "$STEP_FILE"
flock -u 200

log_info "Security hardening completed successfully!"

# Display summary
cat << EOF

============================================================================
                  SECURITY HARDENING SUMMARY
============================================================================

✓ System updated and automatic security updates enabled
✓ New user '$NEW_USER' created with sudo privileges
✓ SSH hardened (port: $SSH_PORT, key-only auth, root login disabled)
✓ SSH cipher restrictions enhanced (ChaCha20-Poly1305, AES256-GCM, etc.)
✓ Fail2ban installed and configured
✓ UFW firewall enabled
EOF

if [ "$DOCKER_INSTALLED" = true ]; then
    echo "✓ Docker Engine and ufw-docker installed"
fi

cat << EOF
✓ Auditd installed with custom rules
✓ File permissions secured
✓ Lynis security audit tool installed
✓ Rkhunter rootkit scanner installed
✓ Shared memory secured
✓ Persistent logging enabled
✓ AIDE intrusion detection initialized
✓ Additional kernel hardening applied

============================================================================
                      IMPORTANT NEXT STEPS
============================================================================

1. TEST SSH CONNECTION before logging out:
   ssh -p $SSH_PORT $NEW_USER@<server-ip>

2. Keep your current session open until SSH is confirmed working

3. Run security audits:
   sudo lynis audit system
   sudo rkhunter --check

4. Review logs:
   sudo journalctl -xe
   sudo tail -f /var/log/auth.log
   sudo cat $PROGRESS_FILE
EOF

if [ "$DOCKER_INSTALLED" = true ]; then
    cat << EOF

5. Docker and ufw-docker usage:
   # User '$NEW_USER' needs to re-login for docker group changes

   # Allow external access to a container's port:
   sudo ufw-docker allow <container-name> 80

   # Delete a rule:
   sudo ufw-docker delete allow <container-name> 80

   # List Docker container IPs:
   docker inspect --format='{{.Name}}: {{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \$(docker ps -q)

6. Reboot to apply all changes:
EOF
else
    cat << EOF

5. Reboot to apply all changes:
EOF
fi

cat << EOF
   sudo reboot

============================================================================

Log file: $PROGRESS_FILE

EOF
