#!/bin/bash

# Ubuntu Server 24.04 Security Hardening Script
# Run as root or with sudo

set -euo pipefail  # Exit on error, undefined variables, and pipe failures

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging function
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   log_error "This script must be run as root or with sudo"
   exit 1
fi

# ============================================================================
# CONFIGURATION - CUSTOMIZE THESE VALUES BEFORE RUNNING
# ============================================================================
NEW_USER="YOUR_USERNAME"           # Replace with your desired username
SSH_PORT="22"                    # Replace with your desired SSH port (1024-65535)
SSH_PUBLIC_KEY="YOUR_SSH_PUBLIC_KEY_HERE"  # Replace with your actual SSH public key

# Validation
if [[ "$NEW_USER" == "YOUR_USERNAME" ]] || [[ "$SSH_PUBLIC_KEY" == "YOUR_SSH_PUBLIC_KEY_HERE" ]]; then
    log_error "You must customize NEW_USER and SSH_PUBLIC_KEY before running this script!"
    log_error "Edit this script and replace the placeholder values in the CONFIGURATION section."
    exit 1
fi

log_info "Starting Ubuntu Server 24.04 security hardening..."

# ============================================================================
# 1. SYSTEM UPDATES
# ============================================================================
log_info "Step 1: Updating system packages..."

apt update
apt full-upgrade -y
apt install -y unattended-upgrades apt-listchanges
dpkg-reconfigure --priority=low unattended-upgrades

# Configure unattended-upgrades for automatic security updates
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
log_info "System updates completed."

# ============================================================================
# 2. CREATE NEW USER
# ============================================================================
log_info "Step 2: Creating user '$NEW_USER'..."

if id "$NEW_USER" &>/dev/null; then
    log_warn "User '$NEW_USER' already exists. Skipping creation."
else
    adduser --disabled-password --gecos "" "$NEW_USER"
    usermod -aG sudo "$NEW_USER"
    log_info "User '$NEW_USER' created and added to sudo group."
    
    # Set password for sudo usage
    log_info "Please set a password for '$NEW_USER' (required for sudo):"
    passwd "$NEW_USER"
fi

# ============================================================================
# 3. SSH HARDENING
# ============================================================================
log_info "Step 3: Hardening SSH configuration..."

# Create SSH config directory if it doesn't exist
mkdir -p /etc/ssh/sshd_config.d

# Create custom SSH configuration
cat > /etc/ssh/sshd_config.d/99-custom.conf << EOF
# Custom SSH Security Configuration
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
EOF

# Set up SSH keys for new user
USER_HOME="/home/$NEW_USER"
SSH_DIR="$USER_HOME/.ssh"
AUTH_KEYS="$SSH_DIR/authorized_keys"

mkdir -p "$SSH_DIR"
touch "$AUTH_KEYS"

# Add SSH key (avoid duplicates)
if ! grep -q "$SSH_PUBLIC_KEY" "$AUTH_KEYS" 2>/dev/null; then
    echo "$SSH_PUBLIC_KEY" >> "$AUTH_KEYS"
fi

# Set correct permissions
chown -R "$NEW_USER:$NEW_USER" "$SSH_DIR"
chmod 700 "$SSH_DIR"
chmod 600 "$AUTH_KEYS"

# Validate SSH configuration before restarting
if sshd -t; then
    systemctl restart ssh
    log_info "SSH configuration updated. New port: $SSH_PORT"
    log_warn "IMPORTANT: Test SSH connection on new port before logging out!"
    log_warn "Test command: ssh -p $SSH_PORT $NEW_USER@<server-ip>"
else
    log_error "SSH configuration validation failed. Not restarting SSH."
    exit 1
fi

# ============================================================================
# 4. FAIL2BAN
# ============================================================================
log_info "Step 4: Installing and configuring fail2ban..."

apt install -y fail2ban

# Create fail2ban local configuration
cat > /etc/fail2ban/jail.local << EOF
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
log_info "Fail2ban configured and started."

# ============================================================================
# 5. UFW FIREWALL
# ============================================================================
log_info "Step 5: Configuring UFW firewall..."

apt install -y ufw

# Check if this is first run or if we should preserve existing rules
if ufw status | grep -q "Status: active"; then
    log_warn "UFW is already active. Will update rules without full reset."
    log_warn "To completely reset UFW, run: sudo ufw --force reset"
    
    # Just ensure our SSH rule exists
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
log_info "UFW firewall configured."

# ============================================================================
# 6. AUDITD
# ============================================================================
log_info "Step 6: Installing and configuring auditd..."

apt install -y auditd audispd-plugins

# Add custom audit rules
mkdir -p /etc/systemd/journald.conf.d
cat > /etc/audit/rules.d/custom.rules << 'EOF'
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

# Restart auditd to apply rules
service auditd restart
log_info "Auditd configured with custom rules."

# ============================================================================
# 7. FILE PERMISSIONS
# ============================================================================
log_info "Step 7: Setting secure file permissions..."

chmod 700 /root
chmod 644 /etc/passwd
chmod 600 /etc/shadow
chmod 644 /etc/group
chmod 600 /etc/gshadow

# Secure SSH directory
if [ -d /etc/ssh ]; then
    chmod 755 /etc/ssh
    chmod 600 /etc/ssh/ssh*_key 2>/dev/null || true
    chmod 644 /etc/ssh/*.pub 2>/dev/null || true
    chmod 644 /etc/ssh/sshd_config
    chmod 600 /etc/ssh/sshd_config.d/* 2>/dev/null || true
fi

log_info "File permissions secured."

# ============================================================================
# 8. LYNIS SECURITY AUDIT
# ============================================================================
log_info "Step 8: Installing Lynis security audit tool..."

apt install -y lynis

log_info "Lynis installed. Run 'sudo lynis audit system' to perform security audit."

# ============================================================================
# 9. RKHUNTER
# ============================================================================
log_info "Step 9: Installing and configuring rkhunter..."

apt install -y rkhunter

# Fix rkhunter configuration for Ubuntu 24.04
# Disable WEB_CMD to avoid pathname warning
sed -i 's|^WEB_CMD=.*|WEB_CMD=""|' /etc/rkhunter.conf

# Set MIRRORS_MODE to 0 (use package manager mirrors)
sed -i 's|^MIRRORS_MODE=.*|MIRRORS_MODE=0|' /etc/rkhunter.conf

# Allow hidden directories in /dev (common in containers/modern systems)
sed -i 's|^ALLOWHIDDENDIR=.*|ALLOWHIDDENDIR=/dev/.lxc|' /etc/rkhunter.conf
sed -i 's|^#ALLOWHIDDENDIR=/dev/.udev|ALLOWHIDDENDIR=/dev/.udev|' /etc/rkhunter.conf

# Update rkhunter database
rkhunter --update
rkhunter --propupd

log_info "Rkhunter installed and configured. Run 'sudo rkhunter --check' to scan for rootkits."

# ============================================================================
# 10. SECURE SHARED MEMORY
# ============================================================================
log_info "Step 10: Securing shared memory..."

# Check if entry already exists
if ! grep -q "tmpfs.*\/run\/shm" /etc/fstab; then
    echo "tmpfs /run/shm tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab
    log_info "Shared memory secured in /etc/fstab"
else
    log_warn "Shared memory entry already exists in /etc/fstab"
fi

# ============================================================================
# 11. PERSISTENT LOGGING
# ============================================================================
log_info "Step 11: Enabling persistent journald logging..."

mkdir -p /var/log/journal
systemd-tmpfiles --create --prefix /var/log/journal

# Configure journald
cat > /etc/systemd/journald.conf.d/persistent.conf << 'EOF'
[Journal]
Storage=persistent
Compress=yes
SystemMaxUse=500M
SystemMaxFileSize=100M
EOF

systemctl restart systemd-journald
log_info "Persistent logging enabled."

# ============================================================================
# 12. AIDE (INTRUSION DETECTION)
# ============================================================================
log_info "Step 12: Installing AIDE (Advanced Intrusion Detection Environment)..."

apt install -y aide aide-common

# Only initialize if database doesn't exist
if [ ! -f /var/lib/aide/aide.db ] && [ ! -f /var/lib/aide/aide.db.gz ]; then
    log_info "Initializing AIDE database (this may take several minutes)..."
    aideinit
    
    # Move the database to the correct location
    if [ -f /var/lib/aide/aide.db.new ]; then
        mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
    fi
    log_info "AIDE database initialized."
else
    log_info "AIDE database already exists. Skipping initialization."
    log_info "To reinitialize AIDE, run: sudo aideinit && sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db"
fi

# Set up weekly AIDE checks via cron
cat > /etc/cron.weekly/aide-check << 'EOF'
#!/bin/bash
/usr/bin/aide --check | mail -s "AIDE Report for $(hostname)" root
EOF

chmod +x /etc/cron.weekly/aide-check

log_info "AIDE configured."

# ============================================================================
# ADDITIONAL SECURITY MEASURES
# ============================================================================
log_info "Applying additional security hardening..."

# Disable core dumps
cat > /etc/security/limits.d/disable-coredumps.conf << 'EOF'
* hard core 0
EOF

# Kernel hardening via sysctl
cat > /etc/sysctl.d/99-security.conf << 'EOF'
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

# Ignore ICMP ping requests
net.ipv4.icmp_echo_ignore_all = 0

# Ignore broadcast pings
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Enable TCP SYN cookies
net.ipv4.tcp_syncookies = 1

# Log martian packets
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Disable IPv6 (if not needed)
# net.ipv6.conf.all.disable_ipv6 = 1
# net.ipv6.conf.default.disable_ipv6 = 1
EOF

sysctl -p /etc/sysctl.d/99-security.conf

# ============================================================================
# FINAL STEPS
# ============================================================================
log_info "Security hardening completed!"

echo ""
echo "============================================================================"
echo "                    SECURITY HARDENING SUMMARY"
echo "============================================================================"
echo ""
echo "✓ System updated and automatic security updates enabled"
echo "✓ New user '$NEW_USER' created with sudo privileges"
echo "✓ SSH hardened (port: $SSH_PORT, key-only auth, root login disabled)"
echo "✓ Fail2ban installed and configured"
echo "✓ UFW firewall enabled"
echo "✓ Auditd installed with custom rules"
echo "✓ File permissions secured"
echo "✓ Lynis security audit tool installed"
echo "✓ Rkhunter rootkit scanner installed"
echo "✓ Shared memory secured"
echo "✓ Persistent logging enabled"
echo "✓ AIDE intrusion detection initialized"
echo "✓ Additional kernel hardening applied"
echo ""
echo "============================================================================"
echo "                        IMPORTANT NEXT STEPS"
echo "============================================================================"
echo ""
echo "1. TEST SSH CONNECTION before logging out:"
echo "   ssh -p $SSH_PORT $NEW_USER@<server-ip>"
echo ""
echo "2. Keep your current session open until SSH is confirmed working"
echo ""
echo "3. Run security audits:"
echo "   sudo lynis audit system"
echo "   sudo rkhunter --check"
echo ""
echo "4. Review logs regularly:"
echo "   sudo journalctl -xe"
echo "   sudo tail -f /var/log/auth.log"
echo ""
echo "5. Set up backups for critical data"
echo ""
echo "6. Consider enabling two-factor authentication for SSH"
echo ""
echo "7. Review and customize:"
echo "   /etc/ssh/sshd_config.d/99-custom.conf"
echo "   /etc/fail2ban/jail.local"
echo "   /etc/audit/rules.d/custom.rules"
echo ""
echo "============================================================================"
echo ""

log_warn "Remember to reboot the system to apply all changes:"
echo "sudo reboot"
