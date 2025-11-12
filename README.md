# Utility Scripts

[![Ubuntu](https://img.shields.io/badge/Ubuntu-24.04%20LTS-E95420?logo=ubuntu&logoColor=white)](https://ubuntu.com/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-3.0-green.svg)](https://github.com/awsqed/utility-scripts)
[![Bash](https://img.shields.io/badge/Bash-4.0+-4EAA25?logo=gnu-bash&logoColor=white)](https://www.gnu.org/software/bash/)

A collection of enterprise-grade utility scripts for Ubuntu system administration, security hardening, and automated maintenance.

## 📋 Overview

This repository contains production-ready utility scripts designed to simplify system management, security hardening, and maintenance tasks for Ubuntu environments. Each script features comprehensive error handling, logging, and automated execution capabilities suitable for both interactive and automated deployments.

> **🚀 Quick Start**: Clone the repo, make scripts executable, configure `ubuntu-server-init.sh` variables, and run with sudo. See [Installation](#%EF%B8%8F-installation) for details.

## 📑 Quick Navigation

- [Scripts](#-scripts) - Detailed documentation for each script
  - [ubuntu-server-init.sh](#ubuntu-server-initsh) - Security hardening (v3.0)
  - [ubuntu-server-cleanup.sh](#ubuntu-server-cleanupsh) - Server maintenance
  - [ubuntu-desktop-cleanup.sh](#ubuntu-desktop-cleanupsh) - Desktop cleanup
- [Installation](#%EF%B8%8F-installation) - Quick start and setup guide
- [Prerequisites](#%EF%B8%8F-prerequisites) - System requirements
- [Safety & Best Practices](#-safety--best-practices) - Security guidelines
- [Automation & Scheduling](#-automation--scheduling) - Cron job setup
- [Common Use Cases](#-common-use-cases) - Real-world examples
- [Troubleshooting](#-troubleshooting) - Problem resolution
- [Version History](#-version-history) - Changelog and updates
- [Resources & References](#-resources--references) - Tools and documentation
- [Security Features Summary](#%EF%B8%8F-security-features-summary) - Security overview
- [Contributing](#-contributing) - Contribution guidelines

## 🗂️ Repository Structure

```
utility-scripts/
├── ubuntu-desktop-cleanup.sh           # Desktop environment cleanup script
├── ubuntu-server-cleanup.sh            # Server environment cleanup script
├── ubuntu-server-init.sh               # Server initialization script (v3.0)
└── README.md                           # This file
```

## 🚀 Scripts

### Ubuntu Server Initialization & Security Hardening

#### `ubuntu-server-init.sh`
**Version:** 3.0 - Enhanced with Docker Security & Advanced Hardening

Comprehensive security hardening and initialization script for Ubuntu 24.04 servers with advanced enterprise-grade features.

**Key Features:**
- **23-step automated security hardening** with resume capability (8 new steps in v3.0)
- **User Management:** Secure user creation with SSH key authentication
- **SSH Hardening:** Custom port configuration, key-only auth, advanced security settings
- **Firewall:** UFW configuration with Docker integration (ufw-docker)
- **Docker Security:** Complete Docker installation with AppArmor profiles, runtime security monitoring, and secure daemon configuration
- **Intrusion Detection:** Fail2ban, Rkhunter, AIDE file integrity monitoring
- **System Auditing:** Auditd with Docker-specific rules and automated weekly security audits
- **Security Scanning:** Lynis security auditing tool with automated scheduling
- **Enhanced Logging:** Persistent journald logging and daily log monitoring with alerting
- **Kernel Hardening:** Enhanced IPv6 security, Docker optimizations, module blacklisting, and sysctl security parameters
- **DNS Security:** DNSSEC validation with DNS-over-TLS (opportunistic mode)
- **PAM Security:** Account lockout policies with faillock (replaces pam_tally2)
- **Tmpfs Hardening:** Secure /tmp and /var/tmp with noexec, nosuid, nodev options
- **File System Security:** Secure shared memory and proper file permissions

**Usage:**
```bash
# Configure variables in the script first:
# - NEW_USER: Your username
# - SSH_PORT: SSH port (default: 22)
# - SSH_PUBLIC_KEY: Your SSH public key

chmod +x ubuntu-server-init.sh
sudo ./ubuntu-server-init.sh
```

**Resume Capability:** If interrupted, the script automatically resumes from the last completed step.

**Tested on:** Ubuntu 20.04, 22.04, 24.04 LTS

---

### System Cleanup & Maintenance

#### `ubuntu-server-cleanup.sh`
Enterprise-grade cleanup script optimized for headless server environments.

**Key Features:**
- **Fully Automated:** Designed for cron execution with minimal user interaction
- **Intelligent Package Management:** Safe APT cache cleanup and autoremoval
- **Kernel Management:** Automatic old kernel removal with N-1 retention policy
- **Log Management:** Configurable log retention (default: 90 days)
- **Protected Directories:** Built-in exclusion patterns for critical paths
- **Resource-Aware:** Parallel job support with resource usage limits
- **Comprehensive Logging:** Syslog integration and detailed audit trail
- **Lock Management:** APT and script-level locking to prevent conflicts
- **Dry Run Mode:** Test mode for safe validation before execution

**Configuration:**
```bash
# Environment variables (optional):
export CONFIG_FILE="/etc/ubuntu_cleanup_server.conf"
export LOG_DIR="/var/log/system_cleanup"
export AUTO_CONFIRM=1  # Auto-confirm for automation
export RETENTION_DAYS=10
export LOG_RETENTION_DAYS=90
```

**Usage:**
```bash
chmod +x ubuntu-server-cleanup.sh
sudo ./ubuntu-server-cleanup.sh

# Dry run mode:
sudo ./ubuntu-server-cleanup.sh --dry-run

# Verbose output:
sudo ./ubuntu-server-cleanup.sh --verbose
```

**Protected Directories:** Excludes critical paths like `.git`, `.venv`, `node_modules`, `database`, `backup`, and more.

---

#### `ubuntu-desktop-cleanup.sh`
Interactive cleanup script optimized for Ubuntu desktop environments.

**Key Features:**
- **Desktop-Specific Cleaning:** Browser cache, IDE temp files, thumbnails
- **User-Friendly:** Interactive prompts with sensible timeouts
- **Media Cache Management:** Thumbnail and media cache cleanup (30-day retention)
- **User Cache Cleanup:** User-level and system cache cleaning
- **Protected User Directories:** Excludes Documents, Pictures, Videos, Music, Downloads
- **Safe Kernel Retention:** Keeps current + 1 previous kernel
- **Configurable Retention:** Default 7-day cache retention, 3-day recent cache
- **Non-Root Option:** Can run without sudo for user-level cleanup

**Usage:**
```bash
chmod +x ubuntu-desktop-cleanup.sh
./ubuntu-desktop-cleanup.sh

# For system-wide cleanup (requires sudo):
sudo ./ubuntu-desktop-cleanup.sh
```

**Configuration File:** `~/.config/ubuntu_cleanup_desktop.conf`

## ⚙️ Installation

### Quick Start

1. Clone the repository:
```bash
git clone https://github.com/awsqed/utility-scripts.git
cd utility-scripts
```

2. Make scripts executable:
```bash
chmod +x *.sh
```

3. Run the desired script:
```bash
sudo ./script-name.sh
```

### Individual Script Download

You can also download individual scripts directly:
```bash
wget https://raw.githubusercontent.com/awsqed/utility-scripts/master/ubuntu-server-init.sh
chmod +x ubuntu-server-init.sh
```

## ⚠️ Prerequisites

### General Requirements
- **Operating System:** Ubuntu LTS (tested on 20.04, 22.04, and 24.04)
- **Shell:** Bash 4.0+ (pre-installed on Ubuntu)
- **Network:** Internet connection for package downloads (init script)

### Script-Specific Requirements

**ubuntu-server-init.sh:**
- Fresh Ubuntu Server installation (optimized for 24.04 LTS, compatible with 20.04/22.04)
- Root/sudo access
- SSH public key for remote access
- 2GB+ available disk space
- Internet connection for package downloads

**ubuntu-server-cleanup.sh:**
- Root/sudo access for system-wide cleanup
- Write access to `/var/log` and `/var/lock`

**ubuntu-desktop-cleanup.sh:**
- Can run with or without sudo
- User-level cleanup: No sudo required
- System-level cleanup: Sudo required

## 🔒 Safety & Best Practices

### Before Running Any Script

1. **Review the Code:** Always review scripts before executing, especially with sudo privileges
2. **Backup Critical Data:** Create backups before running system modification scripts
3. **Test First:** Use dry-run mode where available (`--dry-run` flag for cleanup scripts)
4. **Check Compatibility:** Verify Ubuntu version compatibility
5. **Configure Variables:** Update configuration variables in `ubuntu-server-init.sh` before running

### Script-Specific Safety Features

**ubuntu-server-init.sh:**
- Resume capability if interrupted
- Progress logging to `/var/log/hardening-progress.log`
- Lock file prevents concurrent execution
- Automated rollback on critical failures

**Cleanup Scripts:**
- Protected directory exclusion patterns
- Dry-run mode for safe testing
- Comprehensive error handling
- Safe kernel retention (never removes current kernel)
- APT lock detection and handling

### Recommended Workflow

```bash
# 1. Clone and review
git clone https://github.com/awsqed/utility-scripts.git
cd utility-scripts
less ubuntu-server-init.sh  # Review the script

# 2. Configure (for init script)
nano ubuntu-server-init.sh  # Edit configuration variables

# 3. Test (for cleanup scripts)
sudo ./ubuntu-server-cleanup.sh --dry-run

# 4. Execute
sudo ./ubuntu-server-init.sh
```

## 🤖 Automation & Scheduling

### Automated Cleanup with Cron

The cleanup scripts are designed for automated execution. Here's how to set up scheduled maintenance:

#### Weekly Server Cleanup
```bash
# Edit crontab
sudo crontab -e

# Add weekly cleanup (Sunday at 3 AM)
0 3 * * 0 /path/to/utility-scripts/ubuntu-server-cleanup.sh >> /var/log/automated-cleanup.log 2>&1

# Or monthly cleanup (1st of month at 2 AM)
0 2 1 * * /path/to/utility-scripts/ubuntu-server-cleanup.sh
```

#### Desktop Cleanup Schedule
```bash
# User crontab (no sudo needed for user-level cleanup)
crontab -e

# Weekly user cache cleanup (Saturday at 10 PM)
0 22 * * 6 /path/to/utility-scripts/ubuntu-desktop-cleanup.sh
```

### Environment Variables for Automation
```bash
# Create wrapper script for custom configuration
cat > /usr/local/bin/scheduled-cleanup.sh << 'EOF'
#!/bin/bash
export AUTO_CONFIRM=1
export RETENTION_DAYS=14
export LOG_RETENTION_DAYS=90
export VERBOSE=0
/opt/utility-scripts/ubuntu-server-cleanup.sh
EOF

chmod +x /usr/local/bin/scheduled-cleanup.sh
```

### Monitoring Automated Runs
```bash
# View cleanup logs
sudo tail -f /var/log/system_cleanup/cleanup_*.log

# Check syslog entries
sudo journalctl -t ubuntu_cleanup_server -n 50

# Monitor disk space trends
df -h / | tee -a /var/log/disk-usage-trend.log
```

## 📝 Contributing

Contributions are welcome! If you have utility scripts that could benefit others:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-script`)
3. Commit your changes (`git commit -m 'Add new utility script'`)
4. Push to the branch (`git push origin feature/new-script`)
5. Open a Pull Request

### Contribution Guidelines

- Include clear documentation for each script
- Add usage examples and prerequisites
- Follow existing naming conventions
- Test scripts thoroughly before submitting
- Include error handling and user feedback

## 📄 License

This project is open source and available under the [MIT License](LICENSE).

## 💡 Common Use Cases

### Fresh Server Deployment
```bash
# 1. Deploy new Ubuntu 24.04 server
# 2. Update configuration in ubuntu-server-init.sh
# 3. Run security hardening
sudo ./ubuntu-server-init.sh
# 4. Server is production-ready with Docker, firewall, and monitoring
```

### Regular Maintenance Routine
```bash
# Weekly automated cleanup
sudo ./ubuntu-server-cleanup.sh

# Monthly cleanup with verbose logging
sudo ./ubuntu-server-cleanup.sh --verbose >> /var/log/maintenance.log
```

### Desktop System Optimization
```bash
# Quick user cache cleanup (no sudo)
./ubuntu-desktop-cleanup.sh

# Deep system cleanup (requires sudo)
sudo ./ubuntu-desktop-cleanup.sh
```

## 🔧 Troubleshooting

### ubuntu-server-init.sh

**Issue:** Script fails during execution
```bash
# Check progress log
sudo cat /var/log/hardening-progress.log

# Resume from last successful step (automatic)
sudo ./ubuntu-server-init.sh
```

**Issue:** Configuration not set
```bash
# Error: NEW_USER or SSH_PUBLIC_KEY not configured
# Solution: Edit script and update required variables
nano ubuntu-server-init.sh
```

### Cleanup Scripts

**Issue:** APT locked
```bash
# The script will automatically wait for locks to release
# Or manually check:
sudo lsof /var/lib/dpkg/lock-frontend
```

**Issue:** Permission denied
```bash
# Cleanup scripts need sudo for system operations
sudo ./ubuntu-server-cleanup.sh
```

**Issue:** Want to test before running
```bash
# Use dry-run mode
sudo ./ubuntu-server-cleanup.sh --dry-run
```

**Issue:** Protected directory being cleaned
```bash
# Check exclusion patterns in the script
# Add custom patterns by editing EXCLUDED_PATTERNS array
```

## 🤝 Support

If you encounter any issues or have questions:

- Open an [issue](https://github.com/awsqed/utility-scripts/issues)
- Check existing issues for solutions
- Review [troubleshooting](#-troubleshooting) section above
- Contribute fixes via pull requests

## 🔄 Version History

### Recent Updates
- **v3.0** (ubuntu-server-init.sh):
  - 🆕 8 new security steps (15-22)
  - 🐳 Critical Docker security hardening (AppArmor, runtime monitoring)
  - 🔒 PAM account lockout with faillock
  - 📁 Tmpfs hardening (/tmp, /var/tmp with noexec)
  - 🚫 Kernel module blacklisting (USB, uncommon protocols)
  - 🔐 DNS security (DNSSEC + DNS-over-TLS)
  - 📊 Automated security audits (weekly Lynis scans)
  - 📝 Daily log monitoring and alerting
  - 📚 Comprehensive documentation (SECURITY-ENHANCEMENTS-v3.md, QUICK-REFERENCE.md)
  - 🐋 Docker Compose security examples
- **v2.0** (cleanup scripts): Enterprise-grade error handling, logging, and automation support
- Added `.gitignore` for repository management
- Comprehensive documentation updates

### Changelog Highlights
- Docker installation with ufw-docker integration
- DNS-over-TLS security configuration
- Automated security audit scheduling
- Enhanced log monitoring and alerting
- Protected directory exclusion patterns
- Parallel job processing for faster cleanup
- Syslog integration for enterprise environments

Check the [commit history](https://github.com/awsqed/utility-scripts/commits/master) for detailed changes.

## 📚 Resources & References

### Security Tools & Standards

#### Tools Implemented in Scripts
- **[UFW (Uncomplicated Firewall)](https://help.ubuntu.com/community/UFW)** - Ubuntu's default firewall configuration tool
- **[Fail2ban](https://www.fail2ban.org/)** - Intrusion prevention software framework
- **[Docker](https://docs.docker.com/)** - Container platform with security best practices
- **[ufw-docker](https://github.com/chaifeng/ufw-docker)** - UFW and Docker integration for secure container networking
- **[Auditd](https://linux.die.net/man/8/auditd)** - Linux Audit daemon for security auditing
- **[Lynis](https://cisofy.com/lynis/)** - Security auditing tool for Unix-based systems
- **[Rkhunter](http://rkhunter.sourceforge.net/)** - Rootkit detection toolkit
- **[AIDE (Advanced Intrusion Detection Environment)](https://aide.github.io/)** - File integrity monitoring tool
- **[AppArmor](https://apparmor.net/)** - Linux kernel security module for mandatory access control
- **[systemd-resolved](https://www.freedesktop.org/software/systemd/man/systemd-resolved.service.html)** - DNS resolver with DNS-over-TLS support

#### Security Standards & Best Practices
- **[CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)** - Security configuration best practices
- **[NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)** - Standards for security hardening
- **[OWASP Security Guidelines](https://owasp.org/)** - Web application security standards
- **[Linux Kernel Hardening](https://kernsec.org/wiki/index.php/Kernel_Self_Protection_Project)** - Kernel security parameters
- **[Docker Security Best Practices](https://docs.docker.com/engine/security/)** - Container security guidelines

#### Ubuntu 24.04 Specific Security
- **[Ubuntu 24.04 Security Features](https://ubuntu.com/blog/whats-new-in-security-for-ubuntu-24-04-lts)** - New security features in Ubuntu 24.04 LTS
- **[AppArmor 4.0](https://ubuntu.com/server/docs/security-apparmor)** - Enhanced mandatory access control for containers
- **[Kernel 6.8 Security](https://ubuntu.com/blog/whats-new-in-ubuntu-24-04-lts)** - Kernel Control Flow Integrity (KCFI)
- **[FORTIFY_SOURCE=3](https://developers.redhat.com/articles/2022/09/17/gccs-new-fortification-level)** - Enhanced buffer overflow detection

### Configuration References

#### SSH Hardening
- **[Mozilla SSH Guidelines](https://infosec.mozilla.org/guidelines/openssh)** - SSH configuration recommendations
- **[SSH.com Best Practices](https://www.ssh.com/academy/ssh/security)** - SSH security guide

#### PAM (Pluggable Authentication Modules)
- **[Linux PAM Documentation](http://www.linux-pam.org/Linux-PAM-html/)** - PAM configuration guide
- **[Ubuntu PAM Configuration](https://ubuntu.com/server/docs/security-users)** - Ubuntu-specific PAM setup
- **[pam_faillock](https://man7.org/linux/man-pages/man8/pam_faillock.8.html)** - Account lockout module (replaces pam_tally2)

#### Docker & Container Security
- **[Docker Security Documentation](https://docs.docker.com/engine/security/)** - Official Docker security guide
- **[CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)** - Container security standards
- **[OWASP Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)** - Docker security best practices
- **[Docker Compose Security](https://docs.docker.com/compose/compose-file/compose-file-v3/#security_opt)** - Secure compose configurations
- **[User Namespace Remapping](https://docs.docker.com/engine/security/userns-remap/)** - Container privilege isolation

#### Firewall & Network Security
- **[Ubuntu Firewall Documentation](https://ubuntu.com/server/docs/security-firewall)** - UFW configuration guide
- **[DNS-over-TLS RFC 7858](https://datatracker.ietf.org/doc/html/rfc7858)** - DNS privacy specification

#### System Maintenance
- **[Ubuntu Server Guide](https://ubuntu.com/server/docs)** - Official Ubuntu documentation
- **[Debian APT Documentation](https://www.debian.org/doc/manuals/apt-guide/)** - Package management best practices
- **[Filesystem Hierarchy Standard](https://refspecs.linuxfoundation.org/FHS_3.0/fhs/index.html)** - Linux directory structure

### Script Development Resources

#### Bash Best Practices
- **[Google Shell Style Guide](https://google.github.io/styleguide/shellguide.html)** - Shell scripting standards
- **[ShellCheck](https://www.shellcheck.net/)** - Shell script analysis tool
- **[Bash Strict Mode](http://redsymbol.net/articles/unofficial-bash-strict-mode/)** - Error handling in bash

#### Error Handling & Exit Codes
- **[Advanced Bash-Scripting Guide](https://tldp.org/LDP/abs/html/)** - Comprehensive bash scripting reference
- **[Exit Status Codes](https://tldp.org/LDP/abs/html/exitcodes.html)** - Standard exit code conventions

### Community & Support

- **[Ubuntu Security Team](https://ubuntu.com/security)** - Official security updates and advisories
- **[Ubuntu Forums - Security](https://ubuntuforums.org/forumdisplay.php?f=338)** - Community security discussions
- **[Ask Ubuntu - Security Tag](https://askubuntu.com/questions/tagged/security)** - Q&A for security topics

### Modern Hardening Guides (2024-2025)

- **[CIS Ubuntu Linux 24.04 LTS Benchmark](https://www.cisecurity.org/benchmark/ubuntu_linux)** - Security configuration benchmarks
- **[DISA STIG for Ubuntu 24.04](https://stigviewer.com/stigs/canonical_ubuntu_24.04_lts)** - DoD security requirements
- **[Ubuntu Security Guide (USG)](https://ubuntu.com/security/cis)** - Automated CIS hardening
- **[NIST SP 800-123](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-123.pdf)** - Guide to General Server Security

### Related Projects & Guides

- **[Ansible Hardening Roles](https://github.com/dev-sec/ansible-collection-hardening)** - Automated security hardening
- **[OpenSCAP](https://www.open-scap.org/)** - Security compliance checking
- **[Bastille Linux](http://bastille-linux.sourceforge.net/)** - System hardening toolkit
- **[Ubuntu Cleanup Script by Limbicnation](https://gist.github.com/Limbicnation/6763b69ab6a406790f3b7d4b56a2f6e8)** - Comprehensive Ubuntu 24.04 cleanup implementation with similar security patterns

### Inspiration & Methodology

The scripts in this repository incorporate security best practices and patterns from:
- CIS Ubuntu Linux 24.04 LTS Benchmark
- DISA STIG (Security Technical Implementation Guides)
- Community-tested security hardening guides
- Production-tested enterprise deployment patterns
- Open-source security tooling best practices

## ⭐ Acknowledgments

Thanks to all contributors who help improve these utility scripts!

Special recognition to the maintainers and communities behind the security tools and frameworks that make these scripts possible.

## 🛡️ Security Features Summary

### ubuntu-server-init.sh Security Layers

| Layer | Features |
|-------|----------|
| **Network** | UFW firewall, custom SSH port, Docker network isolation, DNS-over-TLS |
| **Access Control** | SSH key-only auth, PAM account lockout (faillock), sudo hardening, AppArmor profiles |
| **Monitoring** | Fail2ban, auditd with Docker rules, automated weekly security audits, daily log monitoring |
| **Integrity** | AIDE file integrity, rkhunter rootkit detection, automated scanning |
| **Container** | Docker AppArmor profiles with userns, runtime security monitoring, secure daemon config |
| **System** | Enhanced kernel hardening (KCFI, ASLR), kernel module blacklisting, secure tmpfs with noexec |
| **DNS** | DNSSEC validation, DNS-over-TLS (opportunistic), Cloudflare/Google DNS |

### Exit Codes

All scripts use consistent exit codes for automation:
- `0` - Success
- `1` - Lock failed / already running
- `2` - APT locked
- `3` - Insufficient privileges
- `4` - Missing dependencies
- `5` - User aborted
- `10` - Operation failed
- `11` - Invalid configuration

---

**Note:** Always exercise caution when running scripts with elevated privileges. Review the code and understand what each script does before execution.
