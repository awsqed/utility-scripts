# Utility Scripts

A collection of useful utility scripts for system administration, automation, and common tasks.

## 📋 Overview

This repository contains various utility scripts designed to simplify system management, automation, and maintenance tasks. These scripts are organized by purpose and platform to help system administrators and developers streamline their workflows.

## 🗂️ Repository Structure

```
utility-scripts/
├── ubuntu-desktop-cleanup.sh    # Desktop environment cleanup script
├── ubuntu-server-cleanup.sh     # Server environment cleanup script
└── ubuntu-server-init.sh        # Server initialization script
```

## 🚀 Scripts

### Ubuntu Scripts

#### `ubuntu-server-init.sh`
Server initialization and setup script for Ubuntu systems.

**Purpose:** Automates the initial setup and configuration of Ubuntu server instances.

**Usage:**
```bash
chmod +x ubuntu-server-init.sh
sudo ./ubuntu-server-init.sh
```

#### `ubuntu-server-cleanup.sh`
Server environment cleanup and maintenance script.

**Purpose:** Performs system cleanup tasks including removing old packages, clearing logs, and freeing up disk space on Ubuntu servers.

**Usage:**
```bash
chmod +x ubuntu-server-cleanup.sh
sudo ./ubuntu-server-cleanup.sh
```

#### `ubuntu-desktop-cleanup.sh`
Desktop environment cleanup script for Ubuntu.

**Purpose:** Cleans up unnecessary files, caches, and packages specific to Ubuntu desktop environments.

**Usage:**
```bash
chmod +x ubuntu-desktop-cleanup.sh
sudo ./ubuntu-desktop-cleanup.sh
```

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

- **Operating System:** Ubuntu (tested on Ubuntu 20.04, 22.04, and 24.04)
- **Permissions:** Most scripts require root/sudo access
- **Shell:** Bash (typically pre-installed on Ubuntu)

## 🔒 Safety & Best Practices

1. **Review Before Running:** Always review scripts before executing them, especially with sudo privileges
2. **Backup Important Data:** Create backups before running cleanup or system modification scripts
3. **Test in Non-Production:** Test scripts in a development or staging environment first
4. **Check Compatibility:** Ensure scripts are compatible with your Ubuntu version

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

## 🤝 Support

If you encounter any issues or have questions:

- Open an [issue](https://github.com/awsqed/utility-scripts/issues)
- Check existing issues for solutions
- Contribute fixes via pull requests

## 🔄 Updates

Scripts are regularly updated to support newer Ubuntu versions and incorporate community feedback. Check the commit history for recent changes.

## ⭐ Acknowledgments

Thanks to all contributors who help improve these utility scripts!

---

**Note:** Always exercise caution when running scripts with elevated privileges. Review the code and understand what each script does before execution.
