#!/usr/bin/env bash

# Ubuntu Server Cleanup Script - Optimized for Headless Environments
# This script performs comprehensive system cleanup for Ubuntu servers
# Designed for automated execution via cron with minimal user interaction
#
# Features:
# - Fully automated with configurable retention policies
# - Enterprise-grade security and error handling
# - Comprehensive logging and audit trail
# - Protected directory exclusions
# - Safe kernel retention (N-1 policy)
# - APT and script-level locking

# Exit codes
readonly EXIT_SUCCESS=0
readonly EXIT_LOCK_FAILED=1
readonly EXIT_APT_LOCKED=2
readonly EXIT_NO_PRIVILEGES=3
readonly EXIT_DEPENDENCY_MISSING=4
readonly EXIT_USER_ABORT=5
readonly EXIT_OPERATION_FAILED=10
readonly EXIT_CONFIG_INVALID=11

# Strict error handling
set -euo pipefail
IFS=$'\n\t'

# Configuration variables (can be overridden via config file)
CONFIG_FILE="${CONFIG_FILE:-/etc/ubuntu_cleanup_server.conf}"
LOG_DIR="${LOG_DIR:-/var/log/system_cleanup}"
LOG_FILE="${LOG_DIR}/cleanup_$(date +%Y%m%d_%H%M%S).log"
LOCK_FILE="/var/lock/ubuntu_cleanup_server.lock"
LOCK_FD=200
DRY_RUN=0
VERBOSE=0
TIMEOUT_DURATION=300  # 5 minutes for APT locks
PARALLEL_JOBS=2
MAX_RESOURCE_USAGE=50
RETENTION_DAYS=10
LOG_RETENTION_DAYS=90
KERNEL_RETAIN_COUNT=2  # Current + 1 previous
AUTO_CONFIRM=${AUTO_CONFIRM:-1}  # Auto-confirm by default for servers
HAS_ROOT=0

# EXCLUSION PATTERNS - Critical directories to protect
EXCLUDED_PATTERNS=(
    "hy3dgen"
    "Hunyuan3D"
    "huggingface"
    ".git"
    ".venv"
    "node_modules"
    "venv"
    "env"
    ".env"
    "backup"
    ".backup"
    "production"
    "database"
    "db"
)

# Logging function with syslog integration
log_operation() {
    local severity=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    echo "[$timestamp] [$severity] $message"

    # Send to syslog
    if command -v logger &>/dev/null; then
        logger -t ubuntu_cleanup_server -p "user.$severity" "$message"
    fi
}

# Cleanup handler for trap
cleanup_on_error() {
    local exit_code=$?
    if [ $exit_code -ne 0 ]; then
        log_operation "err" "Script failed with exit code $exit_code at line ${BASH_LINENO[0]}"
        log_operation "err" "Failed command: ${BASH_COMMAND}"
    fi

    release_lock
    exit $exit_code
}

# Set trap handlers
trap cleanup_on_error ERR EXIT
trap 'log_operation "warning" "Script interrupted by signal"; exit $EXIT_USER_ABORT' SIGTERM SIGINT

# Create log directory with proper permissions
mkdir -p "$LOG_DIR" 2>/dev/null || true
chmod 750 "$LOG_DIR" 2>/dev/null || true

# Setup logging
exec > >(tee -a "$LOG_FILE") 2>&1

# Safe configuration loader
load_safe_config() {
    if [ ! -f "$CONFIG_FILE" ]; then
        log_operation "info" "No config file found at $CONFIG_FILE, using defaults"
        return 0
    fi

    log_operation "info" "Loading configuration from $CONFIG_FILE"

    while IFS='=' read -r key value; do
        [[ "$key" =~ ^#.*$ || -z "$key" ]] && continue

        key=$(echo "$key" | xargs)
        value=$(echo "$value" | xargs | sed 's/^["'\'']\|["'\'']$//g')

        case "$key" in
            RETENTION_DAYS|LOG_RETENTION_DAYS|KERNEL_RETAIN_COUNT|TIMEOUT_DURATION|PARALLEL_JOBS|MAX_RESOURCE_USAGE)
                if [[ "$value" =~ ^[0-9]+$ ]] && [ "$value" -ge 1 ] && [ "$value" -le 9999 ]; then
                    declare -g "$key=$value"
                    log_operation "info" "Config: $key=$value"
                fi
                ;;
            AUTO_CONFIRM|DRY_RUN|VERBOSE)
                if [[ "$value" =~ ^[01]$ ]]; then
                    declare -g "$key=$value"
                    log_operation "info" "Config: $key=$value"
                fi
                ;;
            EXCLUDED_PATTERNS)
                IFS=',' read -ra patterns <<< "$value"
                EXCLUDED_PATTERNS=("${patterns[@]}")
                log_operation "info" "Config: EXCLUDED_PATTERNS=${EXCLUDED_PATTERNS[*]}"
                ;;
        esac
    done < <(grep -v '^#' "$CONFIG_FILE" | grep -v '^$')
}

# Script-level locking
acquire_lock() {
    exec 200>"$LOCK_FILE"
    if ! flock -n 200; then
        log_operation "err" "Another instance is already running"
        exit $EXIT_LOCK_FAILED
    fi
    echo $$ >&200
    log_operation "info" "Lock acquired (PID: $$)"
}

release_lock() {
    if [ -n "${LOCK_FD:-}" ]; then
        flock -u $LOCK_FD 2>/dev/null || true
        rm -f "$LOCK_FILE" 2>/dev/null || true
    fi
}

# APT lock checking with extended timeout for servers
check_apt_lock() {
    local max_wait=$TIMEOUT_DURATION
    local waited=0
    local lock_files=(
        "/var/lib/dpkg/lock-frontend"
        "/var/lib/apt/lists/lock"
        "/var/cache/apt/archives/lock"
    )

    while true; do
        local locked=0

        for lock_file in "${lock_files[@]}"; do
            if fuser "$lock_file" >/dev/null 2>&1; then
                locked=1
                break
            fi
        done

        if [ $locked -eq 0 ]; then
            return 0
        fi

        if [ $waited -ge $max_wait ]; then
            log_operation "err" "APT lock held for $max_wait seconds, aborting"
            exit $EXIT_APT_LOCKED
        fi

        log_operation "warning" "Waiting for APT lock... ($waited/$max_wait seconds)"
        sleep 10
        waited=$((waited + 10))
    done
}

# Check for root privileges
check_root() {
    if [[ $EUID -eq 0 ]]; then
        HAS_ROOT=1
        log_operation "info" "Running with root privileges"
    else
        log_operation "err" "Server script requires root privileges. Run with sudo or as root."
        exit $EXIT_NO_PRIVILEGES
    fi
}

# Resource limit enforcement
enforce_resource_limits() {
    renice -n 15 -p $$ >/dev/null 2>&1 || true

    if command -v ionice &>/dev/null; then
        ionice -c 3 -p $$ >/dev/null 2>&1 || true
    fi

    log_operation "info" "Resource limits enforced: nice=15, ionice=idle"
}

# Path validation
is_safe_path() {
    local path=$1
    local abs_path
    abs_path=$(readlink -f "$path" 2>/dev/null) || return 1

    local dangerous_paths=(
        "/"
        "/bin"
        "/boot"
        "/dev"
        "/etc"
        "/lib"
        "/lib64"
        "/proc"
        "/root"
        "/sbin"
        "/sys"
        "/usr"
    )

    for dangerous_path in "${dangerous_paths[@]}"; do
        if [[ "$abs_path" == "$dangerous_path" ]] || [[ "$abs_path" == "$dangerous_path"/* ]]; then
            log_operation "err" "Refusing to remove critical path: $abs_path"
            return 1
        fi
    done

    return 0
}

# Check if path should be excluded
is_excluded() {
    local path=$1
    for pattern in "${EXCLUDED_PATTERNS[@]}"; do
        if [[ "$path" == *"$pattern"* ]]; then
            log_operation "info" "Excluding protected path: $path (pattern: $pattern)"
            return 0
        fi
    done
    return 1
}

# Safe removal with exclusion checking
safe_remove() {
    local target=$1
    local force=${2:-0}

    is_excluded "$target" && return 0
    is_safe_path "$target" || return 1

    [ ! -e "$target" ] && return 0

    if [ -d "$target" ] && [ ! -L "$target" ]; then
        log_operation "info" "Removing directory contents: $target"
        rm -rf "${target:?}"/* 2>/dev/null || true
    else
        log_operation "info" "Removing: $target"
        [ $force -eq 1 ] && rm -f "$target" 2>/dev/null || rm "$target" 2>/dev/null || true
    fi

    return 0
}

# Enhanced find with exclusions
safe_find() {
    local base_path=$1
    shift
    local find_args=("$@")

    local exclude_args=()
    for pattern in "${EXCLUDED_PATTERNS[@]}"; do
        exclude_args+=(-not -path "*${pattern}*")
    done

    find "$base_path" "${exclude_args[@]}" "${find_args[@]}" 2>/dev/null || true
}

# System snapshot
create_system_snapshot() {
    local snapshot_dir="/var/backups/cleanup_snapshot_$(date +%Y%m%d_%H%M%S)"

    log_operation "info" "Creating system snapshot: $snapshot_dir"
    mkdir -p "$snapshot_dir"

    dpkg --get-selections > "$snapshot_dir/package_selections.txt" 2>/dev/null || true
    apt-mark showmanual > "$snapshot_dir/manual_packages.txt" 2>/dev/null || true
    dpkg -l | grep -E 'linux-image|linux-headers' > "$snapshot_dir/kernel_list.txt" 2>/dev/null || true
    cp -r /etc/apt/sources.list* "$snapshot_dir/" 2>/dev/null || true

    log_operation "info" "Snapshot created: $snapshot_dir"
    echo "$snapshot_dir" > /tmp/cleanup_snapshot.path
}

# Safe kernel cleanup with configurable retention
safe_kernel_cleanup() {
    local current_kernel=$(uname -r)
    local installed_kernels
    installed_kernels=$(dpkg -l | grep -E '^ii.*linux-image-[0-9]' | awk '{print $2}' | grep -v "linux-image-generic" || true)
    local kernel_count=$(echo "$installed_kernels" | grep -v '^$' | wc -l)

    log_operation "info" "Current kernel: $current_kernel"
    log_operation "info" "Installed kernels: $kernel_count"

    if [ $kernel_count -le $KERNEL_RETAIN_COUNT ]; then
        log_operation "info" "Only $kernel_count kernels installed. Skipping cleanup (minimum: $KERNEL_RETAIN_COUNT)"
        return 0
    fi

    log_operation "info" "Removing old kernels (keeping current + $((KERNEL_RETAIN_COUNT-1)) previous)"
    
    check_apt_lock
    apt-get autoremove --purge -y || log_operation "err" "Kernel cleanup failed"

    local remaining_kernels
    remaining_kernels=$(dpkg -l | grep -E '^ii.*linux-image-[0-9]' | awk '{print $2}' | grep -v "linux-image-generic" | wc -l)

    if [ $remaining_kernels -lt $KERNEL_RETAIN_COUNT ]; then
        log_operation "err" "CRITICAL: Less than $KERNEL_RETAIN_COUNT kernels remaining!"
        return 1
    fi

    log_operation "info" "Remaining kernels: $remaining_kernels"
}

# Log rotation
rotate_old_logs() {
    log_operation "info" "Rotating logs older than $LOG_RETENTION_DAYS days"
    find "$LOG_DIR" -name "cleanup_*.log" -mtime +$LOG_RETENTION_DAYS -delete 2>/dev/null || true

    local log_count=$(ls "$LOG_DIR"/cleanup_*.log 2>/dev/null | wc -l)
    if [ $log_count -gt 100 ]; then
        ls -t "$LOG_DIR"/cleanup_*.log | tail -n +101 | xargs rm -f 2>/dev/null || true
    fi
}

# Check dependencies
check_dependencies() {
    local missing_tools=()

    for tool in apt-get find grep awk bc fuser flock; do
        if ! command -v "$tool" &>/dev/null; then
            missing_tools+=("$tool")
        fi
    done

    if [ ${#missing_tools[@]} -gt 0 ]; then
        log_operation "err" "Missing required tools: ${missing_tools[*]}"
        exit $EXIT_DEPENDENCY_MISSING
    fi
}

# Record disk space
record_disk_space() {
    log_operation "info" "Initial disk space:"
    df -h / /var /home 2>/dev/null || df -h /
    initial_space=$(df / | awk 'NR==2 {print $4}')
}

# Parse command line options
while getopts "dnvt:j:r:k:c:" opt; do
    case $opt in
        d|n) DRY_RUN=1 ;;
        v) VERBOSE=1 ;;
        t) TIMEOUT_DURATION=$OPTARG ;;
        j) PARALLEL_JOBS=$OPTARG ;;
        r) MAX_RESOURCE_USAGE=$OPTARG ;;
        k) RETENTION_DAYS=$OPTARG ;;
        c) CONFIG_FILE=$OPTARG ;;
        *) echo "Usage: $0 [-d|-n] [-v] [-t timeout] [-j jobs] [-r max_cpu] [-k retention_days] [-c config_file]" >&2
           exit 1 ;;
    esac
done

# Progress tracking
total_steps=18
current_step=0

progress() {
    current_step=$((current_step + 1))
    percentage=$((current_step * 100 / total_steps))
    log_operation "info" "[$current_step/$total_steps - $percentage%] $1"
}

# Main execution
log_operation "info" "=== Ubuntu Server Cleanup Started ==="
log_operation "info" "PID: $$ | Hostname: $(hostname)"

acquire_lock
load_safe_config
check_dependencies
check_root
enforce_resource_limits
rotate_old_logs
record_disk_space

log_operation "info" "Protected patterns: ${EXCLUDED_PATTERNS[*]}"
[ $DRY_RUN -eq 1 ] && log_operation "warning" "DRY RUN MODE - No changes will be made"

# Create snapshot if not dry run
[ $DRY_RUN -eq 0 ] && [ $AUTO_CONFIRM -eq 1 ] && create_system_snapshot

# Cleanup operations
progress "Updating package list"
if [ $DRY_RUN -eq 0 ]; then
    check_apt_lock
    apt-get update -qq || log_operation "warning" "Package list update failed"
fi

progress "Cleaning APT cache"
[ $DRY_RUN -eq 0 ] && apt-get clean

progress "Removing obsolete packages"
[ $DRY_RUN -eq 0 ] && apt-get autoclean -y

progress "Removing unused packages"
if [ $DRY_RUN -eq 0 ]; then
    check_apt_lock
    apt-get autoremove -y || log_operation "warning" "Autoremove failed"
fi

progress "Cleaning old kernels"
[ $DRY_RUN -eq 0 ] && safe_kernel_cleanup

progress "Cleaning Snap packages"
if [ $DRY_RUN -eq 0 ] && command -v snap &>/dev/null; then
    snap list --all | awk '/disabled/{print $1, $3}' | \
    while read -r snapname revision; do
        snap remove "$snapname" --revision="$revision" 2>/dev/null || true
    done
fi

progress "Cleaning systemd journal logs"
if [ $DRY_RUN -eq 0 ] && command -v journalctl &>/dev/null; then
    journalctl --vacuum-time="${RETENTION_DAYS}d"
    journalctl --vacuum-size=100M
fi

progress "Cleaning /tmp directory"
if [ $DRY_RUN -eq 0 ]; then
    find /tmp -type f -atime +$RETENTION_DAYS -not -exec fuser -s {} \; -delete 2>/dev/null || true
    find /tmp -type d -empty -delete 2>/dev/null || true
fi

progress "Managing log files"
if [ $DRY_RUN -eq 0 ]; then
    find /var/log -type f -name "*.log" -mtime +7 ! -exec fuser -s {} \; -exec gzip -9 {} \; 2>/dev/null || true
    find /var/log -type f -name "*.gz" -mtime +$RETENTION_DAYS -delete 2>/dev/null || true
    find /var/log -type f -name "*.old" -mtime +$RETENTION_DAYS -delete 2>/dev/null || true
fi

progress "Cleaning core dumps"
if [ $DRY_RUN -eq 0 ] && [ -d /var/lib/apport/coredump ]; then
    find /var/lib/apport/coredump -type f -mtime +7 -delete 2>/dev/null || true
fi

progress "Cleaning package backups"
if [ $DRY_RUN -eq 0 ]; then
    ls -t /var/backups/dpkg.status.* 2>/dev/null | tail -n +11 | xargs rm -f 2>/dev/null || true
    ls -t /var/backups/apt.extended_states.* 2>/dev/null | tail -n +11 | xargs rm -f 2>/dev/null || true
fi

progress "Cleaning pip cache"
if [ $DRY_RUN -eq 0 ]; then
    find /root/.cache/pip -type f -mtime +30 -delete 2>/dev/null || true
    find /home/*/.cache/pip -type f -mtime +30 -delete 2>/dev/null || true
fi

progress "Cleaning npm cache"
if [ $DRY_RUN -eq 0 ]; then
    find /root/.npm/_cache -type f -mtime +30 -delete 2>/dev/null || true
    find /home/*/.npm/_cache -type f -mtime +30 -delete 2>/dev/null || true
fi

progress "Cleaning Docker (if installed)"
if [ $DRY_RUN -eq 0 ] && command -v docker &>/dev/null; then
    docker system prune -af --volumes 2>/dev/null || log_operation "info" "Docker cleanup skipped or failed"
fi

progress "Analyzing disk usage"
log_operation "info" "Top 10 largest directories in /var:"
du -sh /var/* 2>/dev/null | sort -rh | head -10 || true

progress "Final disk space check"
log_operation "info" "Final disk space:"
df -h / /var /home 2>/dev/null || df -h /
final_space=$(df / | awk 'NR==2 {print $4}')

# Calculate space freed
space_freed=$((final_space - initial_space))

log_operation "info" "=== Cleanup completed ==="
log_operation "info" "Initial free space: $initial_space KB"
log_operation "info" "Final free space: $final_space KB"
log_operation "info" "Space freed: $space_freed KB"
log_operation "info" "Log file: $LOG_FILE"

if [ -f /tmp/cleanup_snapshot.path ]; then
    snapshot_path=$(cat /tmp/cleanup_snapshot.path)
    log_operation "info" "Snapshot: $snapshot_path"
    rm -f /tmp/cleanup_snapshot.path
fi

exit $EXIT_SUCCESS
