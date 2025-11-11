#!/usr/bin/env bash

# Ubuntu Desktop Cleanup Script - Optimized for Desktop Environments
# This script performs comprehensive system cleanup for Ubuntu desktop systems
# Features user-friendly prompts and desktop-specific cleanup operations
#
# Features:
# - Interactive prompts with sensible timeouts
# - Desktop application cache cleaning (browsers, IDEs, etc.)
# - Thumbnail and media cache management
# - Protected directory exclusions
# - Safe kernel retention (N-1 policy)
# - User and system cache cleanup

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

# Configuration variables
CONFIG_FILE="${HOME}/.config/ubuntu_cleanup_desktop.conf"
LOG_DIR="${HOME}/.local/share/ubuntu_cleanup"
LOG_FILE="${LOG_DIR}/cleanup_$(date +%Y%m%d_%H%M%S).log"
LOCK_FILE="/tmp/ubuntu_cleanup_desktop_${USER}.lock"
LOCK_FD=200
DRY_RUN=0
VERBOSE=0
TIMEOUT_DURATION=60
PARALLEL_JOBS=2
MAX_RESOURCE_USAGE=50
RETENTION_DAYS=7
CACHE_AGE_DAYS=3
THUMBNAIL_AGE_DAYS=30
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
    "Documents"
    "Pictures"
    "Videos"
    "Music"
    "Downloads"
    "Desktop"
    "Projects"
    "workspace"
    ".ssh"
    ".gnupg"
)

# Logging function
log_operation() {
    local severity=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    echo "[$timestamp] [$severity] $message"

    if command -v logger &>/dev/null; then
        logger -t ubuntu_cleanup_desktop -p "user.$severity" "$message"
    fi
}

# Cleanup handler
cleanup_on_error() {
    local exit_code=$?
    if [ $exit_code -ne 0 ]; then
        log_operation "err" "Script failed with exit code $exit_code"
        log_operation "err" "Failed command: ${BASH_COMMAND}"
    fi

    release_lock
    exit $exit_code
}

# Set trap handlers
trap cleanup_on_error ERR EXIT
trap 'log_operation "warning" "Script interrupted by user"; exit $EXIT_USER_ABORT' SIGTERM SIGINT

# Create log directory
mkdir -p "$LOG_DIR" 2>/dev/null || true

# Setup logging
exec > >(tee -a "$LOG_FILE") 2>&1

# Safe configuration loader
load_safe_config() {
    if [ ! -f "$CONFIG_FILE" ]; then
        log_operation "info" "No config file found, using defaults"
        return 0
    fi

    log_operation "info" "Loading configuration from $CONFIG_FILE"

    while IFS='=' read -r key value; do
        [[ "$key" =~ ^#.*$ || -z "$key" ]] && continue

        key=$(echo "$key" | xargs)
        value=$(echo "$value" | xargs | sed 's/^["'\'']\|["'\'']$//g')

        case "$key" in
            RETENTION_DAYS|CACHE_AGE_DAYS|THUMBNAIL_AGE_DAYS|TIMEOUT_DURATION|PARALLEL_JOBS|MAX_RESOURCE_USAGE)
                if [[ "$value" =~ ^[0-9]+$ ]] && [ "$value" -ge 1 ] && [ "$value" -le 365 ]; then
                    declare -g "$key=$value"
                    log_operation "info" "Config: $key=$value"
                fi
                ;;
            DRY_RUN|VERBOSE)
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

# APT lock checking
check_apt_lock() {
    local max_wait=300
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
        sleep 5
        waited=$((waited + 5))
    done
}

# Check for sudo privileges
check_root() {
    if [[ $EUID -eq 0 ]]; then
        HAS_ROOT=1
        log_operation "info" "Running with root privileges"
    else
        HAS_ROOT=0
        log_operation "info" "Running without root, will use sudo when needed"

        if ! sudo -n true 2>/dev/null; then
            log_operation "info" "Sudo password may be required"
        fi
    fi
}

# Run commands with privileges
run_with_privileges() {
    if [[ $HAS_ROOT -eq 1 ]]; then
        "$@"
    else
        sudo "$@"
    fi
}

# Resource limit enforcement
enforce_resource_limits() {
    renice -n 10 -p $$ >/dev/null 2>&1 || true

    if command -v ionice &>/dev/null; then
        ionice -c 3 -p $$ >/dev/null 2>&1 || true
    fi

    log_operation "info" "Resource limits enforced: nice=10, ionice=idle"
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

# User prompt with timeout
prompt_with_timeout() {
    local prompt=$1
    local timeout=$TIMEOUT_DURATION
    local response

    read -t "$timeout" -p "$prompt" response || {
        echo ""
        echo "Timeout reached, assuming 'n'"
        return 1
    }

    if [[ "$response" =~ ^[Yy]$ ]]; then
        return 0
    else
        return 1
    fi
}

# Safe removal
safe_remove() {
    local target=$1

    is_excluded "$target" && return 0
    is_safe_path "$target" || return 1
    [ ! -e "$target" ] && return 0

    if [ -d "$target" ] && [ ! -L "$target" ]; then
        log_operation "info" "Removing directory contents: $target"
        rm -rf "${target:?}"/* 2>/dev/null || true
    else
        log_operation "info" "Removing: $target"
        rm -f "$target" 2>/dev/null || true
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

# Safe kernel cleanup
safe_kernel_cleanup() {
    local current_kernel=$(uname -r)
    local installed_kernels
    installed_kernels=$(dpkg -l | grep -E '^ii.*linux-image-[0-9]' | awk '{print $2}' | grep -v "linux-image-generic" || true)
    local kernel_count=$(echo "$installed_kernels" | grep -v '^$' | wc -l)

    log_operation "info" "Current kernel: $current_kernel"
    log_operation "info" "Installed kernels: $kernel_count"

    if [ $kernel_count -le 2 ]; then
        log_operation "info" "Only $kernel_count kernels installed. Skipping cleanup (minimum: 2)"
        return 0
    fi

    echo ""
    echo "Installed kernels:"
    echo "$installed_kernels"
    echo ""
    echo "This will keep the current kernel + 1 previous version"

    if prompt_with_timeout "Remove old kernels? (y/n): "; then
        check_apt_lock
        run_with_privileges apt-get autoremove --purge -y || log_operation "err" "Kernel cleanup failed"

        local remaining_kernels
        remaining_kernels=$(dpkg -l | grep -E '^ii.*linux-image-[0-9]' | awk '{print $2}' | grep -v "linux-image-generic" | wc -l)

        if [ $remaining_kernels -lt 2 ]; then
            log_operation "err" "CRITICAL: Less than 2 kernels remaining!"
            return 1
        fi

        log_operation "info" "Remaining kernels: $remaining_kernels"
    fi
}

# Calculate directory size
get_dir_size() {
    local dir=$1
    [ -d "$dir" ] && du -sh "$dir" 2>/dev/null | cut -f1 || echo "0"
}

# Check dependencies
check_dependencies() {
    local missing_tools=()

    for tool in apt-get find grep awk bc; do
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
    df -h / /home
    initial_space=$(df / | awk 'NR==2 {print $4}')
}

# Parse command line options
while getopts "dnvt:c:" opt; do
    case $opt in
        d|n) DRY_RUN=1 ;;
        v) VERBOSE=1 ;;
        t) TIMEOUT_DURATION=$OPTARG ;;
        c) CONFIG_FILE=$OPTARG ;;
        *) echo "Usage: $0 [-d|-n] [-v] [-t timeout] [-c config_file]" >&2
           echo "  -d,-n  Dry run (show what would be done)"
           echo "  -v     Verbose output"
           echo "  -t     Timeout for prompts in seconds (default: 60)"
           echo "  -c     Config file path"
           exit 1 ;;
    esac
done

# Progress tracking
total_steps=22
current_step=0

progress() {
    current_step=$((current_step + 1))
    percentage=$((current_step * 100 / total_steps))
    log_operation "info" "[$current_step/$total_steps - $percentage%] $1"
}

# Main execution
echo "=========================================="
echo "  Ubuntu Desktop Cleanup Script"
echo "=========================================="
echo ""

log_operation "info" "=== Ubuntu Desktop Cleanup Started ==="
log_operation "info" "User: $USER | Hostname: $(hostname)"

acquire_lock
load_safe_config
check_dependencies
check_root
enforce_resource_limits
record_disk_space

log_operation "info" "Protected patterns: ${EXCLUDED_PATTERNS[*]}"
[ $DRY_RUN -eq 1 ] && log_operation "warning" "DRY RUN MODE - No changes will be made"

# Confirmation prompt
if [ $DRY_RUN -eq 0 ]; then
    echo "This script will clean up temporary files, caches, and unused packages."
    echo "Your documents and important files are protected."
    echo ""
    if ! prompt_with_timeout "Proceed with cleanup? (y/n): "; then
        log_operation "warning" "User cancelled cleanup"
        exit $EXIT_USER_ABORT
    fi
    echo ""
fi

# Cleanup operations
progress "Updating package list"
if [ $DRY_RUN -eq 0 ]; then
    check_apt_lock
    run_with_privileges apt-get update -qq || log_operation "warning" "Package list update failed"
fi

progress "Clearing user cache (excluding protected folders)"
if [ $DRY_RUN -eq 0 ]; then
    cache_before=$(get_dir_size ~/.cache)
    log_operation "info" "Cache size before: $cache_before"

    safe_find ~/.cache -type f -mtime +$CACHE_AGE_DAYS -delete
    safe_find ~/.cache -type d -empty -delete

    cache_after=$(get_dir_size ~/.cache)
    log_operation "info" "Cache size after: $cache_after"
fi

progress "Cleaning APT cache"
[ $DRY_RUN -eq 0 ] && run_with_privileges apt-get clean

progress "Removing obsolete packages"
[ $DRY_RUN -eq 0 ] && run_with_privileges apt-get autoclean -y

progress "Removing unused packages"
if [ $DRY_RUN -eq 0 ]; then
    check_apt_lock
    echo ""
    echo "Packages that will be removed:"
    run_with_privileges apt-get autoremove -y --dry-run | grep "^Remv" || echo "  None"
    echo ""

    if prompt_with_timeout "Remove these packages? (y/n): "; then
        run_with_privileges apt-get autoremove -y
    fi
fi

progress "Checking old kernel versions"
[ $DRY_RUN -eq 0 ] && safe_kernel_cleanup

progress "Cleaning Snap packages"
if [ $DRY_RUN -eq 0 ] && command -v snap &>/dev/null; then
    run_with_privileges snap list --all | awk '/disabled/{print $1, $3}' | \
    while read -r snapname revision; do
        log_operation "info" "Removing $snapname revision $revision"
        run_with_privileges snap remove "$snapname" --revision="$revision" 2>/dev/null || true
    done
fi

progress "Cleaning Flatpak"
if [ $DRY_RUN -eq 0 ] && command -v flatpak &>/dev/null; then
    flatpak uninstall --unused -y 2>/dev/null || true
fi

progress "Clearing old thumbnails"
if [ $DRY_RUN -eq 0 ]; then
    thumb_before=$(get_dir_size ~/.cache/thumbnails)
    log_operation "info" "Thumbnails before: $thumb_before"

    safe_find ~/.cache/thumbnails -type f -mtime +$THUMBNAIL_AGE_DAYS -delete

    thumb_after=$(get_dir_size ~/.cache/thumbnails)
    log_operation "info" "Thumbnails after: $thumb_after"
fi

progress "Cleaning systemd journal logs"
if [ $DRY_RUN -eq 0 ] && command -v journalctl &>/dev/null; then
    run_with_privileges journalctl --vacuum-time="${RETENTION_DAYS}d"
    run_with_privileges journalctl --vacuum-size=100M
fi

progress "Cleaning browser caches"
if [ $DRY_RUN -eq 0 ]; then
    # Firefox
    if [ -d ~/.mozilla/firefox ]; then
        firefox_before=$(get_dir_size ~/.mozilla/firefox)
        safe_find ~/.mozilla/firefox -name "*Cache*" -type d -mtime +7 -exec rm -rf {} + 2>/dev/null || true
        firefox_after=$(get_dir_size ~/.mozilla/firefox)
        log_operation "info" "Firefox: $firefox_before → $firefox_after"
    fi

    # Chrome/Chromium
    for browser in "google-chrome" "chromium"; do
        browser_dir=~/.config/$browser
        if [ -d "$browser_dir" ]; then
            browser_before=$(get_dir_size "$browser_dir")
            safe_find "$browser_dir" -name "Cache" -type d -mtime +7 -exec rm -rf {} + 2>/dev/null || true
            safe_find "$browser_dir" -name "Code Cache" -type d -mtime +7 -exec rm -rf {} + 2>/dev/null || true
            browser_after=$(get_dir_size "$browser_dir")
            log_operation "info" "$browser: $browser_before → $browser_after"
        fi
    done

    # Brave
    if [ -d ~/.config/BraveSoftware ]; then
        safe_find ~/.config/BraveSoftware -name "Cache" -type d -mtime +7 -exec rm -rf {} + 2>/dev/null || true
    fi
fi

progress "Cleaning VSCode cache"
if [ $DRY_RUN -eq 0 ] && [ -d ~/.config/Code ]; then
    safe_find ~/.config/Code/Cache -type f -mtime +30 -delete 2>/dev/null || true
    safe_find ~/.config/Code/CachedData -type f -mtime +30 -delete 2>/dev/null || true
fi

progress "Cleaning pip cache"
if [ $DRY_RUN -eq 0 ] && [ -d ~/.cache/pip ]; then
    pip_before=$(get_dir_size ~/.cache/pip)
    safe_find ~/.cache/pip -type f -mtime +30 -delete
    pip_after=$(get_dir_size ~/.cache/pip)
    log_operation "info" "Pip cache: $pip_before → $pip_after"
fi

progress "Cleaning npm cache"
if [ $DRY_RUN -eq 0 ] && [ -d ~/.npm ]; then
    npm_before=$(get_dir_size ~/.npm)
    safe_find ~/.npm/_cache -type f -mtime +30 -delete 2>/dev/null || true
    npm_after=$(get_dir_size ~/.npm)
    log_operation "info" "npm cache: $npm_before → $npm_after"
fi

progress "Cleaning Trash"
if [ $DRY_RUN -eq 0 ]; then
    trash_before=$(get_dir_size ~/.local/share/Trash)
    
    echo ""
    if prompt_with_timeout "Empty Trash? (y/n): "; then
        rm -rf ~/.local/share/Trash/files/* 2>/dev/null || true
        rm -rf ~/.local/share/Trash/info/* 2>/dev/null || true
        trash_after=$(get_dir_size ~/.local/share/Trash)
        log_operation "info" "Trash: $trash_before → $trash_after"
    else
        log_operation "info" "Trash not emptied (user choice)"
    fi
fi

progress "Cleaning Wine prefixes"
if [ $DRY_RUN -eq 0 ] && [ -d ~/.wine ]; then
    safe_find ~/.wine -name "*.log" -mtime +30 -delete 2>/dev/null || true
fi

progress "Cleaning Steam shader cache"
if [ $DRY_RUN -eq 0 ] && [ -d ~/.steam ]; then
    safe_find ~/.steam -path "*/shadercache/*" -type f -mtime +60 -delete 2>/dev/null || true
fi

progress "Cleaning GIMP cache"
if [ $DRY_RUN -eq 0 ] && [ -d ~/.config/GIMP ]; then
    safe_find ~/.config/GIMP -name "tmp" -type d -exec rm -rf {} + 2>/dev/null || true
fi

progress "Analyzing disk usage"
echo ""
echo "Top 10 largest directories in your home:"
du -sh ~/.* 2>/dev/null | sort -rh | head -10 || true
echo ""

progress "Final disk space check"
log_operation "info" "Final disk space:"
df -h / /home
final_space=$(df / | awk 'NR==2 {print $4}')

# Calculate results
space_freed=$((final_space - initial_space))

echo ""
echo "=========================================="
echo "  Cleanup Summary"
echo "=========================================="
echo "Initial free space: $initial_space KB"
echo "Final free space: $final_space KB"
echo "Space freed: $space_freed KB"
echo ""
echo "Log file: $LOG_FILE"
echo "=========================================="

log_operation "info" "=== Cleanup completed successfully ==="

exit $EXIT_SUCCESS
