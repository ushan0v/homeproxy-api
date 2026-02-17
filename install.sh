#!/bin/sh
set -eu

APP_NAME='homeproxy-api'
SERVICE_NAME='homeproxy-api'
UCI_CONFIG='homeproxy-api'

: "${HPA_REPO_OWNER:=ushan0v}"
: "${HPA_REPO_NAME:=homeproxy-api}"
: "${HPA_REPO_REF:=main}"
: "${HPA_BASE_URL:=https://raw.githubusercontent.com/${HPA_REPO_OWNER}/${HPA_REPO_NAME}/${HPA_REPO_REF}}"

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
TMP_DIR="$(mktemp -d /tmp/homeproxy-api.XXXXXX)"

cleanup() {
	rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

log() {
	printf '[INFO] %s\n' "$*"
}

warn() {
	printf '[WARN] %s\n' "$*" >&2
}

die() {
	printf '[ERROR] %s\n' "$*" >&2
	exit 1
}

need_root() {
	if [ "$(id -u)" != '0' ]; then
		die 'run as root'
	fi
}

have_cmd() {
	command -v "$1" >/dev/null 2>&1
}

put_file() {
	src="$1"
	dst="$2"
	mode="$3"
	mkdir -p "$(dirname "$dst")"
	if have_cmd install; then
		install -m "$mode" "$src" "$dst"
	else
		cp "$src" "$dst"
		chmod "$mode" "$dst"
	fi
}

fetch_url() {
	url="$1"
	out="$2"
	if have_cmd curl; then
		curl -fsSL "$url" -o "$out"
	elif have_cmd uclient-fetch; then
		uclient-fetch -q -O "$out" "$url"
	elif have_cmd wget; then
		wget -q -O "$out" "$url"
	else
		die 'need one of: curl, uclient-fetch, wget'
	fi
}

copy_or_fetch() {
	rel="$1"
	out="$2"
	local_src="$SCRIPT_DIR/$rel"
	if [ -f "$local_src" ]; then
		cp "$local_src" "$out"
		return 0
	fi
	fetch_url "$HPA_BASE_URL/$rel" "$out"
}

check_dependencies() {
	[ -x /etc/init.d/homeproxy ] || die 'homeproxy service is not installed (/etc/init.d/homeproxy not found)'
	uci -q show homeproxy >/dev/null 2>&1 || die 'homeproxy UCI config is missing'
	if ! [ -x /usr/bin/sing-box ] && ! have_cmd sing-box; then
		die 'sing-box is not installed'
	fi
}

detect_targets() {
	machine="$(uname -m 2>/dev/null || echo unknown)"
	opkg_arch="$(opkg print-architecture 2>/dev/null | awk '{print $2}' | tr '\n' ' ')"

	# OpenWrt package arch is the most reliable source (especially for mips/mipsel).
	if echo "$opkg_arch" | grep -Eq 'mipsel|mipsle'; then
		echo "mipsle-softfloat mipsle-hardfloat mips-softfloat mips-hardfloat"
		return 0
	fi
	if echo "$opkg_arch" | grep -Eq 'mips_'; then
		echo "mips-softfloat mips-hardfloat mipsle-softfloat mipsle-hardfloat"
		return 0
	fi
	if echo "$opkg_arch" | grep -Eq 'aarch64|arm64'; then
		echo "arm64"
		return 0
	fi
	if echo "$opkg_arch" | grep -Eq 'arm_cortex-a|armv7|armhf'; then
		echo "armv7 armv6 armv5"
		return 0
	fi
	if echo "$opkg_arch" | grep -Eq 'arm_arm|armv6'; then
		echo "armv6 armv5"
		return 0
	fi
	if echo "$opkg_arch" | grep -Eq 'x86_64'; then
		echo "amd64"
		return 0
	fi
	if echo "$opkg_arch" | grep -Eq 'i386|i686|x86'; then
		echo "386"
		return 0
	fi
	if echo "$opkg_arch" | grep -Eq 'riscv64'; then
		echo "riscv64"
		return 0
	fi

	case "$machine" in
		x86_64|amd64) echo "amd64" ;;
		i386|i486|i586|i686|x86) echo "386" ;;
		aarch64|arm64|armv8*) echo "arm64" ;;
		armv7*|armhf) echo "armv7 armv6 armv5" ;;
		armv6*) echo "armv6 armv5" ;;
		armv5*|arm) echo "armv5" ;;
		mipsel|mipsle) echo "mipsle-softfloat mipsle-hardfloat mips-softfloat mips-hardfloat" ;;
		mips) echo "mips-softfloat mips-hardfloat mipsle-softfloat mipsle-hardfloat" ;;
		mips64el|mips64le) echo "mips64le" ;;
		mips64) echo "mips64" ;;
		riscv64) echo "riscv64" ;;
		*)
			echo "amd64 arm64 armv7 mipsle-softfloat mips-softfloat"
		;;
	esac
}

binary_compatible() {
	bin="$1"
	# Run help command and detect exec-format style failures.
	# Go flag parser may return non-zero; that's fine as long as binary is executable.
	out="$("$bin" -h 2>&1 || true)"
	echo "$out" | grep -Eq 'exec format error|syntax error|not found' && return 1
	return 0
}

download_binary() {
	targets="$(detect_targets)"
	log "detected candidates: $targets"

	tmp_bin="$TMP_DIR/$APP_NAME"
	for target in $targets; do
		rel="dist/${APP_NAME}-linux-${target}"
		if copy_or_fetch "$rel" "$tmp_bin" 2>/dev/null; then
			chmod 0755 "$tmp_bin"
			if ! binary_compatible "$tmp_bin"; then
				warn "binary ${target} is not compatible on this device, trying next"
				continue
			fi
			put_file "$tmp_bin" "/usr/bin/$APP_NAME" 0755
			log "installed binary: /usr/bin/$APP_NAME (${target})"
			return 0
		fi
	done
	die "no compatible binary found in repository (tried: $targets)"
}

install_file() {
	rel="$1"
	dst="$2"
	mode="$3"
	tmp_file="$TMP_DIR/$(basename "$rel")"
	copy_or_fetch "$rel" "$tmp_file"
	put_file "$tmp_file" "$dst" "$mode"
}

install_luci_files() {
	install_file "luci/etc/init.d/homeproxy-api" "/etc/init.d/homeproxy-api" 0755
	if [ ! -f /etc/config/homeproxy-api ]; then
		install_file "luci/etc/config/homeproxy-api" "/etc/config/homeproxy-api" 0644
	else
		log "keeping existing /etc/config/homeproxy-api"
	fi
	install_file "luci/usr/share/luci/menu.d/luci-app-homeproxy-api.json" "/usr/share/luci/menu.d/luci-app-homeproxy-api.json" 0644
	install_file "luci/usr/share/rpcd/acl.d/luci-app-homeproxy-api.json" "/usr/share/rpcd/acl.d/luci-app-homeproxy-api.json" 0644
	install_file "luci/www/luci-static/resources/view/services/homeproxy-api.js" "/www/luci-static/resources/view/services/homeproxy-api.js" 0644
}

ensure_service_config() {
	get_uci() {
		uci -q get "$1" 2>/dev/null || true
	}

	uci -q get "$UCI_CONFIG.main" >/dev/null 2>&1 || {
		uci -q batch <<-'EOF'
			set homeproxy-api.main=main
			set homeproxy-api.main.enabled='1'
			set homeproxy-api.main.autostart='1'
			set homeproxy-api.main.bin='/usr/bin/homeproxy-api'
			set homeproxy-api.main.listen='0.0.0.0:7878'
			set homeproxy-api.main.port=''
			set homeproxy-api.main.mode='default'
			set homeproxy-api.main.db='/var/run/homeproxy/cache.db'
			set homeproxy-api.main.config='/var/run/homeproxy/sing-box-c.json'
			set homeproxy-api.main.allow_origin='*'
			set homeproxy-api.main.clash_api_port='9090'
		EOF
	}

	uci -q set "$UCI_CONFIG.main.enabled=1"
	uci -q set "$UCI_CONFIG.main.autostart=1"
	uci -q set "$UCI_CONFIG.main.bin=/usr/bin/homeproxy-api"
	[ -n "$(get_uci "$UCI_CONFIG.main.mode")" ] || uci -q set "$UCI_CONFIG.main.mode=default"
	[ -n "$(get_uci "$UCI_CONFIG.main.db")" ] || uci -q set "$UCI_CONFIG.main.db=/var/run/homeproxy/cache.db"
	[ -n "$(get_uci "$UCI_CONFIG.main.config")" ] || uci -q set "$UCI_CONFIG.main.config=/var/run/homeproxy/sing-box-c.json"
	[ -n "$(get_uci "$UCI_CONFIG.main.allow_origin")" ] || uci -q set "$UCI_CONFIG.main.allow_origin=*"
	[ -n "$(get_uci "$UCI_CONFIG.main.clash_api_port")" ] || uci -q set "$UCI_CONFIG.main.clash_api_port=9090"
	uci -q commit "$UCI_CONFIG"
}

patch_generate_client_for_clash_api() {
	gen_client='/etc/homeproxy/scripts/generate_client.uc'
	[ -s "$gen_client" ] || return 0

	if ! grep -q "clash_api_enabled" "$gen_client"; then
		sed -i "/const mixed_port/i\
const clash_api_enabled = uci.get(uciconfig, ucicontrol, 'clash_api_enabled') || '0',\
      clash_api_listen = uci.get(uciconfig, ucicontrol, 'clash_api_listen') || '0.0.0.0:9090',\
      clash_api_secret = uci.get(uciconfig, ucicontrol, 'clash_api_secret'),\
      clash_api_mode = uci.get(uciconfig, ucicontrol, 'clash_api_mode') || 'Rule';\
" "$gen_client"
	fi

	if ! grep -q "config.experimental.clash_api" "$gen_client"; then
		sed -i "/\/\* Experimental end \*\//i\
	if (strToBool(clash_api_enabled)) {\
		config.experimental.clash_api = {\
			external_controller: clash_api_listen,\
			secret: clash_api_secret,\
			default_mode: clash_api_mode,\
		};\
	}\
" "$gen_client"
	fi
}

enable_clash_api() {
	port="$(uci -q get $UCI_CONFIG.main.clash_api_port || echo 9090)"
	case "$port" in
		''|*[!0-9]*) port='9090' ;;
	esac
	listen_addr="0.0.0.0:$port"

	patch_generate_client_for_clash_api || true

	uci -q get homeproxy.control >/dev/null 2>&1 || {
		warn 'homeproxy.control section not found; clash_api was not changed'
		return 0
	}

	uci -q set homeproxy.control.clash_api_enabled='1'
	uci -q set homeproxy.control.clash_api_listen="$listen_addr"
	uci -q set homeproxy.control.clash_api_secret=''
	uci -q set homeproxy.control.clash_api_mode='Rule'
	uci -q commit homeproxy

	/etc/init.d/homeproxy restart >/dev/null 2>&1 || warn 'failed to restart homeproxy'
}

start_services() {
	/etc/init.d/homeproxy-api enable >/dev/null 2>&1 || true
	/etc/init.d/homeproxy-api restart >/dev/null 2>&1 || die 'failed to start homeproxy-api'
	/etc/init.d/rpcd restart >/dev/null 2>&1 || true
}

main() {
	need_root
	check_dependencies
	log "repository source: $HPA_BASE_URL"
	download_binary
	install_luci_files
	ensure_service_config
	enable_clash_api
	start_services
	log "HomeProxy API installed successfully"
	log "LuCI page: Services -> HomeProxy API"
	log "HTTP endpoint: http://<router-ip>:$(uci -q get homeproxy-api.main.port || echo 7878)/check"
}

main "$@"
