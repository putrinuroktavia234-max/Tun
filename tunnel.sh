#!/bin/bash

#================================================
# Youzin Crabz Tunel - FINAL STABLE VERSION
# The Professor
# GitHub: putrinuroktavia234-max/Tunnel
#
# ARSITEKTUR PORT (TIDAK TABRAKAN):
# ┌─────────────────────────────────────────┐
# │  SSH OpenSSH    : 22                    │
# │  SSH Dropbear   : 222                   │
# │  Nginx NonTLS   : 80  → proxy ke Xray   │
# │  Nginx Download : 81                    │
# │  HAProxy TLS    : 443 → WS  ke 8443     │
# │  HAProxy TLS    : 443 → gRPC ke 8444    │
# │                                         │
# │  Xray VMess WS TLS    : 8443 (via 443)  │
# │  Xray VMess WS NonTLS : 8080 (via 80)   │
# │  Xray VLess WS TLS    : 8442 (via 443)  │
# │  Xray VLess WS NonTLS : 8081 (via 80)   │
# │  Xray Trojan WS TLS   : 8441 (via 443)  │
# │  Xray gRPC TLS        : 8444 (via 443)  │
# │                                         │
# │  BadVPN UDP     : 7100-7300             │
# └─────────────────────────────────────────┘
#
# Output akun include:
# - Link vmess:// vless:// trojan://
# - Format Clash YAML siap pakai
# - Download link port 81
#================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
WHITE='\033[1;37m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

DOMAIN=""
DOMAIN_FILE="/root/domain"
AKUN_DIR="/root/akun"
XRAY_CONFIG="/usr/local/etc/xray/config.json"
SCRIPT_VERSION="4.0.0"
SCRIPT_AUTHOR="The Professor"
GITHUB_USER="putrinuroktavia234-max"
GITHUB_REPO="Tunnel"
GITHUB_BRANCH="main"
SCRIPT_URL="https://raw.githubusercontent.com/${GITHUB_USER}/${GITHUB_REPO}/${GITHUB_BRANCH}/tunnel.sh"
VERSION_URL="https://raw.githubusercontent.com/${GITHUB_USER}/${GITHUB_REPO}/${GITHUB_BRANCH}/version"
SCRIPT_PATH="/root/tunnel.sh"
BACKUP_PATH="/root/tunnel.sh.bak"
PUBLIC_HTML="/var/www/html"
BOT_TOKEN_FILE="/root/.bot_token"
CHAT_ID_FILE="/root/.chat_id"
ORDER_DIR="/root/orders"
PAYMENT_FILE="/root/.payment_info"
DOMAIN_TYPE_FILE="/root/.domain_type"

#================================================
# PORT VARIABLES - ARSITEKTUR BARU ANTI TABRAKAN
#================================================
SSH_PORT="22"
DROPBEAR_PORT="222"
NGINX_PORT="80"
NGINX_DL_PORT="81"
HAPROXY_PORT="443"

# Port internal Xray (tidak expose langsung ke internet)
# Semua TLS dikumpulkan di 1 port, dibedakan via PATH
XRAY_TLS_PORT="10443"      # Semua protokol WS+TLS masuk sini
XRAY_NONTLS_PORT="10080"   # Semua protokol WS NonTLS masuk sini
XRAY_GRPC_PORT="10444"     # Khusus gRPC TLS

BADVPN_RANGE="7100-7300"
PRICE_MONTHLY="10000"

#================================================
# BOX DRAWING
#================================================

str_len() {
    local s
    s=$(printf "%b" "$1" | sed 's/\x1b\[[0-9;]*m//g')
    echo ${#s}
}

get_width() {
    local tw
    tw=$(tput cols 2>/dev/null || echo 73)
    if   [ "$tw" -lt 55 ]; then echo 55
    elif [ "$tw" -gt 75 ]; then echo 75
    else echo "$tw"
    fi
}

_box_top() {
    local inner=$(( $1 - 2 ))
    printf "${CYAN}╔"; printf '═%.0s' $(seq 1 $inner); printf "╗${NC}\n"
}
_box_bottom() {
    local inner=$(( $1 - 2 ))
    printf "${CYAN}╚"; printf '═%.0s' $(seq 1 $inner); printf "╝${NC}\n"
}
_box_divider() {
    local inner=$(( $1 - 2 ))
    printf "${CYAN}╠"; printf '═%.0s' $(seq 1 $inner); printf "╣${NC}\n"
}
_box_center() {
    local width=$1 text="$2"
    local inner=$(( width - 2 ))
    local tlen; tlen=$(str_len "$text")
    local pad=$(( (inner - tlen) / 2 ))
    local pad_r=$(( inner - tlen - pad ))
    printf "${CYAN}║${NC}"
    printf "%${pad}s" ""
    printf "%b" "$text"
    printf "%${pad_r}s" ""
    printf "${CYAN}║${NC}\n"
}
_box_left() {
    local width=$1 text="$2"
    local inner=$(( width - 4 ))
    local tlen; tlen=$(str_len "$text")
    local pad_r=$(( inner - tlen ))
    [ $pad_r -lt 0 ] && pad_r=0
    printf "${CYAN}║${NC}  "
    printf "%b" "$text"
    printf "%${pad_r}s" ""
    printf "  ${CYAN}║${NC}\n"
}
_box_two() {
    local width=$1 left="$2" right="$3"
    local inner=$(( width - 4 ))
    local half=$(( inner / 2 ))
    local llen; llen=$(str_len "$left")
    local rlen; rlen=$(str_len "$right")
    local lpad_r=$(( half - llen ))
    local rpad_r=$(( inner - half - rlen ))
    [ $lpad_r -lt 0 ] && lpad_r=0
    [ $rpad_r -lt 0 ] && rpad_r=0
    printf "${CYAN}║${NC}  "
    printf "%b" "$left"
    printf "%${lpad_r}s" ""
    printf "%b" "$right"
    printf "%${rpad_r}s" ""
    printf "  ${CYAN}║${NC}\n"
}
_ram_bar() {
    local pct=$1 bar_len=10 filled empty bar=""
    filled=$(( pct * bar_len / 100 ))
    empty=$(( bar_len - filled ))
    for i in $(seq 1 $filled); do bar="${bar}█"; done
    for i in $(seq 1 $empty); do bar="${bar}░"; done
    echo "$bar"
}
_svc_status() {
    if systemctl is-active --quiet "$1" 2>/dev/null; then
        echo -e "${GREEN}●${NC} ONLINE "
    else
        echo -e "${RED}○${NC} OFFLINE"
    fi
}

#================================================
# ANIMASI
#================================================

spinner_frames=('⣾' '⣽' '⣻' '⢿' '⡿' '⣟' '⣯' '⣷')

animated_loading() {
    local msg="$1"
    local duration="${2:-2}"
    local i=0
    local end=$((SECONDS + duration))
    while [[ $SECONDS -lt $end ]]; do
        local frame="${spinner_frames[$((i % 8))]}"
        local dots=""
        case $((i % 4)) in
            0) dots="   " ;;
            1) dots=".  " ;;
            2) dots=".. " ;;
            3) dots="..." ;;
        esac
        printf "\r  ${CYAN}${frame}${NC} ${WHITE}${msg}${NC}${YELLOW}${dots}${NC}   "
        sleep 0.1
        ((i++))
    done
    printf "\r  ${GREEN}✔${NC} ${WHITE}${msg}${NC} ${GREEN}[SELESAI]${NC}           \n"
}

done_msg() { printf "  ${GREEN}✔${NC} ${WHITE}%-42s${NC}\n" "$1"; }
fail_msg() { printf "  ${RED}✘${NC} ${WHITE}%-42s${NC}\n" "$1"; }
info_msg() { printf "  ${CYAN}◈${NC} %s\n" "$1"; }

#================================================
# BANNER
#================================================

show_install_banner() {
    clear
    echo ""
    echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${YELLOW}  ✦ ✦ ✦  Script Auto Install by Youzin Crabz  ✦ ✦ ✦${NC}"
    echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "  ${WHITE}  Youzin Crabz Tunel v${SCRIPT_VERSION}${NC}"
    echo -e "      ${DIM}  The Professor${NC}"
    echo ""
    echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

#================================================
# UTILITY
#================================================

check_status() {
    systemctl is-active --quiet "$1" 2>/dev/null && echo "ON" || echo "OFF"
}

get_ip() {
    local ip
    for url in \
        "https://ifconfig.me" \
        "https://ipinfo.io/ip" \
        "https://api.ipify.org" \
        "https://checkip.amazonaws.com"; do
        ip=$(curl -s --max-time 3 "$url" 2>/dev/null)
        if [[ -n "$ip" ]] && ! echo "$ip" | grep -q "error\|reset\|refused\|<"; then
            echo "$ip"; return
        fi
    done
    ip=$(ip route get 8.8.8.8 2>/dev/null | awk '{print $7; exit}')
    echo "${ip:-N/A}"
}

send_telegram_admin() {
    [[ ! -f "$BOT_TOKEN_FILE" ]] && return
    [[ ! -f "$CHAT_ID_FILE" ]]   && return
    local token chatid
    token=$(cat "$BOT_TOKEN_FILE")
    chatid=$(cat "$CHAT_ID_FILE")
    curl -s -X POST \
        "https://api.telegram.org/bot${token}/sendMessage" \
        -d chat_id="$chatid" \
        -d text="$1" \
        -d parse_mode="HTML" \
        --max-time 10 >/dev/null 2>&1
}

print_menu_header() {
    local title="$1"
    local W; W=$(get_width)
    echo ""
    _box_top $W
    _box_center $W "${YELLOW}${BOLD}${title}${NC}"
    _box_bottom $W
    echo ""
}

#================================================
# SHOW SYSTEM INFO
#================================================

show_system_info() {
    clear

    [[ -f "$DOMAIN_FILE" ]] && \
        DOMAIN=$(tr -d '\n\r' < "$DOMAIN_FILE" | xargs)

    local os_name="Unknown"
    [[ -f /etc/os-release ]] && {
        source /etc/os-release
        os_name="${PRETTY_NAME}"
    }

    local ip_vps ram_used ram_total ram_pct cpu uptime_str ssl_type svc_running svc_total

    ip_vps=$(get_ip)
    ram_used=$(free -m | awk '/Mem:/{print $3}')
    ram_total=$(free -m | awk '/Mem:/{print $2}')
    ram_pct=$(awk "BEGIN {printf \"%.0f\", ($ram_used/$ram_total)*100}")
    cpu=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1 2>/dev/null || echo "0")
    uptime_str=$(uptime -p 2>/dev/null | sed 's/up //' | sed 's/ hours\?/h/;s/ minutes\?/m/')

    local domain_type="custom"
    [[ -f "$DOMAIN_TYPE_FILE" ]] && domain_type=$(cat "$DOMAIN_TYPE_FILE")

    if [[ "$domain_type" == "custom" ]]; then
        if [[ -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]]; then
            ssl_type="LetsEncrypt (Active)"
        else
            ssl_type="LetsEncrypt (Warn)"
        fi
    else
        ssl_type="Self-Signed"
    fi

    local services=(xray nginx sshd haproxy dropbear udp-custom vpn-keepalive vpn-bot)
    svc_total=${#services[@]}
    svc_running=0
    for svc in "${services[@]}"; do
        systemctl is-active --quiet "$svc" 2>/dev/null && ((svc_running++))
    done

    local ssh_count vmess_count vless_count trojan_count
    ssh_count=$(ls "$AKUN_DIR"/ssh-*.txt 2>/dev/null | wc -l)
    vmess_count=$(ls "$AKUN_DIR"/vmess-*.txt 2>/dev/null | wc -l)
    vless_count=$(ls "$AKUN_DIR"/vless-*.txt 2>/dev/null | wc -l)
    trojan_count=$(ls "$AKUN_DIR"/trojan-*.txt 2>/dev/null | wc -l)

    local BAR; BAR=$(_ram_bar "$ram_pct")
    local W; W=$(get_width)

    # Header
    _box_top $W
    _box_center $W "${YELLOW}${BOLD}✦ YOUZINCRABZ PANEL v${SCRIPT_VERSION} ✦${NC}"
    _box_center $W "${CYAN}The Professor${NC}"
    _box_bottom $W
    echo ""

    # Server Info - single column
    _box_top $W
    _box_center $W "${YELLOW}${BOLD}SERVER CORE STATUS${NC}"
    _box_divider $W
    _box_left $W "IP Address : ${GREEN}${ip_vps}${NC}"
    _box_left $W "Domain     : ${GREEN}${DOMAIN:-N/A}${NC}"
    _box_left $W "OS         : ${WHITE}${os_name}${NC}"
    _box_left $W "Uptime     : ${WHITE}${uptime_str}${NC}"
    _box_left $W "CPU Load   : ${YELLOW}${cpu}%${NC}"
    _box_left $W "RAM        : ${WHITE}${ram_used}/${ram_total}MB${NC} ${CYAN}[${BAR}]${NC} ${YELLOW}${ram_pct}%${NC}"
    _box_left $W "SSL        : ${GREEN}${ssl_type}${NC}"
    _box_left $W "Services   : ${GREEN}${svc_running}/${svc_total} Running${NC}"
    _box_bottom $W
    echo ""

    # Active Accounts
    _box_top $W
    _box_center $W "${YELLOW}${BOLD}ACTIVE ACCOUNTS${NC}"
    _box_divider $W
    _box_left $W "SSH    : ${GREEN}${ssh_count}${NC}  akun"
    _box_left $W "VMess  : ${GREEN}${vmess_count}${NC}  akun"
    _box_left $W "VLess  : ${GREEN}${vless_count}${NC}  akun"
    _box_left $W "Trojan : ${GREEN}${trojan_count}${NC}  akun"
    _box_bottom $W
    echo ""

    # Network Services - single column, clean
    _box_top $W
    _box_center $W "${YELLOW}${BOLD}NETWORK SERVICES${NC}"
    _box_divider $W
    local svc_list=(
        "xray:XRAY"
        "nginx:NGINX"
        "haproxy:HAPROXY"
        "dropbear:DROPBEAR"
        "ssh:SSH"
        "udp-custom:UDP CUSTOM"
        "vpn-bot:TELEGRAM BOT"
        "vpn-keepalive:KEEPALIVE"
    )
    for item in "${svc_list[@]}"; do
        local svcname="${item%%:*}"
        local svclabel="${item##*:}"
        if systemctl is-active --quiet "$svcname" 2>/dev/null; then
            _box_left $W "${GREEN}●${NC} ${WHITE}${svclabel}${NC}"
        else
            _box_left $W "${RED}○${NC} ${WHITE}${svclabel}${NC}"
        fi
    done
    _box_bottom $W
    echo ""
}

#================================================
# SHOW MAIN MENU
#================================================

show_menu() {
    local W; W=$(get_width)

    _box_top $W
    _box_center $W "${YELLOW}${BOLD}ACCOUNT MANAGEMENT${NC}"
    _box_divider $W
    _box_left $W "[1] SSH / OpenVPN"
    _box_left $W "[2] VMess Account"
    _box_left $W "[3] VLess Account"
    _box_left $W "[4] Trojan Account"
    _box_left $W "[5] Trial Account"
    _box_left $W "[6] List All Accounts"
    _box_left $W "[7] Check Expired"
    _box_left $W "[8] Delete Expired"
    _box_bottom $W
    echo ""

    _box_top $W
    _box_center $W "${YELLOW}${BOLD}SYSTEM CONTROL${NC}"
    _box_divider $W
    _box_left $W "[9]  Telegram Bot"
    _box_left $W "[10] Change Domain"
    _box_left $W "[11] Fix SSL / Cert"
    _box_left $W "[12] Optimize VPS"
    _box_left $W "[13] Restart Services"
    _box_left $W "[14] Port Info"
    _box_left $W "[15] Speedtest VPS"
    _box_left $W "[16] Update Panel"
    _box_left $W "[17] Backup Config"
    _box_left $W "[18] Restore Config"
    _box_left $W "[19] Uninstall Panel"
    _box_divider $W
    _box_left $W "${RED}[0]  Exit Panel${NC}"
    _box_divider $W
    _box_left $W "Telegram : ${CYAN}@ridhani16${NC}"
    _box_bottom $W
    echo ""
}

#================================================
# DOMAIN SETUP
#================================================

generate_random_domain() {
    local ip_vps chars random_str
    ip_vps=$(get_ip)
    chars="abcdefghijklmnopqrstuvwxyz"
    random_str=""
    for i in {1..6}; do
        random_str+="${chars:RANDOM%26:1}"
    done
    echo "${random_str}.${ip_vps}.nip.io"
}

setup_domain() {
    clear
    print_menu_header "SETUP DOMAIN"
    echo -e "  ${WHITE}[1]${NC} Pakai domain sendiri"
    echo -e "      ${YELLOW}Contoh: vpn.example.com${NC}"
    echo -e "      ${DIM}SSL: Let's Encrypt${NC}"
    echo ""
    echo -e "  ${WHITE}[2]${NC} Generate domain otomatis"
    local preview
    preview=$(generate_random_domain)
    echo -e "      ${YELLOW}Contoh: ${preview}${NC}"
    echo -e "      ${DIM}SSL: Self-signed${NC}"
    echo ""
    read -p "  Pilih [1/2]: " domain_choice
    case $domain_choice in
        1)
            echo ""
            read -p "  Masukkan domain: " input_domain
            [[ -z "$input_domain" ]] && {
                echo -e "${RED}  ✘ Domain kosong!${NC}"
                sleep 2; setup_domain; return
            }
            DOMAIN="$input_domain"
            echo "custom" > "$DOMAIN_TYPE_FILE"
            ;;
        2)
            DOMAIN=$(generate_random_domain)
            echo "random" > "$DOMAIN_TYPE_FILE"
            echo -e "  ${GREEN}Domain: ${CYAN}${DOMAIN}${NC}"
            sleep 1
            ;;
        *)
            echo -e "  ${RED}✘ Tidak valid!${NC}"
            sleep 1; setup_domain; return
            ;;
    esac
    echo "$DOMAIN" > "$DOMAIN_FILE"
}

get_ssl_cert() {
    local domain_type="custom"
    [[ -f "$DOMAIN_TYPE_FILE" ]] && domain_type=$(cat "$DOMAIN_TYPE_FILE")
    mkdir -p /etc/xray
    if [[ "$domain_type" == "custom" ]]; then
        systemctl stop haproxy nginx 2>/dev/null
        sleep 1
        certbot certonly --standalone \
            -d "$DOMAIN" \
            --non-interactive \
            --agree-tos \
            --register-unsafely-without-email \
            >/dev/null 2>&1
        if [[ -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]]; then
            cp "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" /etc/xray/xray.crt
            cp "/etc/letsencrypt/live/$DOMAIN/privkey.pem"   /etc/xray/xray.key
        else
            _gen_self_signed
        fi
        systemctl start haproxy nginx 2>/dev/null
    else
        _gen_self_signed
    fi
    chmod 644 /etc/xray/xray.* 2>/dev/null
}

_gen_self_signed() {
    openssl req -new -newkey rsa:2048 \
        -days 3650 -nodes -x509 \
        -subj "/C=ID/ST=Jakarta/L=Jakarta/O=VPN/CN=${DOMAIN}" \
        -keyout /etc/xray/xray.key \
        -out /etc/xray/xray.crt 2>/dev/null
}

#================================================
# SETUP MENU COMMAND
#================================================

setup_menu_command() {
    cat > /usr/local/bin/menu << 'MENUEOF'
#!/bin/bash
mesg n 2>/dev/null
[[ -f /root/tunnel.sh ]] && bash /root/tunnel.sh || echo "Script not found!"
MENUEOF
    chmod +x /usr/local/bin/menu
    if ! grep -q "tunnel.sh" /root/.bashrc 2>/dev/null; then
        cat >> /root/.bashrc << 'BASHEOF'

# VPN Menu
mesg n 2>/dev/null
[[ -f /root/tunnel.sh ]] && bash /root/tunnel.sh
BASHEOF
    fi
    mkdir -p /etc/systemd/journald.conf.d
    cat > /etc/systemd/journald.conf.d/no-wall.conf << 'JEOF'
[Journal]
ForwardToWall=no
JEOF
    systemctl restart systemd-journald >/dev/null 2>&1
}

#================================================
# SETUP SWAP
#================================================

setup_swap() {
    local swap_total
    swap_total=$(free -m | awk 'NR==3{print $2}')
    if [[ "$swap_total" -gt 512 ]]; then
        return
    fi
    swapoff -a 2>/dev/null
    sed -i '/swapfile/d' /etc/fstab
    rm -f /swapfile
    fallocate -l 1G /swapfile 2>/dev/null || \
        dd if=/dev/zero of=/swapfile bs=1M count=1024 2>/dev/null
    chmod 600 /swapfile
    mkswap /swapfile >/dev/null 2>&1
    swapon /swapfile
    grep -q "/swapfile" /etc/fstab || \
        echo "/swapfile none swap sw 0 0" >> /etc/fstab
}

#================================================
# OPTIMIZE VPN - TUNING TCP UNTUK TUNNEL STABIL
#================================================

optimize_vpn() {
    cat > /etc/sysctl.d/99-vpn.conf << 'SYSEOF'
# TCP Keepalive - jaga koneksi tunnel tetap hidup
net.ipv4.tcp_keepalive_time = 60
net.ipv4.tcp_keepalive_intvl = 10
net.ipv4.tcp_keepalive_probes = 5

# Timeout lebih wajar - tidak terlalu agresif
net.ipv4.tcp_fin_timeout = 20
net.ipv4.tcp_tw_reuse = 1

# Buffer besar untuk throughput tinggi
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728

# Antrian koneksi besar
net.core.netdev_max_backlog = 250000
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_max_tw_buckets = 400000

# BBR Congestion Control - terbaik untuk tunnel
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# Forward IP
net.ipv4.ip_forward = 1

# Matikan IPv6 (penyebab konflik)
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1

# Swap minimal
vm.swappiness = 10

# Port range luas
net.ipv4.ip_local_port_range = 1024 65535
SYSEOF

    modprobe tcp_bbr 2>/dev/null
    echo "tcp_bbr" > /etc/modules-load.d/bbr.conf
    sysctl -p /etc/sysctl.d/99-vpn.conf >/dev/null 2>&1

    cat > /etc/security/limits.d/99-vpn.conf << 'LIMEOF'
* soft nofile 65535
* hard nofile 65535
root soft nofile 65535
root hard nofile 65535
LIMEOF
}

#================================================
# SETUP KEEPALIVE
#================================================

setup_keepalive() {
    local sshcfg="/etc/ssh/sshd_config"
    grep -q "^ClientAliveInterval" "$sshcfg" && \
        sed -i 's/^ClientAliveInterval.*/ClientAliveInterval 20/' "$sshcfg" || \
        echo "ClientAliveInterval 20" >> "$sshcfg"
    grep -q "^ClientAliveCountMax" "$sshcfg" && \
        sed -i 's/^ClientAliveCountMax.*/ClientAliveCountMax 10/' "$sshcfg" || \
        echo "ClientAliveCountMax 10" >> "$sshcfg"
    grep -q "^TCPKeepAlive" "$sshcfg" && \
        sed -i 's/^TCPKeepAlive.*/TCPKeepAlive yes/' "$sshcfg" || \
        echo "TCPKeepAlive yes" >> "$sshcfg"
    systemctl restart sshd 2>/dev/null

    mkdir -p /etc/systemd/system/xray.service.d
    cat > /etc/systemd/system/xray.service.d/override.conf << 'XEOF'
[Service]
Restart=always
RestartSec=5
LimitNOFILE=65535
XEOF

    cat > /usr/local/bin/vpn-keepalive.sh << 'KAEOF'
#!/bin/bash
while true; do
    GW=$(ip route | awk '/default/{print $3; exit}')
    [[ -n "$GW" ]] && ping -c1 -W2 "$GW" >/dev/null 2>&1
    ping -c1 -W2 8.8.8.8 >/dev/null 2>&1
    sleep 20
done
KAEOF
    chmod +x /usr/local/bin/vpn-keepalive.sh

    cat > /etc/systemd/system/vpn-keepalive.service << 'KASEOF'
[Unit]
Description=VPN Keepalive
After=network.target xray.service

[Service]
Type=simple
ExecStart=/usr/local/bin/vpn-keepalive.sh
Restart=always
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
KASEOF
    systemctl daemon-reload
    systemctl enable vpn-keepalive 2>/dev/null
    systemctl restart vpn-keepalive 2>/dev/null
}

#================================================
# HAPROXY CONFIG - STABIL UNTUK TUNNEL
#================================================

configure_haproxy() {
    cat > /etc/haproxy/haproxy.cfg << 'HAEOF'
global
    log /dev/log local0
    maxconn 65535
    tune.ssl.default-dh-param 2048
    tune.bufsize 32768

defaults
    log global
    mode tcp
    option tcplog
    option dontlognull
    option redispatch
    retries 3
    timeout connect  5s
    timeout client   3h
    timeout server   3h
    timeout tunnel   3h
    timeout check    10s
    timeout queue    30s
    maxconn 65535

# Port 443: deteksi HTTP/2 (gRPC) vs HTTP/1.1 (WS)
# Caranya: inspect 5 byte pertama TLS handshake
# gRPC pakai ALPN h2, WS pakai ALPN http/1.1
# HAProxy routing berdasarkan ALPN negotiation

frontend front_443
    bind *:443
    mode tcp
    tcp-request inspect-delay 5s
    tcp-request content accept if { req.ssl_hello_type 1 }

    # Kalau ALPN h2 → gRPC backend
    use_backend back_grpc if { req.ssl_alpn h2 }

    # Default → WS TLS backend
    default_backend back_xray_tls

# WebSocket TLS → Xray port 8443
backend back_xray_tls
    mode tcp
    option tcp-check
    server xray_ws 127.0.0.1:8443 check inter 10s rise 2 fall 3

# gRPC TLS → Xray port 8444
backend back_grpc
    mode tcp
    option tcp-check
    server xray_grpc 127.0.0.1:8444 check inter 10s rise 2 fall 3
HAEOF
}

#================================================
# NGINX CONFIG - STABIL UNTUK NONTLS TUNNEL
#================================================

configure_nginx() {
    cat > /etc/nginx/sites-available/vpn << 'NGXEOF'
# Port 80 - NonTLS WebSocket tunnel
# Semua protokol masuk sini, dibedakan via path
server {
    listen 80 default_server;
    server_name _;
    root /var/www/html;

    # Jaga koneksi websocket tetap hidup
    keepalive_timeout 3600s;
    keepalive_requests 10000;

    # VMess NonTLS WebSocket
    location /vmess {
        proxy_pass http://127.0.0.1:10080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_buffering off;
        proxy_buffer_size 4k;
    }

    # VLess NonTLS WebSocket
    location /vless {
        proxy_pass http://127.0.0.1:10080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_buffering off;
        proxy_buffer_size 4k;
    }

    # Trojan NonTLS WebSocket
    location /trojan {
        proxy_pass http://127.0.0.1:10080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_buffering off;
        proxy_buffer_size 4k;
    }

    location / {
        try_files $uri $uri/ =404;
        autoindex on;
    }
}

# Port 81 - Download file akun
server {
    listen 81;
    server_name _;
    root /var/www/html;
    autoindex on;
    location / {
        try_files $uri $uri/ =404;
        add_header Content-Type text/plain;
    }
}
NGXEOF

    rm -f /etc/nginx/sites-enabled/default
    rm -f /etc/nginx/sites-enabled/vpn
    ln -sf /etc/nginx/sites-available/vpn /etc/nginx/sites-enabled/vpn

    # Tuning nginx untuk websocket tunnel
    cat > /etc/nginx/conf.d/vpn-tuning.conf << 'TUNEOF'
# Tuning untuk WebSocket tunnel stabil
proxy_connect_timeout 10s;
proxy_read_timeout 3600s;
proxy_send_timeout 3600s;

# Buffer kecil agar tidak buffering data tunnel
proxy_buffering off;
proxy_request_buffering off;

# Gzip off untuk tunnel (data sudah encrypted)
gzip off;
TUNEOF
}

#================================================
# XRAY CONFIG - ARSITEKTUR BARU ANTI TABRAKAN
#
# PENJELASAN DESAIN:
# Port 10443 (TLS): Semua protokol masuk lewat sini
#   Xray bedakan VMess/VLess/Trojan via PATH WebSocket:
#   - /vmess  → VMess
#   - /vless  → VLess
#   - /trojan → Trojan
#
# Port 10080 (NonTLS): Sama, dibedakan via PATH
#
# Port 10444 (gRPC): Dibedakan via serviceName
#
# KENAPA INI BENAR:
# WebSocket di HTTP/HTTPS itu multiplexing via URL path,
# jadi 1 port bisa handle banyak protokol asal path beda.
# Tidak ada tabrakan karena Xray routing berdasarkan path.
#================================================

create_xray_config() {
    mkdir -p /var/log/xray /usr/local/etc/xray

    cat > "$XRAY_CONFIG" << XRAYEOF
{
  "log": {
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log",
    "loglevel": "warning"
  },

  "inbounds": [

    {
      "tag": "vmess-ws-tls",
      "port": 10443,
      "listen": "127.0.0.1",
      "protocol": "vmess",
      "settings": {
        "clients": [],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "alpn": ["http/1.1"],
          "certificates": [
            {
              "certificateFile": "/etc/xray/xray.crt",
              "keyFile": "/etc/xray/xray.key"
            }
          ]
        },
        "wsSettings": {
          "path": "/vmess",
          "headers": {}
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    },

    {
      "tag": "vless-ws-tls",
      "port": 10443,
      "listen": "127.0.0.1",
      "protocol": "vless",
      "settings": {
        "clients": [],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "alpn": ["http/1.1"],
          "certificates": [
            {
              "certificateFile": "/etc/xray/xray.crt",
              "keyFile": "/etc/xray/xray.key"
            }
          ]
        },
        "wsSettings": {
          "path": "/vless",
          "headers": {}
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    },

    {
      "tag": "trojan-ws-tls",
      "port": 10443,
      "listen": "127.0.0.1",
      "protocol": "trojan",
      "settings": {
        "clients": []
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "alpn": ["http/1.1"],
          "certificates": [
            {
              "certificateFile": "/etc/xray/xray.crt",
              "keyFile": "/etc/xray/xray.key"
            }
          ]
        },
        "wsSettings": {
          "path": "/trojan",
          "headers": {}
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    },

    {
      "tag": "vmess-ws-nontls",
      "port": 10080,
      "listen": "127.0.0.1",
      "protocol": "vmess",
      "settings": {
        "clients": []
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": {
          "path": "/vmess",
          "headers": {}
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    },

    {
      "tag": "vless-ws-nontls",
      "port": 10080,
      "listen": "127.0.0.1",
      "protocol": "vless",
      "settings": {
        "clients": [],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": {
          "path": "/vless",
          "headers": {}
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    },

    {
      "tag": "trojan-ws-nontls",
      "port": 10080,
      "listen": "127.0.0.1",
      "protocol": "trojan",
      "settings": {
        "clients": []
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": {
          "path": "/trojan",
          "headers": {}
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    },

    {
      "tag": "vmess-grpc-tls",
      "port": 8444,
      "listen": "127.0.0.1",
      "protocol": "vmess",
      "settings": {
        "clients": []
      },
      "streamSettings": {
        "network": "grpc",
        "security": "tls",
        "tlsSettings": {
          "alpn": ["h2"],
          "certificates": [
            {
              "certificateFile": "/etc/xray/xray.crt",
              "keyFile": "/etc/xray/xray.key"
            }
          ]
        },
        "grpcSettings": {
          "serviceName": "vmess-grpc"
        }
      }
    },

    {
      "tag": "vless-grpc-tls",
      "port": 8444,
      "listen": "127.0.0.1",
      "protocol": "vless",
      "settings": {
        "clients": [],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "grpc",
        "security": "tls",
        "tlsSettings": {
          "alpn": ["h2"],
          "certificates": [
            {
              "certificateFile": "/etc/xray/xray.crt",
              "keyFile": "/etc/xray/xray.key"
            }
          ]
        },
        "grpcSettings": {
          "serviceName": "vless-grpc"
        }
      }
    },

    {
      "tag": "trojan-grpc-tls",
      "port": 8444,
      "listen": "127.0.0.1",
      "protocol": "trojan",
      "settings": {
        "clients": []
      },
      "streamSettings": {
        "network": "grpc",
        "security": "tls",
        "tlsSettings": {
          "alpn": ["h2"],
          "certificates": [
            {
              "certificateFile": "/etc/xray/xray.crt",
              "keyFile": "/etc/xray/xray.key"
            }
          ]
        },
        "grpcSettings": {
          "serviceName": "trojan-grpc"
        }
      }
    }

  ],

  "outbounds": [
    {
      "protocol": "freedom",
      "settings": { "domainStrategy": "UseIPv4" },
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "block"
    }
  ],

  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {
        "type": "field",
        "ip": ["geoip:private"],
        "outboundTag": "block"
      }
    ]
  },

  "policy": {
    "levels": {
      "0": {
        "handshake": 4,
        "connIdle": 300,
        "uplinkOnly": 5,
        "downlinkOnly": 30,
        "statsUserUplink": false,
        "statsUserDownlink": false,
        "bufferSize": 512
      }
    },
    "system": {
      "statsInboundUplink": false,
      "statsInboundDownlink": false
    }
  }
}
XRAYEOF

    fix_xray_permissions
}

fix_xray_permissions() {
    mkdir -p /usr/local/etc/xray /var/log/xray /etc/xray
    chmod 755 /usr/local/etc/xray
    chmod 755 /var/log/xray
    touch /var/log/xray/access.log /var/log/xray/error.log
    chmod 644 /var/log/xray/access.log /var/log/xray/error.log
    chmod 644 /usr/local/etc/xray/config.json 2>/dev/null
    [[ -f /etc/xray/xray.crt ]] && chmod 644 /etc/xray/xray.crt
    [[ -f /etc/xray/xray.key ]] && chmod 644 /etc/xray/xray.key
}

#================================================
# INFO PORT
#================================================

show_info_port() {
    clear
    print_menu_header "SERVER PORT INFORMATION"
    local W; W=$(get_width)
    local inner=$(( W - 4 ))
    printf "  ${CYAN}┌"; printf '─%.0s' $(seq 1 $inner); printf "┐${NC}\n"
    printf "  ${CYAN}│${NC}  ${YELLOW}%-28s${NC} : ${GREEN}%-$((inner-33))s${NC}  ${CYAN}│${NC}\n" "== AKSES DARI LUAR ==" ""
    printf "  ${CYAN}│${NC}  ${WHITE}%-28s${NC} : ${GREEN}%-$((inner-33))s${NC}  ${CYAN}│${NC}\n" "SSH OpenSSH"      "22"
    printf "  ${CYAN}│${NC}  ${WHITE}%-28s${NC} : ${GREEN}%-$((inner-33))s${NC}  ${CYAN}│${NC}\n" "SSH Dropbear"     "222"
    printf "  ${CYAN}│${NC}  ${WHITE}%-28s${NC} : ${GREEN}%-$((inner-33))s${NC}  ${CYAN}│${NC}\n" "NonTLS (Nginx)"   "80  → path /vmess /vless /trojan"
    printf "  ${CYAN}│${NC}  ${WHITE}%-28s${NC} : ${GREEN}%-$((inner-33))s${NC}  ${CYAN}│${NC}\n" "TLS (HAProxy)"    "443 → path /vmess /vless /trojan"
    printf "  ${CYAN}│${NC}  ${WHITE}%-28s${NC} : ${GREEN}%-$((inner-33))s${NC}  ${CYAN}│${NC}\n" "gRPC TLS"         "10444"
    printf "  ${CYAN}│${NC}  ${WHITE}%-28s${NC} : ${GREEN}%-$((inner-33))s${NC}  ${CYAN}│${NC}\n" "BadVPN UDP"       "7100-7300"
    printf "  ${CYAN}│${NC}  ${WHITE}%-28s${NC} : ${GREEN}%-$((inner-33))s${NC}  ${CYAN}│${NC}\n" "Download Akun"    "81"
    printf "  ${CYAN}├"; printf '─%.0s' $(seq 1 $inner); printf "┤${NC}\n"
    printf "  ${CYAN}│${NC}  ${YELLOW}%-28s${NC} : ${GREEN}%-$((inner-33))s${NC}  ${CYAN}│${NC}\n" "== INTERNAL XRAY ==" ""
    printf "  ${CYAN}│${NC}  ${WHITE}%-28s${NC} : ${GREEN}%-$((inner-33))s${NC}  ${CYAN}│${NC}\n" "Xray WS TLS"      "127.0.0.1:10443"
    printf "  ${CYAN}│${NC}  ${WHITE}%-28s${NC} : ${GREEN}%-$((inner-33))s${NC}  ${CYAN}│${NC}\n" "Xray WS NonTLS"   "127.0.0.1:10080"
    printf "  ${CYAN}│${NC}  ${WHITE}%-28s${NC} : ${GREEN}%-$((inner-33))s${NC}  ${CYAN}│${NC}\n" "Xray gRPC"        "0.0.0.0:10444"
    printf "  ${CYAN}├"; printf '─%.0s' $(seq 1 $inner); printf "┤${NC}\n"
    printf "  ${CYAN}│${NC}  ${YELLOW}%-28s${NC} : ${GREEN}%-$((inner-33))s${NC}  ${CYAN}│${NC}\n" "== PATH WEBSOCKET ==" ""
    printf "  ${CYAN}│${NC}  ${WHITE}%-28s${NC} : ${GREEN}%-$((inner-33))s${NC}  ${CYAN}│${NC}\n" "VMess path"       "/vmess"
    printf "  ${CYAN}│${NC}  ${WHITE}%-28s${NC} : ${GREEN}%-$((inner-33))s${NC}  ${CYAN}│${NC}\n" "VLess path"       "/vless"
    printf "  ${CYAN}│${NC}  ${WHITE}%-28s${NC} : ${GREEN}%-$((inner-33))s${NC}  ${CYAN}│${NC}\n" "Trojan path"      "/trojan"
    printf "  ${CYAN}└"; printf '─%.0s' $(seq 1 $inner); printf "┘${NC}\n"
    echo ""
    read -p "  Press any key to back..."
}

#================================================
# FIX PERMISSIONS XRAY
#================================================

fix_xray_permissions() {
    mkdir -p /usr/local/etc/xray /var/log/xray /etc/xray
    chmod 755 /usr/local/etc/xray
    chmod 755 /var/log/xray
    touch /var/log/xray/access.log /var/log/xray/error.log
    chmod 644 /var/log/xray/access.log /var/log/xray/error.log
    chmod 644 /usr/local/etc/xray/config.json 2>/dev/null
    [[ -f /etc/xray/xray.crt ]] && chmod 644 /etc/xray/xray.crt
    [[ -f /etc/xray/xray.key ]] && chmod 644 /etc/xray/xray.key
}

#================================================
# CREATE ACCOUNT - XRAY
#================================================

create_account_template() {
    local protocol="$1"
    local username="$2"
    local days="$3"
    local quota="$4"
    local iplimit="$5"

    local uuid ip_vps exp created
    uuid=$(cat /proc/sys/kernel/random/uuid)
    ip_vps=$(get_ip)
    exp=$(date -d "+${days} days" +"%d %b, %Y")
    created=$(date +"%d %b, %Y")

    local temp
    temp=$(mktemp)

    if [[ "$protocol" == "vmess" ]]; then
        jq --arg uuid "$uuid" --arg email "$username" \
           '(.inbounds[] | select(.tag | startswith("vmess")).settings.clients) += [{"id":$uuid,"email":$email,"alterId":0}]' \
           "$XRAY_CONFIG" > "$temp" 2>/dev/null
    elif [[ "$protocol" == "vless" ]]; then
        jq --arg uuid "$uuid" --arg email "$username" \
           '(.inbounds[] | select(.tag | startswith("vless")).settings.clients) += [{"id":$uuid,"email":$email}]' \
           "$XRAY_CONFIG" > "$temp" 2>/dev/null
    elif [[ "$protocol" == "trojan" ]]; then
        jq --arg password "$uuid" --arg email "$username" \
           '(.inbounds[] | select(.tag | startswith("trojan")).settings.clients) += [{"password":$password,"email":$email}]' \
           "$XRAY_CONFIG" > "$temp" 2>/dev/null
    fi

    if [[ $? -eq 0 ]] && [[ -s "$temp" ]]; then
        mv "$temp" "$XRAY_CONFIG"
        fix_xray_permissions
        systemctl reload xray 2>/dev/null || systemctl restart xray 2>/dev/null
        sleep 1
    else
        rm -f "$temp"
        echo -e "  ${RED}✘ Failed update Xray config!${NC}"
        sleep 2; return 1
    fi

    mkdir -p "$AKUN_DIR"
    printf "UUID=%s\nQUOTA=%s\nIPLIMIT=%s\nEXPIRED=%s\nCREATED=%s\n" \
        "$uuid" "$quota" "$iplimit" "$exp" "$created" \
        > "$AKUN_DIR/${protocol}-${username}.txt"

    # Generate links
    # TLS WS  = via HAProxy port 443
    # NonTLS  = via Nginx port 80
    # gRPC    = via HAProxy port 443

    local link_tls link_nontls link_grpc
    local clash_tls clash_nontls clash_grpc

    if [[ "$protocol" == "vmess" ]]; then
        local j_tls j_nontls j_grpc
        j_tls=$(printf '{"v":"2","ps":"%s-TLS","add":"bug.com","port":"443","id":"%s","aid":"0","net":"ws","path":"/vmess","type":"none","host":"%s","tls":"tls","sni":"%s"}' \
            "$username" "$uuid" "$DOMAIN" "$DOMAIN")
        link_tls="vmess://$(printf '%s' "$j_tls" | base64 -w 0)"

        j_nontls=$(printf '{"v":"2","ps":"%s-NonTLS","add":"bug.com","port":"80","id":"%s","aid":"0","net":"ws","path":"/vmess","type":"none","host":"%s","tls":"none"}' \
            "$username" "$uuid" "$DOMAIN")
        link_nontls="vmess://$(printf '%s' "$j_nontls" | base64 -w 0)"

        j_grpc=$(printf '{"v":"2","ps":"%s-gRPC","add":"%s","port":"443","id":"%s","aid":"0","net":"grpc","path":"vmess-grpc","type":"none","host":"","tls":"tls","sni":"%s"}' \
            "$username" "$DOMAIN" "$uuid" "$DOMAIN")
        link_grpc="vmess://$(printf '%s' "$j_grpc" | base64 -w 0)"

        clash_tls="- name: ${username}-WS-TLS\n  type: vmess\n  server: bug.com\n  port: 443\n  uuid: ${uuid}\n  alterId: 0\n  cipher: auto\n  udp: true\n  tls: true\n  skip-cert-verify: false\n  servername: ${DOMAIN}\n  network: ws\n  ws-opts:\n    path: /vmess\n    headers:\n      Host: ${DOMAIN}"

        clash_nontls="- name: ${username}-WS-NonTLS\n  type: vmess\n  server: bug.com\n  port: 80\n  uuid: ${uuid}\n  alterId: 0\n  cipher: auto\n  udp: true\n  tls: false\n  network: ws\n  ws-opts:\n    path: /vmess\n    headers:\n      Host: ${DOMAIN}"

        clash_grpc="- name: ${username}-gRPC\n  type: vmess\n  server: ${DOMAIN}\n  port: 443\n  uuid: ${uuid}\n  alterId: 0\n  cipher: auto\n  udp: true\n  tls: true\n  skip-cert-verify: false\n  servername: ${DOMAIN}\n  network: grpc\n  grpc-opts:\n    grpc-service-name: vmess-grpc"

    elif [[ "$protocol" == "vless" ]]; then
        link_tls="vless://${uuid}@bug.com:443?path=%2Fvless&security=tls&encryption=none&host=${DOMAIN}&type=ws&sni=${DOMAIN}#${username}-TLS"
        link_nontls="vless://${uuid}@bug.com:80?path=%2Fvless&security=none&encryption=none&host=${DOMAIN}&type=ws#${username}-NonTLS"
        link_grpc="vless://${uuid}@${DOMAIN}:443?mode=gun&security=tls&encryption=none&type=grpc&serviceName=vless-grpc&sni=${DOMAIN}#${username}-gRPC"

        clash_tls="- name: ${username}-WS-TLS\n  type: vless\n  server: bug.com\n  port: 443\n  uuid: ${uuid}\n  udp: true\n  tls: true\n  skip-cert-verify: false\n  servername: ${DOMAIN}\n  network: ws\n  ws-opts:\n    path: /vless\n    headers:\n      Host: ${DOMAIN}"

        clash_nontls="- name: ${username}-WS-NonTLS\n  type: vless\n  server: bug.com\n  port: 80\n  uuid: ${uuid}\n  udp: true\n  tls: false\n  network: ws\n  ws-opts:\n    path: /vless\n    headers:\n      Host: ${DOMAIN}"

        clash_grpc="- name: ${username}-gRPC\n  type: vless\n  server: ${DOMAIN}\n  port: 443\n  uuid: ${uuid}\n  udp: true\n  tls: true\n  skip-cert-verify: false\n  servername: ${DOMAIN}\n  network: grpc\n  grpc-opts:\n    grpc-service-name: vless-grpc"

    elif [[ "$protocol" == "trojan" ]]; then
        link_tls="trojan://${uuid}@bug.com:443?path=%2Ftrojan&security=tls&host=${DOMAIN}&type=ws&sni=${DOMAIN}#${username}-TLS"
        link_nontls="trojan://${uuid}@bug.com:80?path=%2Ftrojan&security=none&host=${DOMAIN}&type=ws#${username}-NonTLS"
        link_grpc="trojan://${uuid}@${DOMAIN}:443?mode=gun&security=tls&type=grpc&serviceName=trojan-grpc&sni=${DOMAIN}#${username}-gRPC"

        clash_tls="- name: ${username}-WS-TLS\n  type: trojan\n  server: bug.com\n  port: 443\n  password: ${uuid}\n  udp: true\n  tls: true\n  skip-cert-verify: false\n  sni: ${DOMAIN}\n  network: ws\n  ws-opts:\n    path: /trojan\n    headers:\n      Host: ${DOMAIN}"

        clash_nontls="- name: ${username}-WS-NonTLS\n  type: trojan\n  server: bug.com\n  port: 80\n  password: ${uuid}\n  udp: true\n  tls: false\n  network: ws\n  ws-opts:\n    path: /trojan\n    headers:\n      Host: ${DOMAIN}"

        clash_grpc="- name: ${username}-gRPC\n  type: trojan\n  server: ${DOMAIN}\n  port: 443\n  password: ${uuid}\n  udp: true\n  tls: true\n  skip-cert-verify: false\n  sni: ${DOMAIN}\n  network: grpc\n  grpc-opts:\n    grpc-service-name: trojan-grpc"
    fi

    mkdir -p "$PUBLIC_HTML"
    cat > "$PUBLIC_HTML/${protocol}-${username}.txt" << DLEOF
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  YOUZIN CRABZ TUNEL - ${protocol^^} Account
  The Professor
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Username         : ${username}
 IP VPS           : ${ip_vps}
 Domain           : ${DOMAIN}
 UUID/Password    : ${uuid}
 Quota            : ${quota} GB
 IP Limit         : ${iplimit} IP
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Port TLS         : 443 (WebSocket)
 Port NonTLS      : 80  (WebSocket)
 Port gRPC        : 443 (via HAProxy)
 Path WS          : /${protocol}
 ServiceName gRPC : ${protocol}-grpc
 TLS              : enabled
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Link TLS:
 ${link_tls}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Link NonTLS:
 ${link_nontls}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Link gRPC:
 ${link_grpc}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 CLASH YAML - WS TLS:
$(printf "%b" "$clash_tls")
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 CLASH YAML - WS NonTLS:
$(printf "%b" "$clash_nontls")
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 CLASH YAML - gRPC:
$(printf "%b" "$clash_grpc")
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Download         : http://${ip_vps}:81/${protocol}-${username}.txt
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Aktif Selama     : ${days} Hari
 Dibuat Pada      : ${created}
 Berakhir Pada    : ${exp}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
DLEOF

    _print_xray_result "$protocol" "$username" "$ip_vps" "$uuid" "$quota" "$iplimit" \
        "$link_tls" "$link_nontls" "$link_grpc" "$days" "$created" "$exp" \
        "$clash_tls" "$clash_nontls" "$clash_grpc"

    local dl_link="http://${ip_vps}:81/${protocol}-${username}.txt"
    send_telegram_admin \
"✅ <b>New ${protocol^^} Account - Youzin Crabz Tunel</b>
━━━━━━━━━━━━━━━━━━━━━━━━━
👤 Username   : <code>${username}</code>
🔑 UUID       : <code>${uuid}</code>
🌐 Domain     : <code>${DOMAIN}</code>
🖥️ IP VPS     : <code>${ip_vps}</code>
📦 Protocol   : ${protocol^^}
━━━━━━━━━━━━━━━━━━━━━━━━━
🔌 Port TLS   : 443 (WebSocket)
🔌 Port NonTLS: 80  (WebSocket)
🔌 Port gRPC  : 10444
━━━━━━━━━━━━━━━━━━━━━━━━━
📅 Dibuat     : ${created}
⏳ Berakhir   : ${exp}
🔗 Download   : ${dl_link}
━━━━━━━━━━━━━━━━━━━━━━━━━
<i>Powered by The Professor</i>"

    read -p "  Press any key to back..."
}

#================================================
# PRINT XRAY RESULT
#================================================

_print_xray_result() {
    local protocol="$1" username="$2" ip_vps="$3" uuid="$4"
    local quota="$5" iplimit="$6" link_tls="$7" link_nontls="$8"
    local link_grpc="$9" days="${10}" created="${11}" exp="${12}"
    local clash_tls="${13}" clash_nontls="${14}" clash_grpc="${15}"

    clear
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${WHITE}${BOLD}YOUZIN CRABZ TUNEL${NC} — ${YELLOW}${protocol^^} Account${NC}"
    echo -e "  ${DIM}The Professor${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    printf "  ${WHITE}%-16s${NC} : ${GREEN}%s${NC}\n" "Username"    "$username"
    printf "  ${WHITE}%-16s${NC} : ${GREEN}%s${NC}\n" "IP VPS"      "$ip_vps"
    printf "  ${WHITE}%-16s${NC} : ${GREEN}%s${NC}\n" "Domain"      "$DOMAIN"
    printf "  ${WHITE}%-16s${NC} : ${CYAN}%s${NC}\n"  "UUID"        "$uuid"
    printf "  ${WHITE}%-16s${NC} : %s GB\n"            "Quota"       "$quota"
    printf "  ${WHITE}%-16s${NC} : %s IP\n"            "IP Limit"    "$iplimit"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    printf "  ${WHITE}%-16s${NC} : %s\n" "Port TLS"    "443 (via HAProxy → WS)"
    printf "  ${WHITE}%-16s${NC} : %s\n" "Port NonTLS" "80  (via Nginx → WS)"
    printf "  ${WHITE}%-16s${NC} : %s\n" "Port gRPC"   "443 (via HAProxy → gRPC)"
    printf "  ${WHITE}%-16s${NC} : %s\n" "Path WS"     "/${protocol}"
    printf "  ${WHITE}%-16s${NC} : %s\n" "ServiceName" "${protocol}-grpc"
    printf "  ${WHITE}%-16s${NC} : %s\n" "SNI"         "$DOMAIN"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    printf "  ${YELLOW}Link TLS${NC} :\n  %s\n" "$link_tls"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    printf "  ${YELLOW}Link NonTLS${NC} :\n  %s\n" "$link_nontls"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    printf "  ${YELLOW}Link gRPC${NC} :\n  %s\n" "$link_grpc"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${YELLOW}Clash YAML - WS TLS${NC} :"
    printf "%b\n" "$clash_tls"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${YELLOW}Clash YAML - WS NonTLS${NC} :"
    printf "%b\n" "$clash_nontls"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${YELLOW}Clash YAML - gRPC${NC} :"
    printf "%b\n" "$clash_grpc"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    printf "  ${WHITE}%-16s${NC} : http://%s:81/%s-%s.txt\n" "Download" "$ip_vps" "$protocol" "$username"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    printf "  ${WHITE}%-16s${NC} : ${YELLOW}%s Hari${NC}\n" "Aktif Selama" "$days"
    printf "  ${WHITE}%-16s${NC} : %s\n"  "Dibuat"    "$created"
    printf "  ${WHITE}%-16s${NC} : ${RED}%s${NC}\n" "Berakhir"  "$exp"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

#================================================
# TRIAL XRAY
#================================================

create_trial_xray() {
    local protocol="$1"
    local username="trial-$(date +%H%M%S)"
    local uuid ip_vps exp created
    uuid=$(cat /proc/sys/kernel/random/uuid)
    ip_vps=$(get_ip)
    exp=$(date -d "+1 hour" +"%d %b, %Y %H:%M")
    created=$(date +"%d %b, %Y %H:%M")

    local temp; temp=$(mktemp)

    if [[ "$protocol" == "vmess" ]]; then
        jq --arg uuid "$uuid" --arg email "$username" \
           '(.inbounds[] | select(.tag | startswith("vmess")).settings.clients) += [{"id":$uuid,"email":$email,"alterId":0}]' \
           "$XRAY_CONFIG" > "$temp" 2>/dev/null
    elif [[ "$protocol" == "vless" ]]; then
        jq --arg uuid "$uuid" --arg email "$username" \
           '(.inbounds[] | select(.tag | startswith("vless")).settings.clients) += [{"id":$uuid,"email":$email}]' \
           "$XRAY_CONFIG" > "$temp" 2>/dev/null
    elif [[ "$protocol" == "trojan" ]]; then
        jq --arg password "$uuid" --arg email "$username" \
           '(.inbounds[] | select(.tag | startswith("trojan")).settings.clients) += [{"password":$password,"email":$email}]' \
           "$XRAY_CONFIG" > "$temp" 2>/dev/null
    fi

    if [[ $? -eq 0 ]] && [[ -s "$temp" ]]; then
        mv "$temp" "$XRAY_CONFIG"
        fix_xray_permissions
        systemctl reload xray 2>/dev/null || systemctl restart xray 2>/dev/null
        sleep 1
    else
        rm -f "$temp"
        echo -e "  ${RED}✘ Failed!${NC}"; sleep 2; return
    fi

    mkdir -p "$AKUN_DIR"
    printf "UUID=%s\nQUOTA=1\nIPLIMIT=1\nEXPIRED=%s\nCREATED=%s\nTRIAL=1\n" \
        "$uuid" "$exp" "$created" \
        > "$AKUN_DIR/${protocol}-${username}.txt"

    # Auto delete setelah 1 jam
    (
        sleep 3600
        local tmp2; tmp2=$(mktemp)
        jq --arg email "$username" \
           'del(.inbounds[].settings.clients[]? | select(.email == $email))' \
           "$XRAY_CONFIG" > "$tmp2" 2>/dev/null && \
           mv "$tmp2" "$XRAY_CONFIG" || rm -f "$tmp2"
        fix_xray_permissions
        systemctl reload xray 2>/dev/null || systemctl restart xray 2>/dev/null
        rm -f "$AKUN_DIR/${protocol}-${username}.txt"
        rm -f "$PUBLIC_HTML/${protocol}-${username}.txt"
    ) &
    disown $!

    local link_tls link_nontls link_grpc

    if [[ "$protocol" == "vmess" ]]; then
        local j_tls j_nontls j_grpc
        j_tls=$(printf '{"v":"2","ps":"%s-TLS","add":"bug.com","port":"443","id":"%s","aid":"0","net":"ws","path":"/vmess","type":"none","host":"%s","tls":"tls","sni":"%s"}' \
            "$username" "$uuid" "$DOMAIN" "$DOMAIN")
        link_tls="vmess://$(printf '%s' "$j_tls" | base64 -w 0)"
        j_nontls=$(printf '{"v":"2","ps":"%s-NonTLS","add":"bug.com","port":"80","id":"%s","aid":"0","net":"ws","path":"/vmess","type":"none","host":"%s","tls":"none"}' \
            "$username" "$uuid" "$DOMAIN")
        link_nontls="vmess://$(printf '%s' "$j_nontls" | base64 -w 0)"
        j_grpc=$(printf '{"v":"2","ps":"%s-gRPC","add":"%s","port":"10444","id":"%s","aid":"0","net":"grpc","path":"vmess-grpc","type":"none","host":"","tls":"tls","sni":"%s"}' \
            "$username" "$DOMAIN" "$uuid" "$DOMAIN")
        link_grpc="vmess://$(printf '%s' "$j_grpc" | base64 -w 0)"
    elif [[ "$protocol" == "vless" ]]; then
        link_tls="vless://${uuid}@bug.com:443?path=%2Fvless&security=tls&encryption=none&host=${DOMAIN}&type=ws&sni=${DOMAIN}#${username}-TLS"
        link_nontls="vless://${uuid}@bug.com:80?path=%2Fvless&security=none&encryption=none&host=${DOMAIN}&type=ws#${username}-NonTLS"
        link_grpc="vless://${uuid}@${DOMAIN}:10444?mode=gun&security=tls&encryption=none&type=grpc&serviceName=vless-grpc&sni=${DOMAIN}#${username}-gRPC"
    elif [[ "$protocol" == "trojan" ]]; then
        link_tls="trojan://${uuid}@bug.com:443?path=%2Ftrojan&security=tls&host=${DOMAIN}&type=ws&sni=${DOMAIN}#${username}-TLS"
        link_nontls="trojan://${uuid}@bug.com:80?path=%2Ftrojan&security=none&host=${DOMAIN}&type=ws#${username}-NonTLS"
        link_grpc="trojan://${uuid}@${DOMAIN}:10444?mode=gun&security=tls&type=grpc&serviceName=trojan-grpc&sni=${DOMAIN}#${username}-gRPC"
    fi

    clear
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${WHITE}${BOLD}YOUZIN CRABZ TUNEL${NC} — ${YELLOW}Trial ${protocol^^} (1 Jam)${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    printf "  ${WHITE}%-16s${NC} : ${GREEN}%s${NC}\n" "Username"    "$username"
    printf "  ${WHITE}%-16s${NC} : ${GREEN}%s${NC}\n" "IP VPS"      "$ip_vps"
    printf "  ${WHITE}%-16s${NC} : ${GREEN}%s${NC}\n" "Domain"      "$DOMAIN"
    printf "  ${WHITE}%-16s${NC} : ${CYAN}%s${NC}\n"  "UUID"        "$uuid"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    printf "  ${YELLOW}Link TLS${NC} :\n  %s\n" "$link_tls"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    printf "  ${YELLOW}Link NonTLS${NC} :\n  %s\n" "$link_nontls"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    printf "  ${YELLOW}Link gRPC${NC} :\n  %s\n" "$link_grpc"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    printf "  ${WHITE}%-16s${NC} : ${YELLOW}1 Jam (Auto Delete)${NC}\n" "Aktif Selama"
    printf "  ${WHITE}%-16s${NC} : %s\n"  "Dibuat"   "$created"
    printf "  ${WHITE}%-16s${NC} : ${RED}%s${NC}\n" "Berakhir" "$exp"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    read -p "  Press any key to back..."
}

#================================================
# CREATE SSH
#================================================

create_ssh() {
    clear
    print_menu_header "CREATE SSH ACCOUNT"
    read -p "  Username      : " username
    [[ -z "$username" ]] && { echo -e "  ${RED}✘ Required!${NC}"; sleep 2; return; }
    if id "$username" &>/dev/null; then
        echo -e "  ${RED}✘ User sudah ada!${NC}"; sleep 2; return
    fi
    read -p "  Password      : " password
    [[ -z "$password" ]] && { echo -e "  ${RED}✘ Required!${NC}"; sleep 2; return; }
    read -p "  Expired (days): " days
    [[ ! "$days" =~ ^[0-9]+$ ]] && { echo -e "  ${RED}✘ Invalid!${NC}"; sleep 2; return; }
    read -p "  Limit IP      : " iplimit
    [[ ! "$iplimit" =~ ^[0-9]+$ ]] && iplimit=1

    local exp exp_date created ip_vps
    exp=$(date -d "+${days} days" +"%d %b, %Y")
    exp_date=$(date -d "+${days} days" +"%Y-%m-%d")
    created=$(date +"%d %b, %Y")
    ip_vps=$(get_ip)

    useradd -M -s /bin/false -e "$exp_date" "$username" 2>/dev/null
    echo "${username}:${password}" | chpasswd

    mkdir -p "$AKUN_DIR"
    printf "USERNAME=%s\nPASSWORD=%s\nIPLIMIT=%s\nEXPIRED=%s\nCREATED=%s\n" \
        "$username" "$password" "$iplimit" "$exp" "$created" \
        > "$AKUN_DIR/ssh-${username}.txt"

    _save_ssh_file "SSH Account" "$username" "$password" "$ip_vps" "$days" "$created" "$exp"
    _print_ssh_result "SSH Account" "$username" "$password" "$ip_vps" "$days" "$created" "$exp"

    send_telegram_admin \
"✅ <b>New SSH Account - Youzin Crabz Tunel</b>
━━━━━━━━━━━━━━━━━━━━━━━━━
👤 Username   : <code>${username}</code>
🔑 Password   : <code>${password}</code>
🌐 Domain     : <code>${DOMAIN}</code>
🖥️ IP VPS     : <code>${ip_vps}</code>
━━━━━━━━━━━━━━━━━━━━━━━━━
🔌 OpenSSH    : 22
🔌 Dropbear   : 222
🔌 SSL/TLS    : 443
🔌 BadVPN UDP : 7100-7300
━━━━━━━━━━━━━━━━━━━━━━━━━
📅 Dibuat     : ${created}
⏳ Berakhir   : ${exp}
🔗 Download   : http://${ip_vps}:81/ssh-${username}.txt
━━━━━━━━━━━━━━━━━━━━━━━━━
<i>Powered by The Professor</i>"

    read -p "  Press any key to back..."
}

#================================================
# SSH TRIAL
#================================================

create_ssh_trial() {
    local suffix
    suffix=$(cat /proc/sys/kernel/random/uuid | tr -d '-' | head -c 4 | tr '[:lower:]' '[:upper:]')
    local username="Trial-${suffix}"
    local password="1"
    local ip_vps exp exp_date created

    ip_vps=$(get_ip)
    exp=$(date -d "+1 hour" +"%d %b, %Y %H:%M")
    exp_date=$(date -d "+1 days" +"%Y-%m-%d")
    created=$(date +"%d %b, %Y %H:%M")

    useradd -M -s /bin/false -e "$exp_date" "$username" 2>/dev/null
    echo "${username}:${password}" | chpasswd

    mkdir -p "$AKUN_DIR"
    printf "USERNAME=%s\nPASSWORD=%s\nIPLIMIT=1\nEXPIRED=%s\nCREATED=%s\nTRIAL=1\n" \
        "$username" "$password" "$exp" "$created" \
        > "$AKUN_DIR/ssh-${username}.txt"

    (
        sleep 3600
        userdel -f "$username" 2>/dev/null
        rm -f "$AKUN_DIR/ssh-${username}.txt"
        rm -f "$PUBLIC_HTML/ssh-${username}.txt"
    ) &
    disown $!

    _save_ssh_file "Trial SSH (1 Jam)" "$username" "$password" "$ip_vps" "1 Jam (Auto Delete)" "$created" "$exp"
    _print_ssh_result "Trial SSH (1 Jam)" "$username" "$password" "$ip_vps" "1 Jam" "$created" "$exp"

    read -p "  Press any key to back..."
}

#================================================
# SSH HELPERS
#================================================

_save_ssh_file() {
    local title="$1" username="$2" password="$3" ip_vps="$4" days="$5" created="$6" exp="$7"
    mkdir -p "$PUBLIC_HTML"
    cat > "$PUBLIC_HTML/ssh-${username}.txt" << SSHFILE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  YOUZIN CRABZ TUNEL - ${title}
  The Professor
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Username         : ${username}
 Password         : ${password}
 IP/Host          : ${ip_vps}
 Domain SSH       : ${DOMAIN}
 OpenSSH          : 22
 Dropbear         : 222
 Port SSH UDP     : 1-65535
 SSL/TLS          : 443
 SSH Ws Non SSL   : 80
 SSH Ws SSL       : 443
 BadVPN UDPGW     : 7100,7200,7300
 Format Hc        : ${DOMAIN}:80@${username}:${password}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Save Link        : http://${ip_vps}:81/ssh-${username}.txt
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Payload          : GET / HTTP/1.1[crlf]Host: ${DOMAIN}[crlf]Upgrade: ws[crlf][crlf]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Aktif Selama     : ${days}
 Dibuat Pada      : ${created}
 Berakhir Pada    : ${exp}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SSHFILE
}

_print_ssh_result() {
    local title="$1" username="$2" password="$3" ip_vps="$4" days="$5" created="$6" exp="$7"
    clear
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${WHITE}${BOLD}YOUZIN CRABZ TUNEL${NC} — ${YELLOW}${title}${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    printf "  ${WHITE}%-16s${NC} : ${GREEN}%s${NC}\n" "Username"       "$username"
    printf "  ${WHITE}%-16s${NC} : ${GREEN}%s${NC}\n" "Password"       "$password"
    printf "  ${WHITE}%-16s${NC} : ${GREEN}%s${NC}\n" "IP/Host"        "$ip_vps"
    printf "  ${WHITE}%-16s${NC} : ${GREEN}%s${NC}\n" "Domain SSH"     "$DOMAIN"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    printf "  ${WHITE}%-16s${NC} : %s\n" "OpenSSH"        "22"
    printf "  ${WHITE}%-16s${NC} : %s\n" "Dropbear"       "222"
    printf "  ${WHITE}%-16s${NC} : %s\n" "Port SSH UDP"   "1-65535"
    printf "  ${WHITE}%-16s${NC} : %s\n" "SSL/TLS"        "443"
    printf "  ${WHITE}%-16s${NC} : %s\n" "SSH Ws Non SSL" "80"
    printf "  ${WHITE}%-16s${NC} : %s\n" "SSH Ws SSL"     "443"
    printf "  ${WHITE}%-16s${NC} : %s\n" "BadVPN UDPGW"   "7100,7200,7300"
    printf "  ${WHITE}%-16s${NC} : %s:80@%s:%s\n" "Format Hc" "$DOMAIN" "$username" "$password"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    printf "  ${WHITE}%-16s${NC} : http://%s:81/ssh-%s.txt\n" "Save Link" "$ip_vps" "$username"
    printf "  ${WHITE}%-16s${NC} : GET / HTTP/1.1[crlf]Host: %s[crlf]Upgrade: ws[crlf][crlf]\n" "Payload" "$DOMAIN"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    printf "  ${WHITE}%-16s${NC} : ${YELLOW}%s${NC}\n"    "Aktif Selama"  "$days"
    printf "  ${WHITE}%-16s${NC} : %s\n"                   "Dibuat Pada"   "$created"
    printf "  ${WHITE}%-16s${NC} : ${RED}%s${NC}\n"        "Berakhir Pada" "$exp"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

#================================================
# DELETE / RENEW / LIST
#================================================

delete_account() {
    local protocol="$1"
    clear
    print_menu_header "DELETE ${protocol^^}"
    shopt -s nullglob
    local files=("$AKUN_DIR"/${protocol}-*.txt)
    shopt -u nullglob
    if [[ ${#files[@]} -eq 0 ]]; then
        echo -e "  ${RED}No accounts!${NC}"; sleep 2; return
    fi
    for f in "${files[@]}"; do
        local n e
        n=$(basename "$f" .txt | sed "s/${protocol}-//")
        e=$(grep "EXPIRED" "$f" 2>/dev/null | cut -d= -f2-)
        echo -e "  ${CYAN}▸${NC} $n ${YELLOW}($e)${NC}"
    done
    echo ""
    read -p "  Username to delete: " username
    [[ -z "$username" ]] && return
    local tmp; tmp=$(mktemp)
    jq --arg email "$username" \
       'del(.inbounds[].settings.clients[]? | select(.email == $email))' \
       "$XRAY_CONFIG" > "$tmp" 2>/dev/null && \
       mv "$tmp" "$XRAY_CONFIG" || rm -f "$tmp"
    fix_xray_permissions
    systemctl reload xray 2>/dev/null || systemctl restart xray 2>/dev/null
    rm -f "$AKUN_DIR/${protocol}-${username}.txt"
    rm -f "$PUBLIC_HTML/${protocol}-${username}.txt"
    [[ "$protocol" == "ssh" ]] && userdel -f "$username" 2>/dev/null
    echo -e "  ${GREEN}✔ Deleted: ${username}${NC}"
    sleep 2
}

renew_account() {
    local protocol="$1"
    clear
    print_menu_header "RENEW ${protocol^^}"
    shopt -s nullglob
    local files=("$AKUN_DIR"/${protocol}-*.txt)
    shopt -u nullglob
    if [[ ${#files[@]} -eq 0 ]]; then
        echo -e "  ${RED}No accounts!${NC}"; sleep 2; return
    fi
    for f in "${files[@]}"; do
        local n e
        n=$(basename "$f" .txt | sed "s/${protocol}-//")
        e=$(grep "EXPIRED" "$f" 2>/dev/null | cut -d= -f2-)
        echo -e "  ${CYAN}▸${NC} $n ${YELLOW}($e)${NC}"
    done
    echo ""
    read -p "  Username to renew: " username
    [[ -z "$username" ]] && return
    [[ ! -f "$AKUN_DIR/${protocol}-${username}.txt" ]] && {
        echo -e "  ${RED}✘ Not found!${NC}"; sleep 2; return
    }
    read -p "  Add days: " days
    [[ ! "$days" =~ ^[0-9]+$ ]] && { echo -e "  ${RED}✘ Invalid!${NC}"; sleep 2; return; }
    local new_exp new_exp_date
    new_exp=$(date -d "+${days} days" +"%d %b, %Y")
    new_exp_date=$(date -d "+${days} days" +"%Y-%m-%d")
    sed -i "s/EXPIRED=.*/EXPIRED=${new_exp}/" "$AKUN_DIR/${protocol}-${username}.txt"
    [[ "$protocol" == "ssh" ]] && chage -E "$new_exp_date" "$username" 2>/dev/null
    echo -e "  ${GREEN}✔ Renewed! Exp: ${new_exp}${NC}"
    sleep 3
}

list_accounts() {
    local protocol="$1"
    clear
    print_menu_header "${protocol^^} ACCOUNT LIST"
    local W; W=$(get_width)
    local inner=$(( W - 4 ))
    shopt -s nullglob
    local files=("$AKUN_DIR"/${protocol}-*.txt)
    shopt -u nullglob
    if [[ ${#files[@]} -eq 0 ]]; then
        echo -e "  ${RED}No accounts!${NC}"; sleep 2; return
    fi
    printf "  ${CYAN}┌"; printf '─%.0s' $(seq 1 $inner); printf "┐${NC}\n"
    printf "  ${CYAN}│${NC} ${WHITE}%-20s %-20s %-6s %-5s${NC} ${CYAN}│${NC}\n" "USERNAME" "EXPIRED" "QUOTA" "TYPE"
    printf "  ${CYAN}├"; printf '─%.0s' $(seq 1 $inner); printf "┤${NC}\n"
    for f in "${files[@]}"; do
        local uname exp quota trial ttype
        uname=$(basename "$f" .txt | sed "s/${protocol}-//")
        exp=$(grep "EXPIRED" "$f" 2>/dev/null | cut -d= -f2-)
        quota=$(grep "QUOTA" "$f" 2>/dev/null | cut -d= -f2)
        trial=$(grep "TRIAL" "$f" 2>/dev/null | cut -d= -f2)
        ttype="Member"
        [[ "$trial" == "1" ]] && ttype="Trial"
        printf "  ${CYAN}│${NC} ${GREEN}%-20s${NC} ${YELLOW}%-20s${NC} %-6s %-5s ${CYAN}│${NC}\n" \
            "$uname" "$exp" "${quota:-N/A}GB" "$ttype"
    done
    printf "  ${CYAN}└"; printf '─%.0s' $(seq 1 $inner); printf "┘${NC}\n"
    echo -e "  Total: ${GREEN}${#files[@]}${NC} accounts"
    echo ""
    read -p "  Press any key to back..."
}

cek_expired() {
    clear
    print_menu_header "CEK EXPIRED ACCOUNTS"
    local today found=0
    today=$(date +%s)
    shopt -s nullglob
    for f in "$AKUN_DIR"/*.txt; do
        [[ ! -f "$f" ]] && continue
        local exp_str exp_ts uname diff
        exp_str=$(grep "EXPIRED=" "$f" 2>/dev/null | head -1 | cut -d= -f2-)
        [[ -z "$exp_str" ]] && continue
        exp_ts=$(date -d "$exp_str" +%s 2>/dev/null)
        [[ -z "$exp_ts" ]] && continue
        uname=$(basename "$f" .txt)
        diff=$(( (exp_ts - today) / 86400 ))
        if [[ $diff -le 3 ]]; then
            found=1
            if [[ $diff -lt 0 ]]; then
                echo -e "  ${RED}✘ EXPIRED${NC}: $uname (${exp_str})"
            else
                echo -e "  ${YELLOW}⚠ ${diff} hari${NC}: $uname (${exp_str})"
            fi
        fi
    done
    shopt -u nullglob
    [[ $found -eq 0 ]] && echo -e "  ${GREEN}✔ Tidak ada akun expired!${NC}"
    echo ""
    read -p "  Press any key to back..."
}

delete_expired() {
    clear
    print_menu_header "DELETE EXPIRED ACCOUNTS"
    local today count=0
    today=$(date +%s)
    shopt -s nullglob
    for f in "$AKUN_DIR"/*.txt; do
        [[ ! -f "$f" ]] && continue
        local exp_str exp_ts fname uname protocol
        exp_str=$(grep "EXPIRED=" "$f" 2>/dev/null | head -1 | cut -d= -f2-)
        [[ -z "$exp_str" ]] && continue
        exp_ts=$(date -d "$exp_str" +%s 2>/dev/null)
        [[ -z "$exp_ts" ]] && continue
        if [[ $exp_ts -lt $today ]]; then
            fname=$(basename "$f" .txt)
            protocol=${fname%%-*}
            uname=${fname#*-}
            echo -e "  ${RED}Deleting${NC}: $fname"
            local tmp; tmp=$(mktemp)
            jq --arg email "$uname" \
               'del(.inbounds[].settings.clients[]? | select(.email == $email))' \
               "$XRAY_CONFIG" > "$tmp" 2>/dev/null && \
               mv "$tmp" "$XRAY_CONFIG" || rm -f "$tmp"
            [[ "$protocol" == "ssh" ]] && userdel -f "$uname" 2>/dev/null
            rm -f "$f"
            rm -f "$PUBLIC_HTML/${fname}.txt"
            ((count++))
        fi
    done
    shopt -u nullglob
    if [[ $count -gt 0 ]]; then
        fix_xray_permissions
        systemctl reload xray 2>/dev/null || systemctl restart xray 2>/dev/null
        echo -e "  ${GREEN}✔ Deleted ${count} accounts!${NC}"
    else
        echo -e "  ${GREEN}✔ Tidak ada akun expired!${NC}"
    fi
    echo ""
    read -p "  Press any key to back..."
}

#================================================
# CREATE VMESS / VLESS / TROJAN
#================================================

create_vmess() {
    clear; print_menu_header "CREATE VMESS ACCOUNT"
    read -p "  Username      : " username
    [[ -z "$username" ]] && { echo -e "  ${RED}✘ Required!${NC}"; sleep 2; return; }
    if grep -q "\"email\":\"${username}\"" "$XRAY_CONFIG" 2>/dev/null; then
        echo -e "  ${RED}✘ Username sudah ada!${NC}"; sleep 2; return
    fi
    read -p "  Expired (days): " days
    [[ ! "$days" =~ ^[0-9]+$ ]] && { echo -e "  ${RED}✘ Invalid!${NC}"; sleep 2; return; }
    read -p "  Quota (GB)    : " quota
    [[ ! "$quota" =~ ^[0-9]+$ ]] && quota=100
    read -p "  IP Limit      : " iplimit
    [[ ! "$iplimit" =~ ^[0-9]+$ ]] && iplimit=1
    create_account_template "vmess" "$username" "$days" "$quota" "$iplimit"
}

create_vless() {
    clear; print_menu_header "CREATE VLESS ACCOUNT"
    read -p "  Username      : " username
    [[ -z "$username" ]] && { echo -e "  ${RED}✘ Required!${NC}"; sleep 2; return; }
    if grep -q "\"email\":\"${username}\"" "$XRAY_CONFIG" 2>/dev/null; then
        echo -e "  ${RED}✘ Username sudah ada!${NC}"; sleep 2; return
    fi
    read -p "  Expired (days): " days
    [[ ! "$days" =~ ^[0-9]+$ ]] && { echo -e "  ${RED}✘ Invalid!${NC}"; sleep 2; return; }
    read -p "  Quota (GB)    : " quota
    [[ ! "$quota" =~ ^[0-9]+$ ]] && quota=100
    read -p "  IP Limit      : " iplimit
    [[ ! "$iplimit" =~ ^[0-9]+$ ]] && iplimit=1
    create_account_template "vless" "$username" "$days" "$quota" "$iplimit"
}

create_trojan() {
    clear; print_menu_header "CREATE TROJAN ACCOUNT"
    read -p "  Username      : " username
    [[ -z "$username" ]] && { echo -e "  ${RED}✘ Required!${NC}"; sleep 2; return; }
    if grep -q "\"email\":\"${username}\"" "$XRAY_CONFIG" 2>/dev/null; then
        echo -e "  ${RED}✘ Username sudah ada!${NC}"; sleep 2; return
    fi
    read -p "  Expired (days): " days
    [[ ! "$days" =~ ^[0-9]+$ ]] && { echo -e "  ${RED}✘ Invalid!${NC}"; sleep 2; return; }
    read -p "  Quota (GB)    : " quota
    [[ ! "$quota" =~ ^[0-9]+$ ]] && quota=100
    read -p "  IP Limit      : " iplimit
    [[ ! "$iplimit" =~ ^[0-9]+$ ]] && iplimit=1
    create_account_template "trojan" "$username" "$days" "$quota" "$iplimit"
}

#================================================
# MENU SSH / VMESS / VLESS / TROJAN
#================================================

menu_ssh() {
    while true; do
        clear; print_menu_header "SSH MENU"
        local W; W=$(get_width)
        _box_top $W
        _box_center $W "${YELLOW}${BOLD}SSH / OPENVPN${NC}"
        _box_divider $W
        _box_left $W "[1] Create SSH"
        _box_left $W "[2] Trial SSH (1 Jam)"
        _box_left $W "[3] Delete SSH"
        _box_left $W "[4] Renew SSH"
        _box_left $W "[5] List User SSH"
        _box_divider $W
        _box_left $W "${RED}[0] Back${NC}"
        _box_bottom $W
        echo ""
        read -p "  Select [0-5]: " choice
        case $choice in
            1) create_ssh ;;
            2) create_ssh_trial ;;
            3) delete_account "ssh" ;;
            4) renew_account "ssh" ;;
            5) list_accounts "ssh" ;;
            0) return ;;
        esac
    done
}

menu_vmess() {
    while true; do
        clear; print_menu_header "VMESS MENU"
        local W; W=$(get_width)
        _box_top $W
        _box_center $W "${YELLOW}${BOLD}VMESS ACCOUNT${NC}"
        _box_divider $W
        _box_left $W "[1] Create VMess"
        _box_left $W "[2] Trial VMess (1 Jam)"
        _box_left $W "[3] Delete VMess"
        _box_left $W "[4] Renew VMess"
        _box_left $W "[5] List User VMess"
        _box_divider $W
        _box_left $W "${RED}[0] Back${NC}"
        _box_bottom $W
        echo ""
        read -p "  Select [0-5]: " choice
        case $choice in
            1) create_vmess ;;
            2) create_trial_xray "vmess" ;;
            3) delete_account "vmess" ;;
            4) renew_account "vmess" ;;
            5) list_accounts "vmess" ;;
            0) return ;;
        esac
    done
}

menu_vless() {
    while true; do
        clear; print_menu_header "VLESS MENU"
        local W; W=$(get_width)
        _box_top $W
        _box_center $W "${YELLOW}${BOLD}VLESS ACCOUNT${NC}"
        _box_divider $W
        _box_left $W "[1] Create VLess"
        _box_left $W "[2] Trial VLess (1 Jam)"
        _box_left $W "[3] Delete VLess"
        _box_left $W "[4] Renew VLess"
        _box_left $W "[5] List User VLess"
        _box_divider $W
        _box_left $W "${RED}[0] Back${NC}"
        _box_bottom $W
        echo ""
        read -p "  Select [0-5]: " choice
        case $choice in
            1) create_vless ;;
            2) create_trial_xray "vless" ;;
            3) delete_account "vless" ;;
            4) renew_account "vless" ;;
            5) list_accounts "vless" ;;
            0) return ;;
        esac
    done
}

menu_trojan() {
    while true; do
        clear; print_menu_header "TROJAN MENU"
        local W; W=$(get_width)
        _box_top $W
        _box_center $W "${YELLOW}${BOLD}TROJAN ACCOUNT${NC}"
        _box_divider $W
        _box_left $W "[1] Create Trojan"
        _box_left $W "[2] Trial Trojan (1 Jam)"
        _box_left $W "[3] Delete Trojan"
        _box_left $W "[4] Renew Trojan"
        _box_left $W "[5] List User Trojan"
        _box_divider $W
        _box_left $W "${RED}[0] Back${NC}"
        _box_bottom $W
        echo ""
        read -p "  Select [0-5]: " choice
        case $choice in
            1) create_trojan ;;
            2) create_trial_xray "trojan" ;;
            3) delete_account "trojan" ;;
            4) renew_account "trojan" ;;
            5) list_accounts "trojan" ;;
            0) return ;;
        esac
    done
}

#================================================
# INSTALL UDP CUSTOM
#================================================

install_udp_custom() {
    cat > /usr/local/bin/udp-custom << 'UDPEOF'
#!/usr/bin/env python3
import socket, threading, select, time

PORTS    = range(7100, 7301)
SSH_HOST = '127.0.0.1'
SSH_PORT = 22
BUF      = 65536
TIMEOUT  = 30

def handle(data, addr, sock):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.connect((SSH_HOST, SSH_PORT))
        s.sendall(data)
        resp = s.recv(BUF)
        if resp: sock.sendto(resp, addr)
        s.close()
    except: pass

sockets = []
for port in PORTS:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
        s.bind(('0.0.0.0', port))
        s.setblocking(False)
        sockets.append(s)
    except: pass

print(f'UDP Custom: {len(sockets)} ports (7100-7300)', flush=True)

while True:
    try:
        readable, _, _ = select.select(sockets, [], [], 1.0)
        for sock in readable:
            try:
                data, addr = sock.recvfrom(BUF)
                threading.Thread(target=handle, args=(data, addr, sock), daemon=True).start()
            except: pass
    except KeyboardInterrupt: break
    except: time.sleep(1)
UDPEOF

    chmod +x /usr/local/bin/udp-custom

    cat > /etc/systemd/system/udp-custom.service << 'UDPSVC'
[Unit]
Description=UDP Custom BadVPN 7100-7300
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/local/bin/udp-custom
Restart=always
RestartSec=5
LimitNOFILE=65535
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
UDPSVC

    systemctl daemon-reload
    systemctl enable udp-custom 2>/dev/null
    systemctl restart udp-custom
    sleep 1
    systemctl is-active --quiet udp-custom && \
        echo -e "  ${GREEN}✔ UDP OK! (7100-7300)${NC}" || \
        echo -e "  ${RED}✘ UDP Failed!${NC}"
}

#================================================
# TELEGRAM BOT
#================================================

setup_telegram_bot() {
    clear
    print_menu_header "SETUP TELEGRAM BOT"
    read -p "  Bot Token     : " bot_token
    [[ -z "$bot_token" ]] && { echo -e "  ${RED}✘ Token required!${NC}"; sleep 2; return; }
    read -p "  Admin Chat ID : " admin_id
    [[ -z "$admin_id" ]] && { echo -e "  ${RED}✘ Chat ID required!${NC}"; sleep 2; return; }

    echo -e "  ${CYAN}Testing token...${NC}"
    local test_result bot_name
    test_result=$(curl -s --max-time 10 "https://api.telegram.org/bot${bot_token}/getMe")
    if ! echo "$test_result" | grep -q '"ok":true'; then
        echo -e "  ${RED}✘ Token tidak valid!${NC}"; sleep 2; return
    fi
    bot_name=$(echo "$test_result" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['result']['username'])" 2>/dev/null)
    echo -e "  ${GREEN}✔ Bot valid! @${bot_name}${NC}"
    echo ""
    read -p "  Nama Pemilik Rekening : " rek_name
    read -p "  Nomor Rek/Dana/GoPay  : " rek_number
    read -p "  Bank / E-Wallet       : " rek_bank
    read -p "  Harga per Bulan (Rp)  : " harga
    [[ ! "$harga" =~ ^[0-9]+$ ]] && harga=10000

    echo "$bot_token" > "$BOT_TOKEN_FILE"
    echo "$admin_id"  > "$CHAT_ID_FILE"
    chmod 600 "$BOT_TOKEN_FILE" "$CHAT_ID_FILE"

    cat > "$PAYMENT_FILE" << PAYEOF
REK_NAME=${rek_name}
REK_NUMBER=${rek_number}
REK_BANK=${rek_bank}
HARGA=${harga}
PAYEOF
    chmod 600 "$PAYMENT_FILE"

    _install_bot_service
    sleep 2

    if systemctl is-active --quiet vpn-bot; then
        echo -e "  ${GREEN}✔ Bot aktif! @${bot_name}${NC}"
        curl -s -X POST \
            "https://api.telegram.org/bot${bot_token}/sendMessage" \
            -d chat_id="$admin_id" \
            -d text="✅ Youzin Crabz Tunel Bot v${SCRIPT_VERSION} Aktif!
Domain: ${DOMAIN}
Powered by The Professor" \
            -d parse_mode="HTML" \
            --max-time 10 >/dev/null 2>&1
    else
        echo -e "  ${RED}✘ Bot gagal start!${NC}"
    fi
    echo ""
    read -p "  Press any key to back..."
}

_install_bot_service() {
    mkdir -p /root/bot "$ORDER_DIR"
    pip3 install requests --break-system-packages >/dev/null 2>&1 || \
        pip3 install requests >/dev/null 2>&1

    # Bot python sederhana tapi fungsional
    cat > /root/bot/bot.py << 'BOTEOF'
#!/usr/bin/env python3
import os, json, time, subprocess, threading, uuid, base64
from datetime import datetime, timedelta
try:
    import requests
except ImportError:
    os.system('pip3 install requests --break-system-packages -q')
    import requests

TOKEN     = open('/root/.bot_token').read().strip()
ADMIN_ID  = int(open('/root/.chat_id').read().strip())
DOMAIN    = open('/root/domain').read().strip() if os.path.exists('/root/domain') else 'N/A'
ORDER_DIR = '/root/orders'
AKUN_DIR  = '/root/akun'
HTML_DIR  = '/var/www/html'
XRAY_CFG  = '/usr/local/etc/xray/config.json'
API       = f'https://api.telegram.org/bot{TOKEN}'

os.makedirs(ORDER_DIR, exist_ok=True)
os.makedirs(AKUN_DIR, exist_ok=True)
os.makedirs(HTML_DIR, exist_ok=True)

state = {}
lock  = threading.Lock()

def get_payment():
    info = {'REK_NAME':'N/A','REK_NUMBER':'N/A','REK_BANK':'N/A','HARGA':'10000'}
    try:
        with open('/root/.payment_info') as f:
            for line in f:
                if '=' in line:
                    k,v = line.strip().split('=',1)
                    info[k] = v
    except: pass
    return info

def api(method, data=None):
    try:
        r = requests.post(f'{API}/{method}', json=data, timeout=10)
        return r.json()
    except: return {}

def send(cid, text, markup=None):
    d = {'chat_id':cid,'text':text,'parse_mode':'HTML'}
    if markup: d['reply_markup'] = json.dumps(markup)
    return api('sendMessage', d)

def get_ip():
    for url in ['https://ifconfig.me','https://api.ipify.org']:
        try: return requests.get(url, timeout=3).text.strip()
        except: pass
    return 'N/A'

def run(cmd):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
        return r.returncode, r.stdout.strip()
    except Exception as e: return 1, str(e)

def make_links(proto, uname, uid):
    if proto == 'vmess':
        j = lambda port,tls,path: base64.b64encode(json.dumps({
            "v":"2","ps":uname,"add":"bug.com","port":str(port),"id":uid,
            "aid":"0","net":"ws","path":path,"type":"none","host":DOMAIN,
            "tls":"tls" if tls else "none","sni":DOMAIN if tls else ""
        }).encode()).decode()
        tls  = "vmess://" + j(443,True,"/vmess")
        ntls = "vmess://" + j(80,False,"/vmess")
        gj   = base64.b64encode(json.dumps({
            "v":"2","ps":uname,"add":DOMAIN,"port":"10444","id":uid,
            "aid":"0","net":"grpc","path":"vmess-grpc","type":"none","tls":"tls","sni":DOMAIN
        }).encode()).decode()
        grpc = "vmess://" + gj
    elif proto == 'vless':
        tls  = f"vless://{uid}@bug.com:443?path=%2Fvless&security=tls&encryption=none&host={DOMAIN}&type=ws&sni={DOMAIN}#{uname}"
        ntls = f"vless://{uid}@bug.com:80?path=%2Fvless&security=none&encryption=none&host={DOMAIN}&type=ws#{uname}"
        grpc = f"vless://{uid}@{DOMAIN}:10444?mode=gun&security=tls&encryption=none&type=grpc&serviceName=vless-grpc&sni={DOMAIN}#{uname}"
    else:
        tls  = f"trojan://{uid}@bug.com:443?path=%2Ftrojan&security=tls&host={DOMAIN}&type=ws&sni={DOMAIN}#{uname}"
        ntls = f"trojan://{uid}@bug.com:80?path=%2Ftrojan&security=none&host={DOMAIN}&type=ws#{uname}"
        grpc = f"trojan://{uid}@{DOMAIN}:10444?mode=gun&security=tls&type=grpc&serviceName=trojan-grpc&sni={DOMAIN}#{uname}"
    return tls, ntls, grpc

def xray_add(proto, uname, days=30):
    uid = str(uuid.uuid4())
    exp = (datetime.now() + timedelta(days=days)).strftime('%d %b, %Y')
    created = datetime.now().strftime('%d %b, %Y')
    if proto == 'vmess':
        cmd = f'jq --arg uid "{uid}" --arg em "{uname}" \'(.inbounds[] | select(.tag | startswith("vmess")).settings.clients) += [{{"id":$uid,"email":$em,"alterId":0}}]\' {XRAY_CFG} > /tmp/_xr.json && mv /tmp/_xr.json {XRAY_CFG} && chmod 644 {XRAY_CFG} && systemctl reload xray 2>/dev/null || systemctl restart xray'
    elif proto == 'vless':
        cmd = f'jq --arg uid "{uid}" --arg em "{uname}" \'(.inbounds[] | select(.tag | startswith("vless")).settings.clients) += [{{"id":$uid,"email":$em}}]\' {XRAY_CFG} > /tmp/_xr.json && mv /tmp/_xr.json {XRAY_CFG} && chmod 644 {XRAY_CFG} && systemctl reload xray 2>/dev/null || systemctl restart xray'
    else:
        cmd = f'jq --arg pw "{uid}" --arg em "{uname}" \'(.inbounds[] | select(.tag | startswith("trojan")).settings.clients) += [{{"password":$pw,"email":$em}}]\' {XRAY_CFG} > /tmp/_xr.json && mv /tmp/_xr.json {XRAY_CFG} && chmod 644 {XRAY_CFG} && systemctl reload xray 2>/dev/null || systemctl restart xray'
    rc, out = run(cmd)
    if rc != 0: return None, None, None, None, None
    with open(f'{AKUN_DIR}/{proto}-{uname}.txt','w') as f:
        f.write(f'UUID={uid}\nQUOTA=100\nIPLIMIT=1\nEXPIRED={exp}\nCREATED={created}\n')
    return uid, exp, *make_links(proto, uname, uid)

def kb_main():
    return {'keyboard':[
        ['🆓 Trial Gratis','🛒 Order VPN'],
        ['📋 Cek Akun','ℹ️ Info Server'],
        ['❓ Bantuan','📞 Hubungi Admin']
    ],'resize_keyboard':True}

def kb_trial():
    return {'inline_keyboard':[[
        {'text':'VMess','callback_data':'trial_vmess'},
        {'text':'VLess','callback_data':'trial_vless'},
        {'text':'Trojan','callback_data':'trial_trojan'}
    ],[ {'text':'◀️ Kembali','callback_data':'back'} ]]}

def kb_order():
    return {'inline_keyboard':[[
        {'text':'VMess','callback_data':'order_vmess'},
        {'text':'VLess','callback_data':'order_vless'},
        {'text':'Trojan','callback_data':'order_trojan'}
    ],[ {'text':'◀️ Kembali','callback_data':'back'} ]]}

def kb_confirm(oid):
    return {'inline_keyboard':[[
        {'text':'✅ Konfirmasi','callback_data':f'confirm_{oid}'},
        {'text':'❌ Tolak','callback_data':f'reject_{oid}'}
    ]]}

def do_trial(proto, cid):
    uname = f'trial-{datetime.now().strftime("%H%M%S")}'
    ip = get_ip()
    exp = (datetime.now() + timedelta(hours=1)).strftime('%d %b %Y %H:%M')
    uid, _, tls, ntls, grpc = xray_add(proto, uname, days=1)
    if not uid:
        send(cid, '❌ Gagal buat akun trial.'); return
    run(f'(sleep 3600; jq --arg em "{uname}" \'del(.inbounds[].settings.clients[]? | select(.email==$em))\' {XRAY_CFG} > /tmp/_xd.json && mv /tmp/_xd.json {XRAY_CFG}; systemctl reload xray 2>/dev/null; rm -f {AKUN_DIR}/{proto}-{uname}.txt) &')
    msg = f'''✅ <b>Trial {proto.upper()} (1 Jam)</b>
━━━━━━━━━━━━━━━━━━━━━━━
👤 <code>{uname}</code>
🔑 <code>{uid}</code>
🌐 Domain: <code>{DOMAIN}</code>
━━━━━━━━━━━━━━━━━━━━━━━
🔗 <b>TLS (port 443):</b>
<code>{tls}</code>
━━━━━━━━━━━━━━━━━━━━━━━
🔗 <b>NonTLS (port 80):</b>
<code>{ntls}</code>
━━━━━━━━━━━━━━━━━━━━━━━
⏰ Expired: {exp}
⚠️ Auto hapus 1 jam'''
    send(cid, msg, markup=kb_main())

def handle_msg(msg):
    cid  = msg['chat']['id']
    text = msg.get('text','').strip()
    fname = msg['from'].get('first_name','User')
    uname = msg['from'].get('username','')
    with lock: s = dict(state.get(cid, {}))

    if s.get('step') == 'wait_username':
        new_u = text.replace(' ','_')
        if len(new_u) < 3:
            send(cid, '❌ Username min 3 karakter!'); return
        proto = s['proto']
        oid = f'{cid}_{int(time.time())}'
        order = {'order_id':oid,'chat_id':cid,'username':new_u,'protocol':proto,
                 'status':'pending','tg_user':uname,'tg_name':fname}
        with open(f'{ORDER_DIR}/{oid}.json','w') as f: json.dump(order, f)
        with lock: state.pop(cid, None)
        pay = get_payment()
        send(cid, f'''🛒 <b>Order {proto.upper()}</b>
👤 Username: <code>{new_u}</code>
💰 Nominal: Rp {int(pay["HARGA"]):,}
🏦 {pay["REK_BANK"]}: {pay["REK_NUMBER"]}
<i>Transfer & kirim bukti ke admin</i>''')
        send(ADMIN_ID, f'🔔 <b>ORDER BARU</b>\n📦 {proto.upper()}\n👤 <code>{new_u}</code>\n📱 @{uname}', markup=kb_confirm(oid))
        return

    with lock: state.pop(cid, None)
    if text in ['/start','🏠 Menu']:
        send(cid, f'👋 Halo <b>{fname}</b>!\n🤖 Youzin Crabz Tunel\n🌐 <code>{DOMAIN}</code>', markup=kb_main())
    elif text == '🆓 Trial Gratis':
        send(cid, '🆓 Pilih protocol:', markup=kb_trial())
    elif text == '🛒 Order VPN':
        send(cid, '🛒 Pilih protocol:', markup=kb_order())
    elif text == '📋 Cek Akun':
        found = []
        for fn in os.listdir(ORDER_DIR) if os.path.exists(ORDER_DIR) else []:
            if not fn.endswith('.json'): continue
            try:
                with open(f'{ORDER_DIR}/{fn}') as f: d = json.load(f)
                if str(d.get('chat_id')) == str(cid) and d.get('status') == 'confirmed':
                    found.append(d)
            except: pass
        if not found: send(cid, '📋 Tidak ada akun aktif.', markup=kb_main())
        else:
            txt = '📋 <b>Akun Aktif:</b>\n'
            for a in found: txt += f'• {a["protocol"].upper()} → <code>{a["username"]}</code>\n'
            send(cid, txt, markup=kb_main())
    elif text == 'ℹ️ Info Server':
        ip = get_ip()
        send(cid, f'ℹ️ <b>INFO SERVER</b>\n🌐 Domain: <code>{DOMAIN}</code>\n🖥️ IP: <code>{ip}</code>\n🔌 TLS: 443 | NonTLS: 80 | gRPC: 10444', markup=kb_main())
    elif text == '❓ Bantuan':
        send(cid, '❓ <b>Cara Order:</b>\n1. Klik 🛒 Order VPN\n2. Pilih protokol\n3. Ketik username\n4. Transfer ke rekening\n5. Admin konfirmasi', markup=kb_main())
    elif text == '📞 Hubungi Admin':
        send(cid, '📞 Pesan diteruskan ke admin.', markup=kb_main())
        send(ADMIN_ID, f'📞 <b>{fname}</b> (@{uname}) butuh bantuan!\n🆔 <code>{cid}</code>')

def handle_cb(cb):
    cid  = cb['message']['chat']['id']
    data = cb['data']
    uname = cb['from'].get('username','')
    api('answerCallbackQuery', {'callback_query_id': cb['id']})

    if data.startswith('trial_'):
        proto = data[6:]
        send(cid, f'⏳ Membuat trial {proto.upper()}...')
        threading.Thread(target=do_trial, args=(proto, cid), daemon=True).start()
    elif data.startswith('order_'):
        proto = data[6:]
        with lock: state[cid] = {'step':'wait_username','proto':proto}
        send(cid, f'📝 Ketik username untuk {proto.upper()}:')
    elif data == 'back':
        send(cid, '🏠 Menu Utama', markup=kb_main())
    elif data.startswith('confirm_') and cid == ADMIN_ID:
        oid = data[8:]
        try:
            with open(f'{ORDER_DIR}/{oid}.json') as f: order = json.load(f)
        except: send(ADMIN_ID,'❌ Order tidak ada!'); return
        if order.get('status') != 'pending': send(ADMIN_ID,'⚠️ Sudah diproses!'); return
        send(ADMIN_ID,'⏳ Membuat akun...')
        def do_confirm():
            uid, exp, tls, ntls, grpc = xray_add(order['protocol'], order['username'])
            if not uid: send(ADMIN_ID,'❌ Gagal buat akun!'); return
            order['status'] = 'confirmed'
            with open(f'{ORDER_DIR}/{oid}.json','w') as f: json.dump(order, f)
            msg = f'''✅ <b>Akun {order["protocol"].upper()} Berhasil!</b>
👤 <code>{order["username"]}</code>
🔑 <code>{uid}</code>
🌐 <code>{DOMAIN}</code>
━━━━━━━━━━━━━━━━━━━━━━━
🔗 TLS: <code>{tls}</code>
🔗 NonTLS: <code>{ntls}</code>
🔗 gRPC: <code>{grpc}</code>
━━━━━━━━━━━━━━━━━━━━━━━
📅 Expired: {exp}'''
            send(order['chat_id'], msg, markup=kb_main())
            send(ADMIN_ID, f'✅ Akun dikirim ke @{order.get("tg_user","?")}')
        threading.Thread(target=do_confirm, daemon=True).start()
    elif data.startswith('reject_') and cid == ADMIN_ID:
        oid = data[7:]
        try:
            with open(f'{ORDER_DIR}/{oid}.json') as f: order = json.load(f)
            order['status'] = 'rejected'
            with open(f'{ORDER_DIR}/{oid}.json','w') as f: json.dump(order, f)
            send(order['chat_id'], '❌ Order ditolak.', markup=kb_main())
        except: pass
        send(ADMIN_ID,'❌ Order ditolak.')

def main():
    print('Bot started!', flush=True)
    offset = 0
    while True:
        try:
            res = requests.get(f'{API}/getUpdates', params={'offset':offset,'timeout':20,'limit':50}, timeout=25)
            for upd in res.json().get('result',[]):
                offset = upd['update_id'] + 1
                if 'message' in upd:
                    threading.Thread(target=handle_msg, args=(upd['message'],), daemon=True).start()
                elif 'callback_query' in upd:
                    threading.Thread(target=handle_cb, args=(upd['callback_query'],), daemon=True).start()
        except: time.sleep(3)

if __name__ == '__main__': main()
BOTEOF

    chmod +x /root/bot/bot.py

    cat > /etc/systemd/system/vpn-bot.service << 'SVCEOF'
[Unit]
Description=Youzin Crabz Tunel Bot
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 -u /root/bot/bot.py
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
SVCEOF

    systemctl daemon-reload
    systemctl enable vpn-bot 2>/dev/null
    systemctl restart vpn-bot 2>/dev/null
}

menu_telegram_bot() {
    while true; do
        clear; print_menu_header "TELEGRAM BOT"
        local W; W=$(get_width)
        local bs; bs=$(check_status vpn-bot)
        local cs
        [[ "$bs" == "ON" ]] && cs="${GREEN}RUNNING${NC}" || cs="${RED}STOPPED${NC}"
        _box_top $W
        _box_center $W "${YELLOW}${BOLD}TELEGRAM BOT${NC}"
        _box_divider $W
        _box_left $W "Status : ${cs}"
        _box_divider $W
        _box_left $W "[1] Setup Bot"
        _box_left $W "[2] Start Bot"
        _box_left $W "[3] Stop Bot"
        _box_left $W "[4] Restart Bot"
        _box_left $W "[5] Lihat Log"
        _box_divider $W
        _box_left $W "${RED}[0] Back${NC}"
        _box_bottom $W
        echo ""
        read -p "  Select [0-5]: " choice
        case $choice in
            1) setup_telegram_bot ;;
            2) systemctl start vpn-bot && echo -e "  ${GREEN}✔ Started!${NC}"; sleep 2 ;;
            3) systemctl stop vpn-bot && echo -e "  ${YELLOW}Stopped!${NC}"; sleep 2 ;;
            4) systemctl restart vpn-bot && echo -e "  ${GREEN}✔ Restarted!${NC}"; sleep 2 ;;
            5) clear; journalctl -u vpn-bot -n 50 --no-pager; echo ""; read -p "  Press any key..." ;;
            0) return ;;
        esac
    done
}

#================================================
# CHANGE DOMAIN & FIX SSL
#================================================

change_domain() {
    clear; print_menu_header "CHANGE DOMAIN"
    echo -e "  Current: ${GREEN}${DOMAIN:-Not Set}${NC}"
    echo ""
    setup_domain
    echo -e "  ${YELLOW}Jalankan Fix Certificate [11]!${NC}"
    sleep 3
}

fix_certificate() {
    clear; print_menu_header "FIX / RENEW CERTIFICATE"
    [[ -f "$DOMAIN_FILE" ]] && DOMAIN=$(tr -d '\n\r' < "$DOMAIN_FILE" | xargs)
    [[ -z "$DOMAIN" ]] && { echo -e "  ${RED}✘ Domain belum diset!${NC}"; sleep 3; return; }
    echo -e "  Domain: ${GREEN}${DOMAIN}${NC}"
    echo ""
    get_ssl_cert
    systemctl restart xray haproxy 2>/dev/null
    echo -e "  ${GREEN}✔ Done!${NC}"
    sleep 3
}

#================================================
# SPEEDTEST
#================================================

run_speedtest() {
    clear; print_menu_header "SPEEDTEST BY OOKLA"
    if ! command -v speedtest >/dev/null 2>&1; then
        echo -e "  ${CYAN}Installing Speedtest CLI...${NC}"
        curl -s https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.deb.sh \
            | bash >/dev/null 2>&1
        apt-get install -y speedtest >/dev/null 2>&1
    fi
    echo -e "  ${YELLOW}Testing... harap tunggu ~30 detik${NC}"
    echo ""
    local result
    if command -v speedtest >/dev/null 2>&1; then
        result=$(speedtest --accept-license --accept-gdpr 2>/dev/null)
        if [[ -n "$result" ]]; then
            local server latency dl ul url
            server=$(echo "$result" | grep "Server:" | sed 's/.*Server: //')
            latency=$(echo "$result" | grep "Latency:" | awk '{print $2,$3}')
            dl=$(echo "$result" | grep "Download:" | awk '{print $2,$3}')
            ul=$(echo "$result" | grep "Upload:" | awk '{print $2,$3}')
            url=$(echo "$result" | grep "Result URL:" | awk '{print $NF}')
            echo -e "  ${WHITE}Server   ${NC}: ${GREEN}${server}${NC}"
            echo -e "  ${WHITE}Latency  ${NC}: ${GREEN}${latency}${NC}"
            echo -e "  ${WHITE}Download ${NC}: ${GREEN}${dl}${NC}"
            echo -e "  ${WHITE}Upload   ${NC}: ${GREEN}${ul}${NC}"
            [[ -n "$url" ]] && echo -e "  ${WHITE}Result   ${NC}: ${CYAN}${url}${NC}"
        else
            echo -e "  ${RED}✘ Speedtest gagal!${NC}"
        fi
    else
        echo -e "  ${RED}✘ Speedtest tidak tersedia!${NC}"
    fi
    echo ""
    read -p "  Press any key to back..."
}

#================================================
# UPDATE SCRIPT
#================================================

update_menu() {
    clear; print_menu_header "UPDATE SCRIPT"
    echo -e "  Current Version : ${GREEN}${SCRIPT_VERSION}${NC}"
    echo ""
    local latest
    latest=$(curl -s --max-time 10 "$VERSION_URL" 2>/dev/null | tr -d '\n\r ' | xargs)
    if [[ -z "$latest" ]]; then
        echo -e "  ${RED}✘ Cannot connect to GitHub!${NC}"
        echo ""; read -p "  Press Enter to back..."; return
    fi
    echo -e "  Latest Version  : ${GREEN}${latest}${NC}"
    echo ""
    if [[ "$latest" == "$SCRIPT_VERSION" ]]; then
        echo -e "  ${GREEN}✔ Script sudah versi terbaru!${NC}"
        echo ""; read -p "  Press Enter to back..."; return
    fi
    read -p "  Update now? [y/N]: " confirm
    [[ "$confirm" != "y" ]] && return
    cp "$SCRIPT_PATH" "$BACKUP_PATH" 2>/dev/null
    local tmp="/tmp/tunnel_new.sh"
    curl -L --max-time 60 "$SCRIPT_URL" -o "$tmp" 2>/dev/null
    if [[ ! -s "$tmp" ]]; then
        echo -e "  ${RED}✘ Download failed!${NC}"
        read -p "  Press Enter to back..."; return
    fi
    bash -n "$tmp" 2>/dev/null && {
        mv "$tmp" "$SCRIPT_PATH"
        chmod +x "$SCRIPT_PATH"
        echo -e "  ${GREEN}✔ Update sukses!${NC}"
        sleep 2
        exec bash "$SCRIPT_PATH"
    } || {
        echo -e "  ${RED}✘ Syntax error!${NC}"
        rm -f "$tmp"
        read -p "  Press Enter to back..."
    }
}

#================================================
# BACKUP / RESTORE
#================================================

_menu_backup() {
    clear; print_menu_header "BACKUP SYSTEM"
    local backup_dir="/root/backups"
    local backup_file="vpn-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
    mkdir -p "$backup_dir"
    tar -czf "$backup_dir/$backup_file" \
        /root/domain /root/.domain_type /root/akun \
        /root/.bot_token /root/.chat_id /root/.payment_info \
        /etc/xray/xray.crt /etc/xray/xray.key \
        /usr/local/etc/xray/config.json 2>/dev/null
    if [[ -f "$backup_dir/$backup_file" ]]; then
        echo -e "  ${GREEN}✔ Backup created!${NC}"
        echo -e "  File : ${WHITE}${backup_file}${NC}"
        echo -e "  Size : ${CYAN}$(du -h "$backup_dir/$backup_file" | awk '{print $1}')${NC}"
    else
        echo -e "  ${RED}✘ Backup failed!${NC}"
    fi
    echo ""; read -p "  Press any key to back..."
}

_menu_restore() {
    clear; print_menu_header "RESTORE SYSTEM"
    local backup_dir="/root/backups"
    [[ ! -d "$backup_dir" ]] && { echo -e "  ${RED}No backup!${NC}"; sleep 2; return; }
    shopt -s nullglob
    local backups=($(ls -t "$backup_dir"/*.tar.gz 2>/dev/null))
    shopt -u nullglob
    [[ ${#backups[@]} -eq 0 ]] && { echo -e "  ${RED}No backups!${NC}"; sleep 2; return; }
    local i=1
    for b in "${backups[@]}"; do
        printf "  ${CYAN}[%d]${NC} %s\n" "$i" "$(basename "$b")"
        ((i++))
    done
    echo ""
    read -p "  Select [1-${#backups[@]}] atau 0 cancel: " choice
    [[ "$choice" == "0" ]] && return
    local selected="${backups[$((choice-1))]}"
    read -p "  Continue? [y/N]: " confirm
    [[ "$confirm" != "y" ]] && return
    tar -xzf "$selected" -C / 2>/dev/null && \
        echo -e "  ${GREEN}✔ Restore OK!${NC}" || \
        echo -e "  ${RED}✘ Restore failed!${NC}"
    systemctl restart xray nginx haproxy 2>/dev/null
    echo ""; read -p "  Press any key to back..."
}

#================================================
# LIST ALL ACCOUNTS
#================================================

_menu_list_all() {
    clear; print_menu_header "ALL ACCOUNTS"
    local total=0
    shopt -s nullglob
    for proto in ssh vmess vless trojan; do
        local files=("$AKUN_DIR"/${proto}-*.txt)
        [[ ${#files[@]} -eq 0 ]] && continue
        echo -e "  ${GREEN}── ${proto^^} ────────────────────────────────────${NC}"
        for f in "${files[@]}"; do
            local uname exp
            uname=$(basename "$f" .txt | sed "s/${proto}-//")
            exp=$(grep "EXPIRED" "$f" 2>/dev/null | cut -d= -f2-)
            printf "  ${CYAN}▸${NC} ${GREEN}%-20s${NC} ${YELLOW}%s${NC}\n" "$uname" "$exp"
            ((total++))
        done
        echo ""
    done
    shopt -u nullglob
    echo -e "  ${WHITE}Total: ${GREEN}${total}${NC} accounts"
    echo ""; read -p "  Press any key to back..."
}

#================================================
# UNINSTALL
#================================================

menu_uninstall() {
    while true; do
        clear; print_menu_header "UNINSTALL MENU"
        local W; W=$(get_width)
        _box_top $W
        _box_center $W "${YELLOW}${BOLD}UNINSTALL${NC}"
        _box_divider $W
        _box_left $W "[1] Uninstall Xray"
        _box_left $W "[2] Uninstall Nginx"
        _box_left $W "[3] Uninstall HAProxy"
        _box_left $W "[4] Uninstall Dropbear"
        _box_left $W "[5] Uninstall UDP Custom"
        _box_left $W "[6] Uninstall Bot"
        _box_divider $W
        _box_left $W "${RED}[7] HAPUS SEMUA${NC}"
        _box_divider $W
        _box_left $W "${RED}[0] Back${NC}"
        _box_bottom $W
        echo ""
        read -p "  Select [0-7]: " choice
        case $choice in
            1) read -p "  Yakin? [y/n]: " c; [[ "$c" == "y" ]] && {
                   systemctl stop xray; systemctl disable xray
                   bash <(curl -Ls https://github.com/XTLS/Xray-install/raw/main/install-release.sh) --remove >/dev/null 2>&1
                   echo -e "  ${GREEN}✔ Done!${NC}"; sleep 2; } ;;
            2) read -p "  Yakin? [y/n]: " c; [[ "$c" == "y" ]] && {
                   systemctl stop nginx; apt-get purge -y nginx >/dev/null 2>&1
                   echo -e "  ${GREEN}✔ Done!${NC}"; sleep 2; } ;;
            3) read -p "  Yakin? [y/n]: " c; [[ "$c" == "y" ]] && {
                   systemctl stop haproxy; apt-get purge -y haproxy >/dev/null 2>&1
                   echo -e "  ${GREEN}✔ Done!${NC}"; sleep 2; } ;;
            4) read -p "  Yakin? [y/n]: " c; [[ "$c" == "y" ]] && {
                   systemctl stop dropbear; apt-get purge -y dropbear >/dev/null 2>&1
                   echo -e "  ${GREEN}✔ Done!${NC}"; sleep 2; } ;;
            5) read -p "  Yakin? [y/n]: " c; [[ "$c" == "y" ]] && {
                   systemctl stop udp-custom; systemctl disable udp-custom
                   rm -f /etc/systemd/system/udp-custom.service /usr/local/bin/udp-custom
                   systemctl daemon-reload; echo -e "  ${GREEN}✔ Done!${NC}"; sleep 2; } ;;
            6) read -p "  Yakin? [y/n]: " c; [[ "$c" == "y" ]] && {
                   systemctl stop vpn-bot; systemctl disable vpn-bot
                   rm -f /etc/systemd/system/vpn-bot.service; rm -rf /root/bot
                   rm -f "$BOT_TOKEN_FILE" "$CHAT_ID_FILE" "$PAYMENT_FILE"
                   systemctl daemon-reload; echo -e "  ${GREEN}✔ Done!${NC}"; sleep 2; } ;;
            7)
                read -p "  Ketik 'HAPUS' untuk konfirmasi: " confirm
                [[ "$confirm" != "HAPUS" ]] && { echo -e "  ${YELLOW}Dibatalkan.${NC}"; sleep 2; continue; }
                for svc in xray nginx haproxy dropbear udp-custom vpn-keepalive vpn-bot; do
                    systemctl stop "$svc" 2>/dev/null; systemctl disable "$svc" 2>/dev/null
                done
                bash <(curl -Ls https://github.com/XTLS/Xray-install/raw/main/install-release.sh) --remove >/dev/null 2>&1
                apt-get purge -y nginx haproxy dropbear >/dev/null 2>&1
                rm -rf /usr/local/etc/xray /var/log/xray /etc/xray /root/akun /root/bot /root/orders \
                       /root/domain /root/.domain_type /root/.bot_token /root/.chat_id /root/.payment_info
                rm -f /etc/systemd/system/udp-custom.service /etc/systemd/system/vpn-keepalive.service \
                      /etc/systemd/system/vpn-bot.service /usr/local/bin/udp-custom \
                      /usr/local/bin/vpn-keepalive.sh /usr/local/bin/menu /root/tunnel.sh
                sed -i '/tunnel.sh/d' /root/.bashrc 2>/dev/null
                systemctl daemon-reload
                echo -e "  ${GREEN}✔ Semua dihapus!${NC}"; sleep 3; exit 0 ;;
            0) return ;;
        esac
    done
}

#================================================
# AUTO INSTALL
#================================================

auto_install() {
    show_install_banner
    setup_domain
    [[ -z "$DOMAIN" ]] && { echo -e "  ${RED}✘ Domain kosong!${NC}"; exit 1; }

    local domain_type="custom"
    [[ -f "$DOMAIN_TYPE_FILE" ]] && domain_type=$(cat "$DOMAIN_TYPE_FILE")

    clear; show_install_banner
    echo -e "  ${WHITE}Domain   :${NC} ${GREEN}${DOMAIN}${NC}"
    echo -e "  ${WHITE}SSL Type :${NC} ${GREEN}$([[ "$domain_type" == "custom" ]] && echo "Let's Encrypt" || echo "Self-Signed")${NC}"
    echo ""

    local LOG="/tmp/install.log"
    > "$LOG"

    _run() {
        local label="$1" cmd="$2"
        printf "  ${CYAN}►${NC} %-45s" "${label}..."
        eval "$cmd" >> "$LOG" 2>&1
        local ret=$?
        [[ $ret -eq 0 ]] && printf "${GREEN}OK${NC}\n" || printf "${RED}FAIL${NC}\n"
        return $ret
    }

    _pkg() {
        printf "  ${CYAN}►${NC} %-45s" "Installing ${1}..."
        DEBIAN_FRONTEND=noninteractive apt-get install -y "$1" >> "$LOG" 2>&1
        [[ $? -eq 0 ]] && printf "${GREEN}OK${NC}\n" || printf "${RED}FAIL${NC}\n"
    }

    echo -e "\n  ${YELLOW}[1/9] System Update${NC}"
    _run "apt-get update" "apt-get update -y"
    _run "apt-get upgrade" "DEBIAN_FRONTEND=noninteractive apt-get upgrade -y"

    echo -e "\n  ${YELLOW}[2/9] Base Packages${NC}"
    for pkg in curl wget unzip uuid-runtime net-tools openssl jq python3 python3-pip; do
        _pkg "$pkg"
    done

    echo -e "\n  ${YELLOW}[3/9] VPN Services${NC}"
    for pkg in nginx openssh-server dropbear haproxy certbot; do
        _pkg "$pkg"
    done

    echo -e "\n  ${YELLOW}[4/9] Installing Xray-Core${NC}"
    _run "Xray install" "bash <(curl -Ls https://github.com/XTLS/Xray-install/raw/main/install-release.sh)"
    mkdir -p "$AKUN_DIR" /var/log/xray /usr/local/etc/xray "$PUBLIC_HTML" "$ORDER_DIR" /root/bot

    echo -e "\n  ${YELLOW}[5/9] Setup Swap Memory${NC}"
    setup_swap && done_msg "Swap 1GB ready"

    echo -e "\n  ${YELLOW}[6/9] SSL Certificate${NC}"
    mkdir -p /etc/xray
    if [[ "$domain_type" == "custom" ]]; then
        _run "Certbot Let's Encrypt" "certbot certonly --standalone -d '$DOMAIN' --non-interactive --agree-tos --register-unsafely-without-email"
        if [[ -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]]; then
            cp "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" /etc/xray/xray.crt
            cp "/etc/letsencrypt/live/$DOMAIN/privkey.pem" /etc/xray/xray.key
            done_msg "Let's Encrypt cert installed"
        else
            _run "Self-signed cert" "_gen_self_signed"
            done_msg "Self-signed cert generated"
        fi
    else
        _run "Self-signed cert" "_gen_self_signed"
        done_msg "Self-signed cert generated"
    fi
    chmod 644 /etc/xray/xray.* 2>/dev/null

    echo -e "\n  ${YELLOW}[7/9] Creating Configs${NC}"
    _run "Xray config (anti-tabrakan)" "create_xray_config"
    done_msg "Port 10443(TLS) 10080(NonTLS) 10444(gRPC)"

    _run "Nginx config" "configure_nginx"
    nginx -t >> "$LOG" 2>&1 && done_msg "Nginx config valid" || fail_msg "Nginx config error"

    _run "HAProxy config" "configure_haproxy"
    done_msg "HAProxy 443 → Xray 10443"

    cat > /etc/default/dropbear << 'DBEOF'
NO_START=0
DROPBEAR_PORT=222
DROPBEAR_EXTRA_ARGS="-K 60 -I 180"
DROPBEAR_RECEIVE_WINDOW=65536
DBEOF
    done_msg "Dropbear port 222"

    echo -e "\n  ${YELLOW}[8/9] UDP, Keepalive & Optimize${NC}"
    _run "UDP Custom 7100-7300" "install_udp_custom"
    _run "SSH keepalive" "setup_keepalive"
    _run "BBR & TCP tuning" "optimize_vpn"
    _run "Python requests" "pip3 install requests --break-system-packages"

    echo -e "\n  ${YELLOW}[9/9] Starting Services${NC}"
    systemctl daemon-reload >> "$LOG" 2>&1
    for svc in xray nginx sshd dropbear haproxy udp-custom vpn-keepalive; do
        systemctl enable "$svc" >> "$LOG" 2>&1
        systemctl restart "$svc" >> "$LOG" 2>&1
        systemctl is-active --quiet "$svc" && \
            printf "  ${GREEN}✔${NC} %-20s ${GREEN}RUNNING${NC}\n" "$svc" || \
            printf "  ${RED}✘${NC} %-20s ${RED}FAILED${NC}\n" "$svc"
    done

    setup_menu_command

    local ip_vps; ip_vps=$(get_ip)
    cat > "$PUBLIC_HTML/index.html" << IDXEOF
<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Youzin Crabz Tunel</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Courier New',monospace;background:#0a0a1a;color:#eee;display:flex;align-items:center;justify-content:center;min-height:100vh;text-align:center}.box{padding:40px;background:#0d1117;border:1px solid #00d4ff44;border-radius:12px;max-width:500px}h1{color:#00d4ff;margin-bottom:5px;font-size:1.8em;letter-spacing:2px}.sub{color:#7ee8fa;font-size:0.9em;margin-bottom:15px}p{color:#666;margin:4px 0;font-size:0.85em}.badge{display:inline-block;background:#00d4ff22;color:#00d4ff;padding:4px 16px;border-radius:20px;margin-top:15px;font-size:12px;letter-spacing:1px;border:1px solid #00d4ff33}</style>
</head><body><div class="box"><h1>⚡ YOUZIN CRABZ</h1><div class="sub">T U N E L v${SCRIPT_VERSION}</div><p>${DOMAIN}</p><p>${ip_vps}</p><div class="badge">The Professor</div></div></body></html>
IDXEOF

    # Verifikasi WebSocket berjalan
    sleep 2
    local ws_test
    ws_test=$(curl -s -o /dev/null -w "%{http_code}" \
        --http1.1 \
        -H "Upgrade: websocket" \
        -H "Connection: Upgrade" \
        http://localhost:10080/vmess 2>/dev/null)
    if [[ "$ws_test" == "400" ]] || [[ "$ws_test" == "101" ]]; then
        done_msg "WebSocket Xray OK (port 10080)"
    else
        fail_msg "WebSocket test gagal (code: $ws_test)"
    fi

    echo ""
    echo -e "${GREEN}  ╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}  ║      ✔  INSTALASI SELESAI!                       ║${NC}"
    echo -e "${GREEN}  ║      Youzin Crabz Tunel v${SCRIPT_VERSION} - The Professor  ║${NC}"
    echo -e "${GREEN}  ╚══════════════════════════════════════════════════╝${NC}"
    echo ""
    printf "  ${WHITE}%-22s${NC}: ${GREEN}%s${NC}\n" "Domain"       "$DOMAIN"
    printf "  ${WHITE}%-22s${NC}: ${GREEN}%s${NC}\n" "IP VPS"       "$ip_vps"
    printf "  ${WHITE}%-22s${NC}: ${CYAN}%s${NC}\n"  "SSH"          "22 | Dropbear: 222"
    printf "  ${WHITE}%-22s${NC}: ${CYAN}%s${NC}\n"  "TLS (HAProxy)" "443 → path /vmess /vless /trojan"
    printf "  ${WHITE}%-22s${NC}: ${CYAN}%s${NC}\n"  "NonTLS (Nginx)" "80 → path /vmess /vless /trojan"
    printf "  ${WHITE}%-22s${NC}: ${CYAN}%s${NC}\n"  "gRPC TLS"     "10444"
    printf "  ${WHITE}%-22s${NC}: ${CYAN}%s${NC}\n"  "BadVPN UDP"   "7100-7300"
    printf "  ${WHITE}%-22s${NC}: ${CYAN}%s${NC}\n"  "Download"     "http://${ip_vps}:81/"
    echo ""
    echo -e "  ${YELLOW}💡 Ketik 'menu' untuk membuka menu!${NC}"
    echo -e "  ${YELLOW}Reboot dalam 5 detik...${NC}"
    sleep 5
    reboot
}

#================================================
# MAIN MENU
#================================================

main_menu() {
    while true; do
        show_system_info
        show_menu
        printf "${YELLOW}${BOLD}➤ ENTER OPTION [0-20] : ${NC}"
        read -r choice

        case $choice in
            1|01) menu_ssh ;;
            2|02) menu_vmess ;;
            3|03) menu_vless ;;
            4|04) menu_trojan ;;
            5|05)
                clear; print_menu_header "TRIAL XRAY GENERATOR"
                echo -e "  ${CYAN}[1]${NC} VMess  ${CYAN}[2]${NC} VLess  ${CYAN}[3]${NC} Trojan  ${CYAN}[0]${NC} Back"
                read -p "  Select: " trial_choice
                case $trial_choice in
                    1) create_trial_xray "vmess" ;;
                    2) create_trial_xray "vless" ;;
                    3) create_trial_xray "trojan" ;;
                esac ;;
            6|06) _menu_list_all ;;
            7|07) cek_expired ;;
            8|08) delete_expired ;;
            9|09) menu_telegram_bot ;;
            10) change_domain ;;
            11) fix_certificate ;;
            12)
                clear; optimize_vpn
                echo -e "  ${GREEN}✔ Optimization done!${NC}"; sleep 2 ;;
            13)
                clear; print_menu_header "RESTART ALL SERVICES"
                for svc in xray nginx sshd dropbear haproxy udp-custom vpn-keepalive vpn-bot; do
                    systemctl restart "$svc" 2>/dev/null && \
                        printf "  ${GREEN}✔${NC} %-20s ${GREEN}Restarted${NC}\n" "$svc" || \
                        printf "  ${RED}✘${NC} %-20s ${RED}Failed${NC}\n" "$svc"
                done
                echo ""; sleep 2 ;;
            14) show_info_port ;;
            15) run_speedtest ;;
            16) update_menu ;;
            17) _menu_backup ;;
            18) _menu_restore ;;
            19) menu_uninstall ;;
            20) echo -e "  ${YELLOW}Advanced mode tidak tersedia di versi ini.${NC}"; sleep 2 ;;
            0|00)
                clear; echo -e "  ${CYAN}Goodbye! — Youzin Crabz Tunel${NC}"; exit 0 ;;
            *) ;;
        esac
    done
}

#================================================
# ENTRY POINT
#================================================

[[ $EUID -ne 0 ]] && {
    echo -e "${RED}Run as root!${NC}"
    echo "  sudo bash $0"
    exit 1
}

[[ -f "$DOMAIN_FILE" ]] && DOMAIN=$(tr -d '\n\r' < "$DOMAIN_FILE" | xargs)

if [[ ! -f "$DOMAIN_FILE" ]]; then
    auto_install
fi

setup_menu_command
main_menu
