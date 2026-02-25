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
# │  Xray VMess/VLess/Trojan WS TLS : 8443  │
# │  Xray VMess/VLess/Trojan WS NonTLS:8080 │
# │  Xray gRPC TLS  : 8444 (via 443)        │
# │  BadVPN UDP     : 7100-7300             │
# └─────────────────────────────────────────┘
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
SCRIPT_VERSION="4.1.0"
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
CRON_FILE="/etc/cron.d/vpn-panel"
FAIL2BAN_CONF="/etc/fail2ban/jail.local"
FIREWALL_RULES="/root/.firewall_rules"

#================================================
# PORT VARIABLES
#================================================
SSH_PORT="22"
DROPBEAR_PORT="222"
NGINX_PORT="80"
NGINX_DL_PORT="81"
HAPROXY_PORT="443"

# Xray internal ports - PERBAIKAN: 1 port per protokol group, bukan per path
# Port 8443: Semua WS TLS (VMess+VLess+Trojan dibedakan via path)
# Port 8080: Semua WS NonTLS
# Port 8444: Semua gRPC TLS
XRAY_WS_TLS_PORT="8443"
XRAY_WS_NONTLS_PORT="8080"
XRAY_GRPC_PORT="8444"

BADVPN_RANGE="7100-7300"
PRICE_MONTHLY="10000"

#================================================
# BOX DRAWING - FIXED ALIGNMENT
#================================================

str_len() {
    local s
    s=$(printf "%b" "$1" | sed 's/\x1b\[[0-9;]*m//g')
    echo ${#s}
}

get_width() {
    local tw
    tw=$(tput cols 2>/dev/null || echo 73)
    if   [ "$tw" -lt 60 ]; then echo 60
    elif [ "$tw" -gt 78 ]; then echo 78
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
    [ $pad -lt 0 ] && pad=0
    [ $pad_r -lt 0 ] && pad_r=0
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

# Menu dua kolom - rata kanan kiri sempurna
_box_two_col() {
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
    local pct=$1 bar_len=12 filled empty bar=""
    filled=$(( pct * bar_len / 100 ))
    empty=$(( bar_len - filled ))
    for i in $(seq 1 $filled); do bar="${bar}█"; done
    for i in $(seq 1 $empty); do bar="${bar}░"; done
    echo "$bar"
}

#================================================
# ANIMASI
#================================================

spinner_frames=('⣾' '⣽' '⣻' '⢿' '⡿' '⣟' '⣯' '⣷')

animated_loading() {
    local msg="$1" duration="${2:-2}" i=0
    local end=$((SECONDS + duration))
    while [[ $SECONDS -lt $end ]]; do
        local frame="${spinner_frames[$((i % 8))]}"
        local dots=""
        case $((i % 4)) in
            0) dots="   " ;; 1) dots=".  " ;; 2) dots=".. " ;; 3) dots="..." ;;
        esac
        printf "\r  ${CYAN}${frame}${NC} ${WHITE}${msg}${NC}${YELLOW}${dots}${NC}   "
        sleep 0.1; ((i++))
    done
    printf "\r  ${GREEN}✔${NC} ${WHITE}${msg}${NC} ${GREEN}[SELESAI]${NC}           \n"
}

done_msg() { printf "  ${GREEN}✔${NC} ${WHITE}%-42s${NC}\n" "$1"; }
fail_msg() { printf "  ${RED}✘${NC} ${WHITE}%-42s${NC}\n" "$1"; }
info_msg() { printf "  ${CYAN}◈${NC} %s\n" "$1"; }

#================================================
# UTILITY
#================================================

check_status() {
    systemctl is-active --quiet "$1" 2>/dev/null && echo "ON" || echo "OFF"
}

get_ip() {
    local ip
    for url in "https://ifconfig.me" "https://ipinfo.io/ip" "https://api.ipify.org" "https://checkip.amazonaws.com"; do
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
    curl -s -X POST "https://api.telegram.org/bot${token}/sendMessage" \
        -d chat_id="$chatid" -d text="$1" -d parse_mode="HTML" --max-time 10 >/dev/null 2>&1
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
# SHOW SYSTEM INFO - LAYOUT SEPERTI FOTO
#================================================

show_system_info() {
    clear
    [[ -f "$DOMAIN_FILE" ]] && DOMAIN=$(tr -d '\n\r' < "$DOMAIN_FILE" | xargs)

    local os_name="Unknown"
    [[ -f /etc/os-release ]] && { source /etc/os-release; os_name="${PRETTY_NAME}"; }

    local ip_vps ram_used ram_total ram_pct cpu uptime_str ssl_status svc_running svc_total

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
            # Cek expiry cert
            local cert_exp
            cert_exp=$(openssl x509 -enddate -noout -in "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" 2>/dev/null | cut -d= -f2)
            local days_left
            days_left=$(( ( $(date -d "$cert_exp" +%s 2>/dev/null || echo 0) - $(date +%s) ) / 86400 ))
            if [[ $days_left -gt 30 ]]; then
                ssl_status="${GREEN}LetsEncrypt (Active - ${days_left}d)${NC}"
            else
                ssl_status="${YELLOW}LetsEncrypt (Warn - ${days_left}d)${NC}"
            fi
        else
            ssl_status="${RED}LetsEncrypt (Missing)${NC}"
        fi
    else
        ssl_status="${CYAN}Self-Signed${NC}"
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

    # === HEADER ===
    _box_top $W
    _box_center $W "${YELLOW}${BOLD}✦ YOUZINCRABZ PANEL v${SCRIPT_VERSION} ✦${NC}"
    _box_center $W "${CYAN}The Professor${NC}"
    _box_bottom $W
    echo ""

    # === SERVER CORE STATUS ===
    _box_top $W
    _box_center $W "🖥  ${YELLOW}${BOLD}SERVER CORE STATUS${NC}"
    _box_divider $W
    _box_left $W "IP Address  : ${GREEN}${ip_vps}${NC}"
    _box_left $W "Domain      : ${GREEN}${DOMAIN:-N/A}${NC}"
    _box_left $W "OS          : ${WHITE}${os_name}${NC}"
    _box_left $W "Uptime      : ${WHITE}${uptime_str}${NC}"
    _box_left $W "CPU Load    : ${YELLOW}${cpu}%${NC}"
    _box_left $W "RAM Usage   : ${WHITE}${ram_used} / ${ram_total} MB${NC} ${CYAN}[${BAR}]${NC} ${YELLOW}${ram_pct}%${NC}"
    _box_left $W "SSL Status  : $(printf "%b" "$ssl_status")"
    _box_left $W "Services    : ${GREEN}${svc_running}/${svc_total} Running${NC}"
    _box_bottom $W
    echo ""

    # === ACTIVE ACCOUNTS - satu baris seperti foto ===
    _box_top $W
    _box_center $W "👥  ${YELLOW}${BOLD}ACTIVE ACCOUNTS${NC}"
    _box_divider $W
    local acc_line=" SSH: ${GREEN}${ssh_count}${NC}  |  VMess: ${GREEN}${vmess_count}${NC}  |  VLess: ${GREEN}${vless_count}${NC}  |  Trojan: ${GREEN}${trojan_count}${NC}"
    _box_center $W "$acc_line"
    _box_bottom $W
    echo ""

    # === NETWORK SERVICES - dua kolom ===
    _box_top $W
    _box_center $W "🔧  ${YELLOW}${BOLD}NETWORK SERVICES${NC}"
    _box_divider $W
    local svc_pairs=(
        "xray:XRAY" "nginx:NGINX"
        "haproxy:HAPROXY" "dropbear:DROPBEAR"
        "sshd:SSH" "udp-custom:UDP CUST"
        "vpn-bot:TELEGRAM" "vpn-keepalive:KEEPALIVE"
    )
    local count=0
    local left_item=""
    for item in "${svc_pairs[@]}"; do
        local svcname="${item%%:*}" svclabel="${item##*:}"
        local status_str
        if systemctl is-active --quiet "$svcname" 2>/dev/null; then
            status_str="${GREEN}● ONLINE${NC}"
        else
            status_str="${RED}○ OFFLINE${NC}"
        fi
        local col_item="${WHITE}${svclabel}${NC} ${status_str}"
        if [[ $((count % 2)) -eq 0 ]]; then
            left_item="$col_item"
        else
            _box_two_col $W "$left_item" "$col_item"
        fi
        ((count++))
    done
    [[ $((count % 2)) -ne 0 ]] && _box_left $W "$left_item"
    _box_bottom $W
    echo ""
}

#================================================
# SHOW MAIN MENU - LAYOUT SEPERTI FOTO 2
#================================================

show_menu() {
    local W; W=$(get_width)

    # === ACCOUNT MANAGEMENT - dua kolom ===
    _box_top $W
    _box_center $W "💎  ${YELLOW}${BOLD}ACCOUNT MANAGEMENT${NC}  💎"
    _box_divider $W
    _box_two_col $W "[1] SSH / OpenVPN"    "[5] Trial Account"
    _box_two_col $W "[2] VMess Account"    "[6] List All Accounts"
    _box_two_col $W "[3] VLess Account"    "[7] Check Expired"
    _box_two_col $W "[4] Trojan Account"   "[8] Delete Expired"
    _box_bottom $W
    echo ""

    # === SYSTEM CONTROL - dua kolom ===
    _box_top $W
    _box_center $W "⚙️  ${YELLOW}${BOLD}SYSTEM CONTROL${NC}  ⚙️"
    _box_divider $W
    _box_two_col $W "[9]  Telegram Bot"    "[15] Speedtest VPS"
    _box_two_col $W "[10] Change Domain"   "[16] Update Panel"
    _box_two_col $W "[11] Fix SSL / Cert"  "[17] Backup Config"
    _box_two_col $W "[12] Optimize VPS"    "[18] Restore Config"
    _box_two_col $W "[13] Restart Services" "[19] Uninstall Panel"
    _box_two_col $W "[14] Port Info"       "[20] Advanced Mode"
    _box_divider $W
    _box_center $W "${RED}[0] Exit Panel${NC}"
    _box_divider $W
    _box_center $W "🔔  Telegram : ${CYAN}@YouzinCrabz${NC}"
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
    for i in {1..6}; do random_str+="${chars:RANDOM%26:1}"; done
    echo "${random_str}.${ip_vps}.nip.io"
}

setup_domain() {
    clear; print_menu_header "SETUP DOMAIN"
    echo -e "  ${WHITE}[1]${NC} Pakai domain sendiri"
    echo -e "      ${YELLOW}Contoh: vpn.example.com${NC}"
    echo -e "      ${DIM}SSL: Let's Encrypt${NC}"
    echo ""
    echo -e "  ${WHITE}[2]${NC} Generate domain otomatis"
    local preview; preview=$(generate_random_domain)
    echo -e "      ${YELLOW}Contoh: ${preview}${NC}"
    echo -e "      ${DIM}SSL: Self-signed${NC}"
    echo ""
    read -p "  Pilih [1/2]: " domain_choice
    case $domain_choice in
        1)
            echo ""; read -p "  Masukkan domain: " input_domain
            [[ -z "$input_domain" ]] && { echo -e "${RED}  ✘ Domain kosong!${NC}"; sleep 2; setup_domain; return; }
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
            echo -e "  ${RED}✘ Tidak valid!${NC}"; sleep 1; setup_domain; return ;;
    esac
    echo "$DOMAIN" > "$DOMAIN_FILE"
}

get_ssl_cert() {
    local domain_type="custom"
    [[ -f "$DOMAIN_TYPE_FILE" ]] && domain_type=$(cat "$DOMAIN_TYPE_FILE")
    mkdir -p /etc/xray
    if [[ "$domain_type" == "custom" ]]; then
        systemctl stop haproxy nginx 2>/dev/null; sleep 1
        certbot certonly --standalone -d "$DOMAIN" --non-interactive --agree-tos \
            --register-unsafely-without-email >/dev/null 2>&1
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
    openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 \
        -subj "/C=ID/ST=Jakarta/L=Jakarta/O=VPN/CN=${DOMAIN}" \
        -keyout /etc/xray/xray.key -out /etc/xray/xray.crt 2>/dev/null
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
    [[ "$swap_total" -gt 512 ]] && return
    swapoff -a 2>/dev/null
    sed -i '/swapfile/d' /etc/fstab
    rm -f /swapfile
    fallocate -l 1G /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=1024 2>/dev/null
    chmod 600 /swapfile
    mkswap /swapfile >/dev/null 2>&1
    swapon /swapfile
    grep -q "/swapfile" /etc/fstab || echo "/swapfile none swap sw 0 0" >> /etc/fstab
}

#================================================
# OPTIMIZE VPN
#================================================

optimize_vpn() {
    cat > /etc/sysctl.d/99-vpn.conf << 'SYSEOF'
net.ipv4.tcp_keepalive_time = 60
net.ipv4.tcp_keepalive_intvl = 10
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_fin_timeout = 20
net.ipv4.tcp_tw_reuse = 1
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.core.netdev_max_backlog = 250000
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_max_tw_buckets = 400000
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.ip_forward = 1
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
vm.swappiness = 10
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
# HAPROXY CONFIG
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

frontend front_443
    bind *:443
    mode tcp
    tcp-request inspect-delay 5s
    tcp-request content accept if { req.ssl_hello_type 1 }
    use_backend back_grpc if { req.ssl_alpn h2 }
    default_backend back_xray_tls

backend back_xray_tls
    mode tcp
    option tcp-check
    server xray_ws 127.0.0.1:8443 check inter 10s rise 2 fall 3

backend back_grpc
    mode tcp
    option tcp-check
    server xray_grpc 127.0.0.1:8444 check inter 10s rise 2 fall 3
HAEOF
}

#================================================
# NGINX CONFIG - DIOPTIMALKAN UNTUK TUNNELING
# PERBAIKAN: proxy_pass benar ke port 8080 (bukan 10080)
# Tambahan: header yang tepat untuk WebSocket tunnel
#================================================

configure_nginx() {
    # Main nginx.conf tuning
    cat > /etc/nginx/nginx.conf << 'NGEOF'
user www-data;
worker_processes auto;
worker_rlimit_nofile 65535;
pid /run/nginx.pid;

events {
    worker_connections 65535;
    multi_accept on;
    use epoll;
}

http {
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 3600;
    keepalive_requests 100000;
    types_hash_max_size 2048;
    server_tokens off;

    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # Logging
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log warn;

    # Gzip off untuk tunnel (sudah encrypted)
    gzip off;

    # Buffer untuk WebSocket
    proxy_buffering off;
    proxy_request_buffering off;
    proxy_buffer_size 4k;

    # Timeout panjang untuk tunnel
    proxy_connect_timeout 10s;
    proxy_read_timeout 3600s;
    proxy_send_timeout 3600s;

    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
NGEOF

    cat > /etc/nginx/sites-available/vpn << NGXEOF
# ============================================
# Port 80 - NonTLS WebSocket Tunnel
# PERBAIKAN: proxy_pass ke Xray port 8080
# ============================================
map \$http_upgrade \$connection_upgrade {
    default upgrade;
    ''      close;
}

server {
    listen 80 default_server;
    server_name _;
    root /var/www/html;

    # VMess NonTLS WebSocket - path /vmess
    location /vmess {
        if (\$http_upgrade != "websocket") {
            return 400;
        }
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_buffering off;
        proxy_buffer_size 4k;
    }

    # VLess NonTLS WebSocket - path /vless
    location /vless {
        if (\$http_upgrade != "websocket") {
            return 400;
        }
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_buffering off;
        proxy_buffer_size 4k;
    }

    # Trojan NonTLS WebSocket - path /trojan
    location /trojan {
        if (\$http_upgrade != "websocket") {
            return 400;
        }
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_buffering off;
        proxy_buffer_size 4k;
    }

    # SSH WebSocket (untuk HTTP Injector / payload)
    location /ssh-ws {
        proxy_pass http://127.0.0.1:22;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_buffering off;
    }

    location / {
        try_files \$uri \$uri/ =404;
        autoindex off;
    }
}

# Port 81 - Download file akun
server {
    listen 81;
    server_name _;
    root /var/www/html;
    autoindex on;
    location / {
        try_files \$uri \$uri/ =404;
        add_header Content-Type text/plain;
        add_header Content-Disposition inline;
    }
}
NGXEOF

    rm -f /etc/nginx/sites-enabled/default
    rm -f /etc/nginx/sites-enabled/vpn
    ln -sf /etc/nginx/sites-available/vpn /etc/nginx/sites-enabled/vpn
}

#================================================
# XRAY CONFIG - DIPERBAIKI & DIOPTIMALKAN
# PERBAIKAN UTAMA:
# 1. Setiap protokol pakai port BERBEDA (tidak bisa share port untuk protokol beda)
#    - VMess WS TLS  : 8443 path /vmess
#    - VLess WS TLS  : 8442 path /vless
#    - Trojan WS TLS : 8441 path /trojan
#    - NonTLS semua  : 8080 (nginx routing berdasar path)
#    - gRPC          : 8444
# 2. HAProxy forward port 443 ke 8443 (VMess), 8442 (VLess), 8441 (Trojan)
#    berdasarkan SNI/path - ATAU pakai 1 port 8443 beda path (Xray support ini)
# 3. Nginx NonTLS routing ke 8080 (1 server handle semua path via ws settings)
#
# CATATAN ARSITEKTUR:
# Xray BISA handle multiple inbound di 1 port dengan path berbeda (WS mode)
# Jadi port 8443 bisa untuk VMess/VLess/Trojan asal path berbeda
# Xray routing berdasarkan: protocol type yang match path yang dikonfigurasi
#================================================

create_xray_config() {
    mkdir -p /var/log/xray /usr/local/etc/xray

    cat > "$XRAY_CONFIG" << 'XRAYEOF'
{
  "log": {
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log",
    "loglevel": "warning"
  },

  "inbounds": [

    {
      "tag": "vmess-ws-tls",
      "port": 8443,
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
          "headers": { "Host": "" }
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    },

    {
      "tag": "vless-ws-tls",
      "port": 8442,
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
          "headers": { "Host": "" }
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    },

    {
      "tag": "trojan-ws-tls",
      "port": 8441,
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
          "headers": { "Host": "" }
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    },

    {
      "tag": "vmess-ws-nontls",
      "port": 8080,
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
      "port": 8081,
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
      "port": 8082,
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
      "port": 8445,
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
      "port": 8446,
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
      },
      {
        "type": "field",
        "domain": ["geosite:category-ads-all"],
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

    # Update HAProxy untuk routing multi-port
    configure_haproxy_multiport

    fix_xray_permissions
}

# HAProxy multi-port untuk routing ke tiap protokol Xray
configure_haproxy_multiport() {
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

# Port 443: TLS traffic masuk, routing berdasarkan ALPN
frontend front_443
    bind *:443
    mode tcp
    tcp-request inspect-delay 5s
    tcp-request content accept if { req.ssl_hello_type 1 }

    # gRPC (ALPN h2) → backend gRPC
    use_backend back_grpc if { req.ssl_alpn h2 }

    # Default → VMess WS TLS (client bisa pilih path /vmess /vless /trojan)
    # HAProxy tidak bisa inspect HTTP path di TLS tanpa termination
    # Solusi: gunakan port berbeda untuk tiap protokol atau SNI routing
    default_backend back_vmess_tls

# VMess WS TLS
backend back_vmess_tls
    mode tcp
    option tcp-check
    server xray_vmess 127.0.0.1:8443 check inter 10s rise 2 fall 3

# gRPC (multi-protocol via serviceName)
backend back_grpc
    mode tcp
    option tcp-check
    server xray_grpc 127.0.0.1:8444 check inter 10s rise 2 fall 3

# Port langsung untuk VLess dan Trojan TLS (akses via port berbeda)
frontend front_8442
    bind *:8442
    mode tcp
    default_backend back_vless_tls

backend back_vless_tls
    mode tcp
    server xray_vless 127.0.0.1:8442 check inter 10s

frontend front_8441
    bind *:8441
    mode tcp
    default_backend back_trojan_tls

backend back_trojan_tls
    mode tcp
    server xray_trojan 127.0.0.1:8441 check inter 10s
HAEOF
}

# Update nginx untuk routing NonTLS per protokol
configure_nginx_updated() {
    configure_nginx  # Gunakan nginx config yang sudah diperbaiki

    # Tambah routing VLess dan Trojan NonTLS
    cat >> /etc/nginx/sites-available/vpn << 'ADDEOF'

# Catatan: VLess NonTLS di port 8081, Trojan NonTLS di 8082
# Nginx di port 80 hanya handle VMess NonTLS (path /vmess)
# Untuk VLess NonTLS, client connect ke port 8081 langsung
# Untuk Trojan NonTLS, client connect ke port 8082 langsung
ADDEOF
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
# INFO PORT - DIUPDATE
#================================================

show_info_port() {
    clear; print_menu_header "SERVER PORT INFORMATION"
    local W; W=$(get_width)
    _box_top $W
    _box_center $W "${YELLOW}${BOLD}═ AKSES DARI INTERNET ═${NC}"
    _box_divider $W
    _box_left $W "${WHITE}SSH OpenSSH    ${NC}: ${GREEN}22${NC}"
    _box_left $W "${WHITE}SSH Dropbear   ${NC}: ${GREEN}222${NC}"
    _box_left $W "${WHITE}NonTLS (Nginx) ${NC}: ${GREEN}80 → VMess/VLess/Trojan WS${NC}"
    _box_left $W "${WHITE}VMess TLS      ${NC}: ${GREEN}443 (via HAProxy → 8443)${NC}"
    _box_left $W "${WHITE}VLess TLS      ${NC}: ${GREEN}8442 (direct)${NC}"
    _box_left $W "${WHITE}Trojan TLS     ${NC}: ${GREEN}8441 (direct)${NC}"
    _box_left $W "${WHITE}gRPC TLS       ${NC}: ${GREEN}443 (via HAProxy → 8444)${NC}"
    _box_left $W "${WHITE}BadVPN UDP     ${NC}: ${GREEN}7100-7300${NC}"
    _box_left $W "${WHITE}Download Akun  ${NC}: ${GREEN}81${NC}"
    _box_divider $W
    _box_center $W "${YELLOW}${BOLD}═ INTERNAL XRAY PORTS ═${NC}"
    _box_divider $W
    _box_left $W "${WHITE}VMess WS TLS   ${NC}: ${CYAN}127.0.0.1:8443${NC} path /vmess"
    _box_left $W "${WHITE}VLess WS TLS   ${NC}: ${CYAN}127.0.0.1:8442${NC} path /vless"
    _box_left $W "${WHITE}Trojan WS TLS  ${NC}: ${CYAN}127.0.0.1:8441${NC} path /trojan"
    _box_left $W "${WHITE}VMess WS NonTLS${NC}: ${CYAN}127.0.0.1:8080${NC} path /vmess"
    _box_left $W "${WHITE}VLess WS NonTLS${NC}: ${CYAN}127.0.0.1:8081${NC} path /vless"
    _box_left $W "${WHITE}Trojan WS NonTLS${NC}: ${CYAN}127.0.0.1:8082${NC} path /trojan"
    _box_left $W "${WHITE}VMess gRPC TLS ${NC}: ${CYAN}127.0.0.1:8444${NC}"
    _box_left $W "${WHITE}VLess gRPC TLS ${NC}: ${CYAN}127.0.0.1:8445${NC}"
    _box_left $W "${WHITE}Trojan gRPC TLS${NC}: ${CYAN}127.0.0.1:8446${NC}"
    _box_bottom $W
    echo ""; read -p "  Press any key to back..."
}

#================================================
# CREATE ACCOUNT - XRAY
#================================================

create_account_template() {
    local protocol="$1" username="$2" days="$3" quota="$4" iplimit="$5"
    local uuid ip_vps exp created
    uuid=$(cat /proc/sys/kernel/random/uuid)
    ip_vps=$(get_ip)
    exp=$(date -d "+${days} days" +"%d %b, %Y")
    created=$(date +"%d %b, %Y")

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
        echo -e "  ${RED}✘ Failed update Xray config!${NC}"; sleep 2; return 1
    fi

    mkdir -p "$AKUN_DIR"
    printf "UUID=%s\nQUOTA=%s\nIPLIMIT=%s\nEXPIRED=%s\nCREATED=%s\n" \
        "$uuid" "$quota" "$iplimit" "$exp" "$created" \
        > "$AKUN_DIR/${protocol}-${username}.txt"

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
        j_grpc=$(printf '{"v":"2","ps":"%s-gRPC","add":"%s","port":"443","id":"%s","aid":"0","net":"grpc","path":"vmess-grpc","type":"none","tls":"tls","sni":"%s"}' \
            "$username" "$DOMAIN" "$uuid" "$DOMAIN")
        link_grpc="vmess://$(printf '%s' "$j_grpc" | base64 -w 0)"
        clash_tls="- name: ${username}-WS-TLS\n  type: vmess\n  server: bug.com\n  port: 443\n  uuid: ${uuid}\n  alterId: 0\n  cipher: auto\n  udp: true\n  tls: true\n  skip-cert-verify: false\n  servername: ${DOMAIN}\n  network: ws\n  ws-opts:\n    path: /vmess\n    headers:\n      Host: ${DOMAIN}"
        clash_nontls="- name: ${username}-WS-NonTLS\n  type: vmess\n  server: bug.com\n  port: 80\n  uuid: ${uuid}\n  alterId: 0\n  cipher: auto\n  udp: true\n  tls: false\n  network: ws\n  ws-opts:\n    path: /vmess\n    headers:\n      Host: ${DOMAIN}"
        clash_grpc="- name: ${username}-gRPC\n  type: vmess\n  server: ${DOMAIN}\n  port: 443\n  uuid: ${uuid}\n  alterId: 0\n  cipher: auto\n  udp: true\n  tls: true\n  skip-cert-verify: false\n  network: grpc\n  grpc-opts:\n    grpc-service-name: vmess-grpc"
    elif [[ "$protocol" == "vless" ]]; then
        link_tls="vless://${uuid}@bug.com:8442?path=%2Fvless&security=tls&encryption=none&host=${DOMAIN}&type=ws&sni=${DOMAIN}#${username}-TLS"
        link_nontls="vless://${uuid}@bug.com:80?path=%2Fvless&security=none&encryption=none&host=${DOMAIN}&type=ws#${username}-NonTLS"
        link_grpc="vless://${uuid}@${DOMAIN}:443?mode=gun&security=tls&encryption=none&type=grpc&serviceName=vless-grpc&sni=${DOMAIN}#${username}-gRPC"
        clash_tls="- name: ${username}-WS-TLS\n  type: vless\n  server: bug.com\n  port: 8442\n  uuid: ${uuid}\n  udp: true\n  tls: true\n  skip-cert-verify: false\n  servername: ${DOMAIN}\n  network: ws\n  ws-opts:\n    path: /vless\n    headers:\n      Host: ${DOMAIN}"
        clash_nontls="- name: ${username}-WS-NonTLS\n  type: vless\n  server: bug.com\n  port: 80\n  uuid: ${uuid}\n  udp: true\n  tls: false\n  network: ws\n  ws-opts:\n    path: /vless\n    headers:\n      Host: ${DOMAIN}"
        clash_grpc="- name: ${username}-gRPC\n  type: vless\n  server: ${DOMAIN}\n  port: 443\n  uuid: ${uuid}\n  udp: true\n  tls: true\n  skip-cert-verify: false\n  network: grpc\n  grpc-opts:\n    grpc-service-name: vless-grpc"
    elif [[ "$protocol" == "trojan" ]]; then
        link_tls="trojan://${uuid}@bug.com:8441?path=%2Ftrojan&security=tls&host=${DOMAIN}&type=ws&sni=${DOMAIN}#${username}-TLS"
        link_nontls="trojan://${uuid}@bug.com:80?path=%2Ftrojan&security=none&host=${DOMAIN}&type=ws#${username}-NonTLS"
        link_grpc="trojan://${uuid}@${DOMAIN}:443?mode=gun&security=tls&type=grpc&serviceName=trojan-grpc&sni=${DOMAIN}#${username}-gRPC"
        clash_tls="- name: ${username}-WS-TLS\n  type: trojan\n  server: bug.com\n  port: 8441\n  password: ${uuid}\n  udp: true\n  tls: true\n  skip-cert-verify: false\n  sni: ${DOMAIN}\n  network: ws\n  ws-opts:\n    path: /trojan\n    headers:\n      Host: ${DOMAIN}"
        clash_nontls="- name: ${username}-WS-NonTLS\n  type: trojan\n  server: bug.com\n  port: 80\n  password: ${uuid}\n  udp: true\n  tls: false\n  network: ws\n  ws-opts:\n    path: /trojan\n    headers:\n      Host: ${DOMAIN}"
        clash_grpc="- name: ${username}-gRPC\n  type: trojan\n  server: ${DOMAIN}\n  port: 443\n  password: ${uuid}\n  udp: true\n  tls: true\n  skip-cert-verify: false\n  network: grpc\n  grpc-opts:\n    grpc-service-name: trojan-grpc"
    fi

    mkdir -p "$PUBLIC_HTML"
    cat > "$PUBLIC_HTML/${protocol}-${username}.txt" << DLEOF
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  YOUZIN CRABZ TUNEL - ${protocol^^} Account
  The Professor | v${SCRIPT_VERSION}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Username         : ${username}
 IP VPS           : ${ip_vps}
 Domain           : ${DOMAIN}
 UUID/Password    : ${uuid}
 Quota            : ${quota} GB
 IP Limit         : ${iplimit} IP
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 PORTS:
 VMess TLS   : 443  (HAProxy → 8443)
 VLess TLS   : 8442
 Trojan TLS  : 8441
 NonTLS/WS   : 80   (Nginx → 808x)
 gRPC TLS    : 443  (HAProxy → 844x)
 Path WS     : /${protocol}
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
 Download : http://${ip_vps}:81/${protocol}-${username}.txt
 Aktif    : ${days} Hari | Dibuat: ${created} | Exp: ${exp}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
DLEOF

    _print_xray_result "$protocol" "$username" "$ip_vps" "$uuid" "$quota" "$iplimit" \
        "$link_tls" "$link_nontls" "$link_grpc" "$days" "$created" "$exp" \
        "$clash_tls" "$clash_nontls" "$clash_grpc"

    send_telegram_admin \
"✅ <b>New ${protocol^^} - Youzin Crabz</b>
👤 <code>${username}</code> | 🔑 <code>${uuid}</code>
🌐 <code>${DOMAIN}</code> | 🖥️ <code>${ip_vps}</code>
⏳ Berakhir: ${exp}
🔗 http://${ip_vps}:81/${protocol}-${username}.txt"

    read -p "  Press any key to back..."
}

_print_xray_result() {
    local protocol="$1" username="$2" ip_vps="$3" uuid="$4"
    local quota="$5" iplimit="$6" link_tls="$7" link_nontls="$8"
    local link_grpc="$9" days="${10}" created="${11}" exp="${12}"
    local clash_tls="${13}" clash_nontls="${14}" clash_grpc="${15}"

    clear
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${WHITE}${BOLD}YOUZIN CRABZ TUNEL${NC} — ${YELLOW}${protocol^^} Account${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    printf "  ${WHITE}%-16s${NC} : ${GREEN}%s${NC}\n" "Username"    "$username"
    printf "  ${WHITE}%-16s${NC} : ${GREEN}%s${NC}\n" "IP VPS"      "$ip_vps"
    printf "  ${WHITE}%-16s${NC} : ${GREEN}%s${NC}\n" "Domain"      "$DOMAIN"
    printf "  ${WHITE}%-16s${NC} : ${CYAN}%s${NC}\n"  "UUID"        "$uuid"
    printf "  ${WHITE}%-16s${NC} : %s GB | IP Limit: %s\n" "Quota" "$quota" "$iplimit"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    printf "  ${YELLOW}Link TLS${NC}:\n  %s\n" "$link_tls"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    printf "  ${YELLOW}Link NonTLS${NC}:\n  %s\n" "$link_nontls"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    printf "  ${YELLOW}Link gRPC${NC}:\n  %s\n" "$link_grpc"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    printf "  ${WHITE}%-16s${NC} : ${YELLOW}%s Hari${NC} | Exp: ${RED}%s${NC}\n" "Aktif" "$days" "$exp"
    printf "  ${WHITE}%-16s${NC} : http://%s:81/%s-%s.txt\n" "Download" "$ip_vps" "$protocol" "$username"
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
        systemctl reload xray 2>/dev/null || systemctl restart xray 2>/dev/null; sleep 1
    else
        rm -f "$temp"; echo -e "  ${RED}✘ Failed!${NC}"; sleep 2; return
    fi

    mkdir -p "$AKUN_DIR"
    printf "UUID=%s\nQUOTA=1\nIPLIMIT=1\nEXPIRED=%s\nCREATED=%s\nTRIAL=1\n" \
        "$uuid" "$exp" "$created" > "$AKUN_DIR/${protocol}-${username}.txt"

    (sleep 3600
     local tmp2; tmp2=$(mktemp)
     jq --arg email "$username" 'del(.inbounds[].settings.clients[]? | select(.email == $email))' \
        "$XRAY_CONFIG" > "$tmp2" 2>/dev/null && mv "$tmp2" "$XRAY_CONFIG" || rm -f "$tmp2"
     fix_xray_permissions
     systemctl reload xray 2>/dev/null || systemctl restart xray 2>/dev/null
     rm -f "$AKUN_DIR/${protocol}-${username}.txt") &
    disown $!

    clear
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${YELLOW}Trial ${protocol^^} (1 Jam) | Auto Delete${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    printf "  ${WHITE}%-16s${NC} : ${GREEN}%s${NC}\n" "Username" "$username"
    printf "  ${WHITE}%-16s${NC} : ${CYAN}%s${NC}\n" "UUID" "$uuid"
    printf "  ${WHITE}%-16s${NC} : ${RED}%s${NC}\n" "Exp" "$exp"
    echo ""; read -p "  Press any key to back..."
}

#================================================
# CREATE SSH
#================================================

create_ssh() {
    clear; print_menu_header "CREATE SSH ACCOUNT"
    read -p "  Username      : " username
    [[ -z "$username" ]] && { echo -e "  ${RED}✘ Required!${NC}"; sleep 2; return; }
    id "$username" &>/dev/null && { echo -e "  ${RED}✘ User sudah ada!${NC}"; sleep 2; return; }
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
    read -p "  Press any key to back..."
}

create_ssh_trial() {
    local suffix; suffix=$(cat /proc/sys/kernel/random/uuid | tr -d '-' | head -c 4 | tr '[:lower:]' '[:upper:]')
    local username="Trial-${suffix}" password="1"
    local ip_vps exp exp_date created
    ip_vps=$(get_ip)
    exp=$(date -d "+1 hour" +"%d %b, %Y %H:%M")
    exp_date=$(date -d "+1 days" +"%Y-%m-%d")
    created=$(date +"%d %b, %Y %H:%M")

    useradd -M -s /bin/false -e "$exp_date" "$username" 2>/dev/null
    echo "${username}:${password}" | chpasswd

    mkdir -p "$AKUN_DIR"
    printf "USERNAME=%s\nPASSWORD=%s\nIPLIMIT=1\nEXPIRED=%s\nCREATED=%s\nTRIAL=1\n" \
        "$username" "$password" "$exp" "$created" > "$AKUN_DIR/ssh-${username}.txt"

    (sleep 3600; userdel -f "$username" 2>/dev/null; rm -f "$AKUN_DIR/ssh-${username}.txt") &
    disown $!

    _save_ssh_file "Trial SSH (1 Jam)" "$username" "$password" "$ip_vps" "1 Jam" "$created" "$exp"
    _print_ssh_result "Trial SSH (1 Jam)" "$username" "$password" "$ip_vps" "1 Jam" "$created" "$exp"
    read -p "  Press any key to back..."
}

_save_ssh_file() {
    local title="$1" username="$2" password="$3" ip_vps="$4" days="$5" created="$6" exp="$7"
    mkdir -p "$PUBLIC_HTML"
    cat > "$PUBLIC_HTML/ssh-${username}.txt" << SSHFILE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  YOUZIN CRABZ TUNEL - ${title}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Username   : ${username}
 Password   : ${password}
 Host/IP    : ${ip_vps}
 Domain     : ${DOMAIN}
 OpenSSH    : 22
 Dropbear   : 222
 SSL/TLS    : 443
 WS NonSSL  : 80
 WS SSL     : 443
 BadVPN UDP : 7100,7200,7300
 Format HC  : ${DOMAIN}:80@${username}:${password}
 Payload    : GET / HTTP/1.1[crlf]Host: ${DOMAIN}[crlf]Upgrade: ws[crlf][crlf]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Download   : http://${ip_vps}:81/ssh-${username}.txt
 Aktif      : ${days} | Dibuat: ${created} | Exp: ${exp}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SSHFILE
}

_print_ssh_result() {
    local title="$1" username="$2" password="$3" ip_vps="$4" days="$5" created="$6" exp="$7"
    clear
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${WHITE}${BOLD}YOUZIN CRABZ TUNEL${NC} — ${YELLOW}${title}${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    printf "  ${WHITE}%-14s${NC} : ${GREEN}%s${NC}\n" "Username"   "$username"
    printf "  ${WHITE}%-14s${NC} : ${GREEN}%s${NC}\n" "Password"   "$password"
    printf "  ${WHITE}%-14s${NC} : ${GREEN}%s${NC}\n" "Host/IP"    "$ip_vps"
    printf "  ${WHITE}%-14s${NC} : ${GREEN}%s${NC}\n" "Domain"     "$DOMAIN"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    printf "  ${WHITE}%-14s${NC} : %s\n" "OpenSSH"    "22"
    printf "  ${WHITE}%-14s${NC} : %s\n" "Dropbear"   "222"
    printf "  ${WHITE}%-14s${NC} : %s\n" "SSL/TLS"    "443"
    printf "  ${WHITE}%-14s${NC} : %s\n" "WS NonSSL"  "80"
    printf "  ${WHITE}%-14s${NC} : %s\n" "WS SSL"     "443"
    printf "  ${WHITE}%-14s${NC} : %s\n" "BadVPN UDP" "7100,7200,7300"
    printf "  ${WHITE}%-14s${NC} : %s:80@%s:%s\n" "Format HC" "$DOMAIN" "$username" "$password"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    printf "  ${WHITE}%-14s${NC} : ${YELLOW}%s${NC}\n" "Aktif"    "$days"
    printf "  ${WHITE}%-14s${NC} : %s\n" "Dibuat"     "$created"
    printf "  ${WHITE}%-14s${NC} : ${RED}%s${NC}\n" "Berakhir"  "$exp"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

#================================================
# DELETE / RENEW / LIST
#================================================

delete_account() {
    local protocol="$1"
    clear; print_menu_header "DELETE ${protocol^^}"
    shopt -s nullglob
    local files=("$AKUN_DIR"/${protocol}-*.txt)
    shopt -u nullglob
    if [[ ${#files[@]} -eq 0 ]]; then echo -e "  ${RED}No accounts!${NC}"; sleep 2; return; fi
    for f in "${files[@]}"; do
        local n e
        n=$(basename "$f" .txt | sed "s/${protocol}-//")
        e=$(grep "EXPIRED" "$f" 2>/dev/null | cut -d= -f2-)
        echo -e "  ${CYAN}▸${NC} $n ${YELLOW}($e)${NC}"
    done
    echo ""; read -p "  Username to delete: " username
    [[ -z "$username" ]] && return
    local tmp; tmp=$(mktemp)
    jq --arg email "$username" 'del(.inbounds[].settings.clients[]? | select(.email == $email))' \
       "$XRAY_CONFIG" > "$tmp" 2>/dev/null && mv "$tmp" "$XRAY_CONFIG" || rm -f "$tmp"
    fix_xray_permissions
    systemctl reload xray 2>/dev/null || systemctl restart xray 2>/dev/null
    rm -f "$AKUN_DIR/${protocol}-${username}.txt" "$PUBLIC_HTML/${protocol}-${username}.txt"
    [[ "$protocol" == "ssh" ]] && userdel -f "$username" 2>/dev/null
    echo -e "  ${GREEN}✔ Deleted: ${username}${NC}"; sleep 2
}

renew_account() {
    local protocol="$1"
    clear; print_menu_header "RENEW ${protocol^^}"
    shopt -s nullglob
    local files=("$AKUN_DIR"/${protocol}-*.txt)
    shopt -u nullglob
    if [[ ${#files[@]} -eq 0 ]]; then echo -e "  ${RED}No accounts!${NC}"; sleep 2; return; fi
    for f in "${files[@]}"; do
        local n e
        n=$(basename "$f" .txt | sed "s/${protocol}-//")
        e=$(grep "EXPIRED" "$f" 2>/dev/null | cut -d= -f2-)
        echo -e "  ${CYAN}▸${NC} $n ${YELLOW}($e)${NC}"
    done
    echo ""; read -p "  Username to renew: " username
    [[ -z "$username" ]] && return
    [[ ! -f "$AKUN_DIR/${protocol}-${username}.txt" ]] && { echo -e "  ${RED}✘ Not found!${NC}"; sleep 2; return; }
    read -p "  Add days: " days
    [[ ! "$days" =~ ^[0-9]+$ ]] && { echo -e "  ${RED}✘ Invalid!${NC}"; sleep 2; return; }
    local new_exp new_exp_date
    new_exp=$(date -d "+${days} days" +"%d %b, %Y")
    new_exp_date=$(date -d "+${days} days" +"%Y-%m-%d")
    sed -i "s/EXPIRED=.*/EXPIRED=${new_exp}/" "$AKUN_DIR/${protocol}-${username}.txt"
    [[ "$protocol" == "ssh" ]] && chage -E "$new_exp_date" "$username" 2>/dev/null
    echo -e "  ${GREEN}✔ Renewed! Exp: ${new_exp}${NC}"; sleep 3
}

list_accounts() {
    local protocol="$1"
    clear; print_menu_header "${protocol^^} ACCOUNT LIST"
    local W; W=$(get_width)
    shopt -s nullglob
    local files=("$AKUN_DIR"/${protocol}-*.txt)
    shopt -u nullglob
    if [[ ${#files[@]} -eq 0 ]]; then echo -e "  ${RED}No accounts!${NC}"; sleep 2; return; fi
    _box_top $W
    _box_two_col $W "${WHITE}USERNAME${NC}" "${WHITE}EXPIRED${NC}"
    _box_divider $W
    for f in "${files[@]}"; do
        local uname exp trial ttype
        uname=$(basename "$f" .txt | sed "s/${protocol}-//")
        exp=$(grep "EXPIRED" "$f" 2>/dev/null | cut -d= -f2-)
        trial=$(grep "TRIAL" "$f" 2>/dev/null | cut -d= -f2)
        ttype="${WHITE}Member${NC}"
        [[ "$trial" == "1" ]] && ttype="${YELLOW}Trial${NC}"
        _box_two_col $W "${GREEN}${uname}${NC} [${ttype}]" "${YELLOW}${exp}${NC}"
    done
    _box_divider $W
    _box_left $W "Total: ${GREEN}${#files[@]}${NC} accounts"
    _box_bottom $W
    echo ""; read -p "  Press any key to back..."
}

cek_expired() {
    clear; print_menu_header "CEK EXPIRED ACCOUNTS"
    local today found=0; today=$(date +%s)
    shopt -s nullglob
    for f in "$AKUN_DIR"/*.txt; do
        [[ ! -f "$f" ]] && continue
        local exp_str exp_ts uname diff
        exp_str=$(grep "EXPIRED=" "$f" 2>/dev/null | head -1 | cut -d= -f2-)
        [[ -z "$exp_str" ]] && continue
        exp_ts=$(date -d "$exp_str" +%s 2>/dev/null); [[ -z "$exp_ts" ]] && continue
        uname=$(basename "$f" .txt)
        diff=$(( (exp_ts - today) / 86400 ))
        if [[ $diff -le 3 ]]; then
            found=1
            [[ $diff -lt 0 ]] && echo -e "  ${RED}✘ EXPIRED${NC}: $uname ($exp_str)" || \
                echo -e "  ${YELLOW}⚠ ${diff} hari${NC}: $uname ($exp_str)"
        fi
    done
    shopt -u nullglob
    [[ $found -eq 0 ]] && echo -e "  ${GREEN}✔ Tidak ada akun expired!${NC}"
    echo ""; read -p "  Press any key to back..."
}

delete_expired() {
    clear; print_menu_header "DELETE EXPIRED ACCOUNTS"
    local today count=0; today=$(date +%s)
    shopt -s nullglob
    for f in "$AKUN_DIR"/*.txt; do
        [[ ! -f "$f" ]] && continue
        local exp_str exp_ts fname uname protocol
        exp_str=$(grep "EXPIRED=" "$f" 2>/dev/null | head -1 | cut -d= -f2-)
        [[ -z "$exp_str" ]] && continue
        exp_ts=$(date -d "$exp_str" +%s 2>/dev/null); [[ -z "$exp_ts" ]] && continue
        if [[ $exp_ts -lt $today ]]; then
            fname=$(basename "$f" .txt)
            protocol=${fname%%-*}; uname=${fname#*-}
            echo -e "  ${RED}Deleting${NC}: $fname"
            local tmp; tmp=$(mktemp)
            jq --arg email "$uname" 'del(.inbounds[].settings.clients[]? | select(.email == $email))' \
               "$XRAY_CONFIG" > "$tmp" 2>/dev/null && mv "$tmp" "$XRAY_CONFIG" || rm -f "$tmp"
            [[ "$protocol" == "ssh" ]] && userdel -f "$uname" 2>/dev/null
            rm -f "$f" "$PUBLIC_HTML/${fname}.txt"
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
    echo ""; read -p "  Press any key to back..."
}

#================================================
# CREATE VMESS / VLESS / TROJAN WRAPPERS
#================================================

create_vmess() {
    clear; print_menu_header "CREATE VMESS ACCOUNT"
    read -p "  Username      : " username
    [[ -z "$username" ]] && { echo -e "  ${RED}✘ Required!${NC}"; sleep 2; return; }
    grep -q "\"email\":\"${username}\"" "$XRAY_CONFIG" 2>/dev/null && { echo -e "  ${RED}✘ Sudah ada!${NC}"; sleep 2; return; }
    read -p "  Expired (days): " days
    [[ ! "$days" =~ ^[0-9]+$ ]] && { echo -e "  ${RED}✘ Invalid!${NC}"; sleep 2; return; }
    read -p "  Quota (GB)    : " quota; [[ ! "$quota" =~ ^[0-9]+$ ]] && quota=100
    read -p "  IP Limit      : " iplimit; [[ ! "$iplimit" =~ ^[0-9]+$ ]] && iplimit=1
    create_account_template "vmess" "$username" "$days" "$quota" "$iplimit"
}

create_vless() {
    clear; print_menu_header "CREATE VLESS ACCOUNT"
    read -p "  Username      : " username
    [[ -z "$username" ]] && { echo -e "  ${RED}✘ Required!${NC}"; sleep 2; return; }
    grep -q "\"email\":\"${username}\"" "$XRAY_CONFIG" 2>/dev/null && { echo -e "  ${RED}✘ Sudah ada!${NC}"; sleep 2; return; }
    read -p "  Expired (days): " days
    [[ ! "$days" =~ ^[0-9]+$ ]] && { echo -e "  ${RED}✘ Invalid!${NC}"; sleep 2; return; }
    read -p "  Quota (GB)    : " quota; [[ ! "$quota" =~ ^[0-9]+$ ]] && quota=100
    read -p "  IP Limit      : " iplimit; [[ ! "$iplimit" =~ ^[0-9]+$ ]] && iplimit=1
    create_account_template "vless" "$username" "$days" "$quota" "$iplimit"
}

create_trojan() {
    clear; print_menu_header "CREATE TROJAN ACCOUNT"
    read -p "  Username      : " username
    [[ -z "$username" ]] && { echo -e "  ${RED}✘ Required!${NC}"; sleep 2; return; }
    grep -q "\"email\":\"${username}\"" "$XRAY_CONFIG" 2>/dev/null && { echo -e "  ${RED}✘ Sudah ada!${NC}"; sleep 2; return; }
    read -p "  Expired (days): " days
    [[ ! "$days" =~ ^[0-9]+$ ]] && { echo -e "  ${RED}✘ Invalid!${NC}"; sleep 2; return; }
    read -p "  Quota (GB)    : " quota; [[ ! "$quota" =~ ^[0-9]+$ ]] && quota=100
    read -p "  IP Limit      : " iplimit; [[ ! "$iplimit" =~ ^[0-9]+$ ]] && iplimit=1
    create_account_template "trojan" "$username" "$days" "$quota" "$iplimit"
}

#================================================
# MENU WRAPPERS
#================================================

menu_ssh() {
    while true; do
        clear; print_menu_header "SSH MENU"
        local W; W=$(get_width)
        _box_top $W; _box_center $W "${YELLOW}${BOLD}SSH / OPENVPN${NC}"; _box_divider $W
        _box_left $W "[1] Create SSH"
        _box_left $W "[2] Trial SSH (1 Jam)"
        _box_left $W "[3] Delete SSH"
        _box_left $W "[4] Renew SSH"
        _box_left $W "[5] List User SSH"
        _box_divider $W; _box_left $W "${RED}[0] Back${NC}"; _box_bottom $W
        echo ""; read -p "  Select [0-5]: " choice
        case $choice in
            1) create_ssh ;; 2) create_ssh_trial ;; 3) delete_account "ssh" ;;
            4) renew_account "ssh" ;; 5) list_accounts "ssh" ;; 0) return ;;
        esac
    done
}

menu_vmess() {
    while true; do
        clear; print_menu_header "VMESS MENU"
        local W; W=$(get_width)
        _box_top $W; _box_center $W "${YELLOW}${BOLD}VMESS ACCOUNT${NC}"; _box_divider $W
        _box_left $W "[1] Create VMess"; _box_left $W "[2] Trial VMess (1 Jam)"
        _box_left $W "[3] Delete VMess"; _box_left $W "[4] Renew VMess"
        _box_left $W "[5] List User VMess"
        _box_divider $W; _box_left $W "${RED}[0] Back${NC}"; _box_bottom $W
        echo ""; read -p "  Select [0-5]: " choice
        case $choice in
            1) create_vmess ;; 2) create_trial_xray "vmess" ;; 3) delete_account "vmess" ;;
            4) renew_account "vmess" ;; 5) list_accounts "vmess" ;; 0) return ;;
        esac
    done
}

menu_vless() {
    while true; do
        clear; print_menu_header "VLESS MENU"
        local W; W=$(get_width)
        _box_top $W; _box_center $W "${YELLOW}${BOLD}VLESS ACCOUNT${NC}"; _box_divider $W
        _box_left $W "[1] Create VLess"; _box_left $W "[2] Trial VLess (1 Jam)"
        _box_left $W "[3] Delete VLess"; _box_left $W "[4] Renew VLess"
        _box_left $W "[5] List User VLess"
        _box_divider $W; _box_left $W "${RED}[0] Back${NC}"; _box_bottom $W
        echo ""; read -p "  Select [0-5]: " choice
        case $choice in
            1) create_vless ;; 2) create_trial_xray "vless" ;; 3) delete_account "vless" ;;
            4) renew_account "vless" ;; 5) list_accounts "vless" ;; 0) return ;;
        esac
    done
}

menu_trojan() {
    while true; do
        clear; print_menu_header "TROJAN MENU"
        local W; W=$(get_width)
        _box_top $W; _box_center $W "${YELLOW}${BOLD}TROJAN ACCOUNT${NC}"; _box_divider $W
        _box_left $W "[1] Create Trojan"; _box_left $W "[2] Trial Trojan (1 Jam)"
        _box_left $W "[3] Delete Trojan"; _box_left $W "[4] Renew Trojan"
        _box_left $W "[5] List User Trojan"
        _box_divider $W; _box_left $W "${RED}[0] Back${NC}"; _box_bottom $W
        echo ""; read -p "  Select [0-5]: " choice
        case $choice in
            1) create_trojan ;; 2) create_trial_xray "trojan" ;; 3) delete_account "trojan" ;;
            4) renew_account "trojan" ;; 5) list_accounts "trojan" ;; 0) return ;;
        esac
    done
}

#================================================
# ADVANCED MODE - FITUR LENGKAP SEPERTI FOTO
#================================================

menu_advanced() {
    while true; do
        clear
        local W; W=$(get_width)
        _box_top $W
        _box_center $W "⚙  ${YELLOW}${BOLD}ADVANCED SETTINGS${NC}"
        _box_divider $W
        _box_two_col $W "[1]  Port Management"     "[7]  Firewall Rules"
        _box_two_col $W "[2]  Protocol Settings"   "[8]  Bandwidth Monitor"
        _box_two_col $W "[3]  Auto Backup"         "[9]  User IP Limits"
        _box_two_col $W "[4]  SSH Brute Protect"   "[10] Custom Payload"
        _box_two_col $W "[5]  Fail2Ban Setup"      "[11] Cron Jobs"
        _box_two_col $W "[6]  DDoS Protection"     "[12] System Logs"
        _box_divider $W
        _box_left $W "${RED}[0] Back to Main Menu${NC}"
        _box_bottom $W
        echo ""
        read -p "  Select [0-12]: " choice
        case $choice in
            1) adv_port_management ;;
            2) adv_protocol_settings ;;
            3) adv_auto_backup ;;
            4) adv_ssh_brute_protect ;;
            5) adv_fail2ban_setup ;;
            6) adv_ddos_protection ;;
            7) adv_firewall_rules ;;
            8) adv_bandwidth_monitor ;;
            9) adv_user_ip_limits ;;
            10) adv_custom_payload ;;
            11) adv_cron_jobs ;;
            12) adv_system_logs ;;
            0) return ;;
        esac
    done
}

# [1] Port Management
adv_port_management() {
    while true; do
        clear; print_menu_header "PORT MANAGEMENT"
        local W; W=$(get_width)
        _box_top $W
        _box_center $W "${YELLOW}${BOLD}KELOLA PORT PANEL${NC}"
        _box_divider $W
        # Tampilkan status port
        _box_left $W "${WHITE}Current Port Status:${NC}"
        _box_left $W ""
        local ports=(22 222 80 81 443 8441 8442 8443 8444)
        local labels=("SSH" "Dropbear" "Nginx NonTLS" "Nginx Download" "HAProxy TLS" "Trojan TLS" "VLess TLS" "VMess TLS" "VMess gRPC")
        for i in "${!ports[@]}"; do
            local port="${ports[$i]}" label="${labels[$i]}"
            if ss -tlnp 2>/dev/null | grep -q ":${port} " || ss -tlnp 2>/dev/null | grep -q ":${port}$"; then
                _box_left $W "${GREEN}●${NC} ${WHITE}${label}${NC} (${port}) ${GREEN}OPEN${NC}"
            else
                _box_left $W "${RED}○${NC} ${WHITE}${label}${NC} (${port}) ${RED}CLOSED${NC}"
            fi
        done
        _box_divider $W
        _box_left $W "[1] Ubah Port SSH"
        _box_left $W "[2] Ubah Port Dropbear"
        _box_left $W "[3] Ubah Port Nginx"
        _box_left $W "[4] Buka Port Custom (UFW)"
        _box_left $W "[5] Tutup Port Custom (UFW)"
        _box_left $W "[6] Scan Port Terbuka"
        _box_divider $W; _box_left $W "${RED}[0] Back${NC}"; _box_bottom $W
        echo ""; read -p "  Select [0-6]: " ch
        case $ch in
            1)
                read -p "  Port SSH baru (default 22): " np
                [[ "$np" =~ ^[0-9]+$ ]] && {
                    sed -i "s/^#*Port .*/Port ${np}/" /etc/ssh/sshd_config
                    systemctl restart sshd 2>/dev/null
                    echo -e "  ${GREEN}✔ SSH port changed to ${np}!${NC}"
                    [[ $(command -v ufw) ]] && ufw allow "$np" 2>/dev/null
                } || echo -e "  ${RED}✘ Invalid port!${NC}"
                sleep 2 ;;
            2)
                read -p "  Port Dropbear baru (default 222): " np
                [[ "$np" =~ ^[0-9]+$ ]] && {
                    sed -i "s/DROPBEAR_PORT=.*/DROPBEAR_PORT=${np}/" /etc/default/dropbear
                    systemctl restart dropbear 2>/dev/null
                    echo -e "  ${GREEN}✔ Dropbear port changed to ${np}!${NC}"
                } || echo -e "  ${RED}✘ Invalid port!${NC}"
                sleep 2 ;;
            3)
                read -p "  Port Nginx baru (default 80): " np
                [[ "$np" =~ ^[0-9]+$ ]] && {
                    sed -i "s/listen 80 default_server/listen ${np} default_server/g" /etc/nginx/sites-available/vpn
                    nginx -t && systemctl reload nginx && echo -e "  ${GREEN}✔ Nginx port changed to ${np}!${NC}" || echo -e "  ${RED}✘ Config error!${NC}"
                } || echo -e "  ${RED}✘ Invalid port!${NC}"
                sleep 2 ;;
            4)
                read -p "  Port yang akan dibuka: " np
                [[ "$np" =~ ^[0-9]+$ ]] && {
                    ufw allow "$np" 2>/dev/null && echo -e "  ${GREEN}✔ Port ${np} opened!${NC}" || \
                    iptables -I INPUT -p tcp --dport "$np" -j ACCEPT 2>/dev/null && echo -e "  ${GREEN}✔ Port ${np} opened!${NC}"
                } || echo -e "  ${RED}✘ Invalid!${NC}"
                sleep 2 ;;
            5)
                read -p "  Port yang akan ditutup: " np
                [[ "$np" =~ ^[0-9]+$ ]] && {
                    ufw delete allow "$np" 2>/dev/null
                    iptables -D INPUT -p tcp --dport "$np" -j ACCEPT 2>/dev/null
                    echo -e "  ${GREEN}✔ Port ${np} closed!${NC}"
                } || echo -e "  ${RED}✘ Invalid!${NC}"
                sleep 2 ;;
            6)
                echo -e "  ${CYAN}Scanning open ports...${NC}"
                ss -tlnp | grep -E "LISTEN" | awk '{print $4}' | sort -t: -k2 -n | while read addr; do
                    echo -e "  ${GREEN}●${NC} $addr"
                done
                echo ""; read -p "  Press any key..." ;;
            0) return ;;
        esac
    done
}

# [2] Protocol Settings
adv_protocol_settings() {
    while true; do
        clear; print_menu_header "PROTOCOL SETTINGS"
        local W; W=$(get_width)
        _box_top $W
        _box_center $W "${YELLOW}${BOLD}PROTOKOL XRAY${NC}"
        _box_divider $W
        _box_left $W "[1] Aktifkan/Nonaktifkan VMess"
        _box_left $W "[2] Aktifkan/Nonaktifkan VLess"
        _box_left $W "[3] Aktifkan/Nonaktifkan Trojan"
        _box_left $W "[4] Ganti Xray Config (Restore Default)"
        _box_left $W "[5] View Xray Config"
        _box_left $W "[6] Test Xray Config"
        _box_left $W "[7] Set AlterId VMess (0=AEAD)"
        _box_divider $W; _box_left $W "${RED}[0] Back${NC}"; _box_bottom $W
        echo ""; read -p "  Select [0-7]: " ch
        case $ch in
            1)
                local count; count=$(jq '[.inbounds[] | select(.tag | startswith("vmess"))] | length' "$XRAY_CONFIG" 2>/dev/null)
                echo -e "  VMess inbounds aktif: ${GREEN}${count}${NC}"
                echo -e "  ${YELLOW}Disable VMess akan menghapus semua user VMess dari Xray!${NC}"
                read -p "  Lanjutkan? [y/N]: " c
                [[ "$c" == "y" ]] && echo -e "  ${CYAN}Fitur ini perlu modifikasi manual config.${NC}"
                sleep 2 ;;
            4) create_xray_config; echo -e "  ${GREEN}✔ Xray config restored!${NC}"; sleep 2 ;;
            5) clear; cat "$XRAY_CONFIG" | jq . | head -80; echo ""; read -p "  Press any key..." ;;
            6)
                echo -e "  ${CYAN}Testing Xray config...${NC}"
                /usr/local/bin/xray run -test -c "$XRAY_CONFIG" 2>&1 && \
                    echo -e "  ${GREEN}✔ Config OK!${NC}" || echo -e "  ${RED}✘ Config ERROR!${NC}"
                sleep 3 ;;
            7)
                read -p "  AlterId baru (0 untuk AEAD): " aid
                [[ "$aid" =~ ^[0-9]+$ ]] && {
                    jq --argjson aid "$aid" '(.inbounds[] | select(.protocol=="vmess").settings.clients[]?) .alterId = $aid' \
                        "$XRAY_CONFIG" > /tmp/_xr.json && mv /tmp/_xr.json "$XRAY_CONFIG"
                    systemctl reload xray && echo -e "  ${GREEN}✔ AlterId set to ${aid}${NC}"
                }
                sleep 2 ;;
            0) return ;;
        esac
    done
}

# [3] Auto Backup
adv_auto_backup() {
    while true; do
        clear; print_menu_header "AUTO BACKUP"
        local W; W=$(get_width)
        _box_top $W; _box_center $W "${YELLOW}${BOLD}AUTO BACKUP MANAGER${NC}"; _box_divider $W

        # Cek status cron backup
        local cron_status="DISABLED"
        grep -q "vpn-backup" "$CRON_FILE" 2>/dev/null && cron_status="${GREEN}ENABLED${NC}" || cron_status="${RED}DISABLED${NC}"
        _box_left $W "Auto Backup: $(printf "%b" "$cron_status")"
        _box_divider $W
        _box_left $W "[1] Backup Sekarang"
        _box_left $W "[2] Enable Auto Backup (Daily)"
        _box_left $W "[3] Enable Auto Backup (Weekly)"
        _box_left $W "[4] Disable Auto Backup"
        _box_left $W "[5] List Backup Files"
        _box_left $W "[6] Restore dari Backup"
        _box_left $W "[7] Hapus Backup Lama (>7 hari)"
        _box_divider $W; _box_left $W "${RED}[0] Back${NC}"; _box_bottom $W
        echo ""; read -p "  Select [0-7]: " ch
        case $ch in
            1) _menu_backup ;;
            2)
                mkdir -p /etc/cron.d
                echo "0 2 * * * root bash /root/tunnel.sh backup_auto >> /var/log/vpn-backup.log 2>&1" > "$CRON_FILE"
                echo -e "  ${GREEN}✔ Auto backup harian jam 02:00 aktif!${NC}"; sleep 2 ;;
            3)
                mkdir -p /etc/cron.d
                echo "0 2 * * 0 root bash /root/tunnel.sh backup_auto >> /var/log/vpn-backup.log 2>&1" > "$CRON_FILE"
                echo -e "  ${GREEN}✔ Auto backup mingguan (Minggu 02:00) aktif!${NC}"; sleep 2 ;;
            4) rm -f "$CRON_FILE"; echo -e "  ${YELLOW}Auto backup disabled!${NC}"; sleep 2 ;;
            5)
                local backup_dir="/root/backups"
                echo -e "  ${CYAN}Backup files di ${backup_dir}:${NC}"; echo ""
                ls -lh "$backup_dir"/*.tar.gz 2>/dev/null | awk '{print "  "$9" ("$5")"}' || echo -e "  ${RED}Tidak ada backup!${NC}"
                echo ""; read -p "  Press any key..." ;;
            6) _menu_restore ;;
            7)
                local backup_dir="/root/backups"
                find "$backup_dir" -name "*.tar.gz" -mtime +7 -delete 2>/dev/null
                echo -e "  ${GREEN}✔ Backup lama dihapus!${NC}"; sleep 2 ;;
            0) return ;;
        esac
    done
}

# [4] SSH Brute Protect
adv_ssh_brute_protect() {
    while true; do
        clear; print_menu_header "SSH BRUTE PROTECT"
        local W; W=$(get_width)
        _box_top $W; _box_center $W "${YELLOW}${BOLD}SSH BRUTE FORCE PROTECTION${NC}"; _box_divider $W

        local f2b_status="NOT INSTALLED"
        systemctl is-active --quiet fail2ban 2>/dev/null && f2b_status="${GREEN}RUNNING${NC}" || f2b_status="${RED}STOPPED${NC}"
        _box_left $W "Fail2Ban: $(printf "%b" "$f2b_status")"
        _box_divider $W
        _box_left $W "[1] Install & Setup Fail2Ban SSH"
        _box_left $W "[2] Lihat IP yang Diblokir"
        _box_left $W "[3] Unblock IP"
        _box_left $W "[4] Set Max Retry (saat ini: 5)"
        _box_left $W "[5] Set Ban Time (saat ini: 1 jam)"
        _box_left $W "[6] Restart Fail2Ban"
        _box_left $W "[7] Lihat Log Fail2Ban"
        _box_divider $W; _box_left $W "${RED}[0] Back${NC}"; _box_bottom $W
        echo ""; read -p "  Select [0-7]: " ch
        case $ch in
            1)
                echo -e "  ${CYAN}Installing Fail2Ban...${NC}"
                apt-get install -y fail2ban >/dev/null 2>&1
                cat > "$FAIL2BAN_CONF" << 'F2BEOF'
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 5
backend  = systemd

[sshd]
enabled  = true
port     = 22,222
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 5
bantime  = 3600
F2BEOF
                systemctl enable fail2ban 2>/dev/null
                systemctl restart fail2ban 2>/dev/null
                echo -e "  ${GREEN}✔ Fail2Ban SSH aktif! Max 5 retry, ban 1 jam.${NC}"
                sleep 3 ;;
            2)
                fail2ban-client status sshd 2>/dev/null | grep "Banned IP" || echo -e "  ${YELLOW}Fail2Ban tidak aktif.${NC}"
                echo ""; read -p "  Press any key..." ;;
            3)
                read -p "  Masukkan IP untuk unblock: " ip
                [[ -n "$ip" ]] && fail2ban-client set sshd unbanip "$ip" && \
                    echo -e "  ${GREEN}✔ IP ${ip} unblocked!${NC}" || echo -e "  ${RED}✘ Gagal!${NC}"
                sleep 2 ;;
            4)
                read -p "  Max retry baru: " mr
                [[ "$mr" =~ ^[0-9]+$ ]] && {
                    sed -i "s/maxretry = .*/maxretry = ${mr}/" "$FAIL2BAN_CONF"
                    systemctl restart fail2ban && echo -e "  ${GREEN}✔ Max retry: ${mr}${NC}"
                }; sleep 2 ;;
            5)
                read -p "  Ban time baru (detik, 3600=1jam): " bt
                [[ "$bt" =~ ^[0-9]+$ ]] && {
                    sed -i "s/bantime  = .*/bantime  = ${bt}/" "$FAIL2BAN_CONF"
                    systemctl restart fail2ban && echo -e "  ${GREEN}✔ Ban time: ${bt}s${NC}"
                }; sleep 2 ;;
            6) systemctl restart fail2ban && echo -e "  ${GREEN}✔ Restarted!${NC}"; sleep 2 ;;
            7) clear; journalctl -u fail2ban -n 30 --no-pager; echo ""; read -p "  Press any key..." ;;
            0) return ;;
        esac
    done
}

# [5] Fail2Ban Setup (mirip SSH Brute Protect tapi lebih general)
adv_fail2ban_setup() {
    while true; do
        clear; print_menu_header "FAIL2BAN SETUP"
        local W; W=$(get_width)
        _box_top $W; _box_center $W "${YELLOW}${BOLD}FAIL2BAN CONFIGURATION${NC}"; _box_divider $W

        local f2b_status="NOT INSTALLED"
        command -v fail2ban-client >/dev/null && {
            systemctl is-active --quiet fail2ban && f2b_status="${GREEN}RUNNING${NC}" || f2b_status="${YELLOW}STOPPED${NC}"
        }
        _box_left $W "Status: $(printf "%b" "$f2b_status")"
        _box_divider $W
        _box_left $W "[1] Install Fail2Ban"
        _box_left $W "[2] Setup Jail SSH + Nginx"
        _box_left $W "[3] Setup Jail Xray (Log Analysis)"
        _box_left $W "[4] Lihat Semua Jail Status"
        _box_left $W "[5] Enable/Disable Jail"
        _box_left $W "[6] Whitelist IP"
        _box_left $W "[7] Hapus Semua Ban"
        _box_divider $W; _box_left $W "${RED}[0] Back${NC}"; _box_bottom $W
        echo ""; read -p "  Select [0-7]: " ch
        case $ch in
            1)
                apt-get install -y fail2ban >/dev/null 2>&1
                systemctl enable fail2ban; systemctl start fail2ban
                echo -e "  ${GREEN}✔ Fail2Ban installed!${NC}"; sleep 2 ;;
            2)
                cat > "$FAIL2BAN_CONF" << 'F2BEOF'
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 5

[sshd]
enabled  = true
port     = 22,222
maxretry = 5

[nginx-http-auth]
enabled  = true
port     = http,https
logpath  = /var/log/nginx/error.log

[nginx-botsearch]
enabled  = true
port     = http,https
logpath  = /var/log/nginx/error.log
maxretry = 2
F2BEOF
                systemctl restart fail2ban && echo -e "  ${GREEN}✔ Jail SSH + Nginx aktif!${NC}"
                sleep 2 ;;
            3)
                cat >> "$FAIL2BAN_CONF" << 'F2BEOF'

[xray-limit]
enabled  = true
filter   = xray-limit
logpath  = /var/log/xray/error.log
maxretry = 10
bantime  = 600
F2BEOF
                cat > /etc/fail2ban/filter.d/xray-limit.conf << 'FEOF'
[Definition]
failregex = ^.*error.*<HOST>.*$
ignoreregex =
FEOF
                systemctl restart fail2ban && echo -e "  ${GREEN}✔ Jail Xray aktif!${NC}"
                sleep 2 ;;
            4)
                fail2ban-client status 2>/dev/null || echo -e "  ${RED}Fail2Ban tidak aktif!${NC}"
                echo ""; read -p "  Press any key..." ;;
            5)
                read -p "  Nama jail (e.g. sshd): " jail
                read -p "  [enable/disable]: " act
                [[ "$act" == "enable" ]] && fail2ban-client start "$jail" || fail2ban-client stop "$jail"
                sleep 2 ;;
            6)
                read -p "  IP untuk whitelist: " wip
                [[ -n "$wip" ]] && {
                    grep -q "ignoreip" "$FAIL2BAN_CONF" && \
                        sed -i "s/ignoreip.*/ignoreip = 127.0.0.1 ${wip}/" "$FAIL2BAN_CONF" || \
                        echo "ignoreip = 127.0.0.1 ${wip}" >> "$FAIL2BAN_CONF"
                    systemctl restart fail2ban && echo -e "  ${GREEN}✔ IP ${wip} whitelisted!${NC}"
                }; sleep 2 ;;
            7)
                fail2ban-client unban --all 2>/dev/null && echo -e "  ${GREEN}✔ Semua ban dihapus!${NC}"
                sleep 2 ;;
            0) return ;;
        esac
    done
}

# [6] DDoS Protection
adv_ddos_protection() {
    while true; do
        clear; print_menu_header "DDoS PROTECTION"
        local W; W=$(get_width)
        _box_top $W; _box_center $W "${YELLOW}${BOLD}DDoS PROTECTION CONFIG${NC}"; _box_divider $W
        _box_left $W "[1] Enable Basic DDoS Protection (iptables)"
        _box_left $W "[2] Limit Koneksi per IP"
        _box_left $W "[3] Rate Limit HTTP (Nginx)"
        _box_left $W "[4] Block SYN Flood"
        _box_left $W "[5] Block ICMP Flood"
        _box_left $W "[6] Lihat Koneksi Aktif (Top IP)"
        _box_left $W "[7] Block IP Manual"
        _box_left $W "[8] Unblock IP"
        _box_left $W "[9] Disable Semua DDoS Rules"
        _box_divider $W; _box_left $W "${RED}[0] Back${NC}"; _box_bottom $W
        echo ""; read -p "  Select [0-9]: " ch
        case $ch in
            1)
                echo -e "  ${CYAN}Setting up DDoS protection...${NC}"
                # Limit connections per IP
                iptables -A INPUT -p tcp --dport 80 -m connlimit --connlimit-above 50 -j REJECT 2>/dev/null
                iptables -A INPUT -p tcp --dport 443 -m connlimit --connlimit-above 50 -j REJECT 2>/dev/null
                # Rate limit new connections
                iptables -A INPUT -p tcp --dport 80 -m state --state NEW -m limit --limit 50/min --limit-burst 200 -j ACCEPT 2>/dev/null
                iptables -A INPUT -p tcp --dport 443 -m state --state NEW -m limit --limit 50/min --limit-burst 200 -j ACCEPT 2>/dev/null
                echo -e "  ${GREEN}✔ Basic DDoS protection aktif!${NC}"; sleep 2 ;;
            2)
                read -p "  Max koneksi per IP (default 50): " max
                [[ ! "$max" =~ ^[0-9]+$ ]] && max=50
                for port in 80 443 22 222; do
                    iptables -A INPUT -p tcp --dport "$port" -m connlimit --connlimit-above "$max" -j REJECT 2>/dev/null
                done
                echo -e "  ${GREEN}✔ Limit ${max} koneksi/IP aktif!${NC}"; sleep 2 ;;
            3)
                # Nginx rate limiting
                cat > /etc/nginx/conf.d/rate-limit.conf << 'RLEOF'
limit_req_zone $binary_remote_addr zone=one:10m rate=10r/s;
limit_conn_zone $binary_remote_addr zone=addr:10m;
RLEOF
                nginx -t && systemctl reload nginx && echo -e "  ${GREEN}✔ Nginx rate limit aktif!${NC}"
                sleep 2 ;;
            4)
                iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 4 -j ACCEPT 2>/dev/null
                iptables -A INPUT -p tcp --syn -j DROP 2>/dev/null
                echo -e "  ${GREEN}✔ SYN flood protection aktif!${NC}"; sleep 2 ;;
            5)
                iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT 2>/dev/null
                iptables -A INPUT -p icmp --icmp-type echo-request -j DROP 2>/dev/null
                echo -e "  ${GREEN}✔ ICMP flood protection aktif!${NC}"; sleep 2 ;;
            6)
                echo -e "  ${CYAN}Top 20 IP by connection:${NC}"; echo ""
                ss -ntu 2>/dev/null | awk 'NR>1 {print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -20 | \
                    awk '{printf "  %s koneksi : %s\n", $1, $2}'
                echo ""; read -p "  Press any key..." ;;
            7)
                read -p "  IP yang akan diblokir: " bip
                [[ -n "$bip" ]] && {
                    iptables -A INPUT -s "$bip" -j DROP
                    echo -e "  ${GREEN}✔ IP ${bip} diblokir!${NC}"
                    echo "$bip" >> /root/.blocked_ips
                }; sleep 2 ;;
            8)
                read -p "  IP yang akan dibuka: " uip
                [[ -n "$uip" ]] && {
                    iptables -D INPUT -s "$uip" -j DROP 2>/dev/null
                    echo -e "  ${GREEN}✔ IP ${uip} dibuka!${NC}"
                }; sleep 2 ;;
            9)
                iptables -F INPUT 2>/dev/null; iptables -P INPUT ACCEPT 2>/dev/null
                echo -e "  ${YELLOW}Semua DDoS rules dihapus!${NC}"; sleep 2 ;;
            0) return ;;
        esac
    done
}

# [7] Firewall Rules
adv_firewall_rules() {
    while true; do
        clear; print_menu_header "FIREWALL RULES"
        local W; W=$(get_width)
        _box_top $W; _box_center $W "${YELLOW}${BOLD}IPTABLES / UFW FIREWALL${NC}"; _box_divider $W

        # Cek UFW
        local ufw_status="NOT INSTALLED"
        command -v ufw >/dev/null && {
            ufw status 2>/dev/null | grep -q "Status: active" && \
                ufw_status="${GREEN}ACTIVE${NC}" || ufw_status="${YELLOW}INACTIVE${NC}"
        }
        _box_left $W "UFW: $(printf "%b" "$ufw_status")"
        _box_divider $W
        _box_left $W "[1] Install & Enable UFW"
        _box_left $W "[2] Setup Default VPN Rules"
        _box_left $W "[3] Tambah Rule Baru"
        _box_left $W "[4] Hapus Rule"
        _box_left $W "[5] Lihat Semua Rules"
        _box_left $W "[6] Disable UFW"
        _box_left $W "[7] Reset Rules (Default)"
        _box_left $W "[8] Export Rules ke File"
        _box_divider $W; _box_left $W "${RED}[0] Back${NC}"; _box_bottom $W
        echo ""; read -p "  Select [0-8]: " ch
        case $ch in
            1)
                apt-get install -y ufw >/dev/null 2>&1
                ufw --force enable
                echo -e "  ${GREEN}✔ UFW enabled!${NC}"; sleep 2 ;;
            2)
                echo -e "  ${CYAN}Setting up VPN firewall rules...${NC}"
                ufw default deny incoming 2>/dev/null
                ufw default allow outgoing 2>/dev/null
                for port in 22 222 80 81 443 8441 8442 8443 8444; do
                    ufw allow "$port" 2>/dev/null
                done
                ufw allow 7100:7300/udp 2>/dev/null
                ufw --force enable
                echo -e "  ${GREEN}✔ VPN firewall rules aktif!${NC}"; sleep 3 ;;
            3)
                read -p "  Port (contoh: 8080): " port
                read -p "  Protokol [tcp/udp/both]: " proto
                [[ "$proto" == "both" || -z "$proto" ]] && {
                    ufw allow "$port/tcp" 2>/dev/null; ufw allow "$port/udp" 2>/dev/null
                } || ufw allow "$port/$proto" 2>/dev/null
                echo -e "  ${GREEN}✔ Rule added!${NC}"; sleep 2 ;;
            4)
                read -p "  Port yang dihapus: " port
                ufw delete allow "$port" 2>/dev/null && echo -e "  ${GREEN}✔ Rule removed!${NC}"
                sleep 2 ;;
            5) clear; ufw status numbered 2>/dev/null; echo ""; read -p "  Press any key..." ;;
            6) ufw --force disable; echo -e "  ${YELLOW}UFW disabled!${NC}"; sleep 2 ;;
            7)
                read -p "  Reset semua rules? [y/N]: " c
                [[ "$c" == "y" ]] && { ufw --force reset; echo -e "  ${GREEN}✔ Rules reset!${NC}"; }
                sleep 2 ;;
            8)
                ufw status numbered > /root/firewall_rules_backup.txt
                echo -e "  ${GREEN}✔ Rules saved to /root/firewall_rules_backup.txt${NC}"
                sleep 2 ;;
            0) return ;;
        esac
    done
}

# [8] Bandwidth Monitor
adv_bandwidth_monitor() {
    while true; do
        clear; print_menu_header "BANDWIDTH MONITOR"
        local W; W=$(get_width)
        _box_top $W; _box_center $W "${YELLOW}${BOLD}NETWORK BANDWIDTH${NC}"; _box_divider $W
        _box_left $W "[1] Monitor Real-time (vnstat)"
        _box_left $W "[2] Statistik Harian"
        _box_left $W "[3] Statistik Bulanan"
        _box_left $W "[4] Monitor Interface Live (iftop)"
        _box_left $W "[5] Bandwidth per Proses (nethogs)"
        _box_left $W "[6] Install Monitor Tools"
        _box_divider $W; _box_left $W "${RED}[0] Back${NC}"; _box_bottom $W
        echo ""; read -p "  Select [0-6]: " ch
        case $ch in
            1) command -v vnstat >/dev/null && vnstat -l || echo -e "  ${RED}vnstat tidak ada. Pilih [6] install dulu.${NC}"; echo ""; read -p "  Press any key..." ;;
            2) command -v vnstat >/dev/null && vnstat -d || echo -e "  ${RED}vnstat tidak ada.${NC}"; echo ""; read -p "  Press any key..." ;;
            3) command -v vnstat >/dev/null && vnstat -m || echo -e "  ${RED}vnstat tidak ada.${NC}"; echo ""; read -p "  Press any key..." ;;
            4) command -v iftop >/dev/null && iftop || echo -e "  ${RED}iftop tidak ada. Pilih [6] install dulu.${NC}"; echo ""; read -p "  Press any key..." ;;
            5) command -v nethogs >/dev/null && nethogs || echo -e "  ${RED}nethogs tidak ada. Pilih [6] install dulu.${NC}"; echo ""; read -p "  Press any key..." ;;
            6)
                echo -e "  ${CYAN}Installing bandwidth tools...${NC}"
                apt-get install -y vnstat iftop nethogs nload >/dev/null 2>&1
                systemctl enable vnstat; systemctl start vnstat
                echo -e "  ${GREEN}✔ vnstat, iftop, nethogs, nload installed!${NC}"; sleep 2 ;;
            0) return ;;
        esac
    done
}

# [9] User IP Limits
adv_user_ip_limits() {
    while true; do
        clear; print_menu_header "USER IP LIMITS"
        local W; W=$(get_width)
        _box_top $W; _box_center $W "${YELLOW}${BOLD}IP LIMIT MANAGEMENT${NC}"; _box_divider $W
        _box_left $W "[1] Lihat IP Limit Semua User"
        _box_left $W "[2] Set IP Limit User"
        _box_left $W "[3] Cek User Multi-Login"
        _box_left $W "[4] Kick User Multi-Login"
        _box_left $W "[5] Setup Script Cek IP Limit Otomatis"
        _box_divider $W; _box_left $W "${RED}[0] Back${NC}"; _box_bottom $W
        echo ""; read -p "  Select [0-5]: " ch
        case $ch in
            1)
                clear; echo -e "  ${CYAN}IP Limits per User:${NC}"; echo ""
                for f in "$AKUN_DIR"/*.txt; do
                    [[ ! -f "$f" ]] && continue
                    local uname iplimit
                    uname=$(basename "$f" .txt)
                    iplimit=$(grep "IPLIMIT=" "$f" 2>/dev/null | cut -d= -f2)
                    printf "  ${WHITE}%-30s${NC} : ${GREEN}%s IP${NC}\n" "$uname" "${iplimit:-1}"
                done
                echo ""; read -p "  Press any key..." ;;
            2)
                read -p "  Nama file akun (tanpa .txt): " afile
                read -p "  IP Limit baru: " newlimit
                [[ -f "$AKUN_DIR/${afile}.txt" && "$newlimit" =~ ^[0-9]+$ ]] && {
                    sed -i "s/IPLIMIT=.*/IPLIMIT=${newlimit}/" "$AKUN_DIR/${afile}.txt"
                    echo -e "  ${GREEN}✔ IP limit ${afile} → ${newlimit}${NC}"
                } || echo -e "  ${RED}✘ File tidak ditemukan atau limit invalid!${NC}"
                sleep 2 ;;
            3)
                clear; echo -e "  ${CYAN}Koneksi SSH aktif:${NC}"; echo ""
                who | awk '{print $1}' | sort | uniq -c | sort -rn | \
                    awk '{printf "  %s sessions : %s\n", $1, $2}'
                echo ""
                echo -e "  ${CYAN}Koneksi Xray (estimasi dari log):${NC}"
                grep "accepted" /var/log/xray/access.log 2>/dev/null | tail -20 | \
                    awk '{print $NF}' | sort | uniq -c | sort -rn | head -10
                echo ""; read -p "  Press any key..." ;;
            4)
                read -p "  Username SSH untuk kick: " kickuser
                [[ -n "$kickuser" ]] && {
                    pkill -u "$kickuser" 2>/dev/null && echo -e "  ${GREEN}✔ User ${kickuser} di-kick!${NC}" || \
                        echo -e "  ${RED}✘ Tidak ada sesi aktif untuk ${kickuser}${NC}"
                }; sleep 2 ;;
            5)
                cat > /usr/local/bin/check-iplimit.sh << 'IPEOF'
#!/bin/bash
# Cek IP limit untuk SSH
AKUN_DIR="/root/akun"
for f in "$AKUN_DIR"/ssh-*.txt; do
    [[ ! -f "$f" ]] && continue
    uname=$(grep "USERNAME=" "$f" | cut -d= -f2)
    limit=$(grep "IPLIMIT=" "$f" | cut -d= -f2)
    sessions=$(who | grep "^${uname} " | wc -l)
    if [[ "$sessions" -gt "${limit:-1}" ]]; then
        echo "$(date): ${uname} over limit (${sessions}/${limit}), kicking..."
        pkill -u "$uname" 2>/dev/null
    fi
done
IPEOF
                chmod +x /usr/local/bin/check-iplimit.sh
                echo "*/5 * * * * root /usr/local/bin/check-iplimit.sh >> /var/log/iplimit.log 2>&1" > /etc/cron.d/iplimit
                echo -e "  ${GREEN}✔ Cek IP limit otomatis setiap 5 menit aktif!${NC}"; sleep 2 ;;
            0) return ;;
        esac
    done
}

# [10] Custom Payload
adv_custom_payload() {
    while true; do
        clear; print_menu_header "CUSTOM PAYLOAD"
        local W; W=$(get_width)
        _box_top $W; _box_center $W "${YELLOW}${BOLD}HTTP INJECTOR PAYLOAD${NC}"; _box_divider $W
        _box_left $W "[1] Generate Payload GET"
        _box_left $W "[2] Generate Payload POST"
        _box_left $W "[3] Generate Payload WebSocket"
        _box_left $W "[4] Payload untuk HTTP Custom"
        _box_left $W "[5] Payload untuk HTTP Injector"
        _box_left $W "[6] Payload CDN (Cloudflare)"
        _box_left $W "[7] Simpan Payload ke File"
        _box_divider $W; _box_left $W "${RED}[0] Back${NC}"; _box_bottom $W
        echo ""; read -p "  Select [0-7]: " ch
        case $ch in
            1)
                local payload="GET / HTTP/1.1[crlf]Host: ${DOMAIN}[crlf]Connection: Upgrade[crlf]Upgrade: websocket[crlf][crlf]"
                echo -e "  ${YELLOW}Payload GET:${NC}"
                echo -e "  ${GREEN}${payload}${NC}"; echo ""
                read -p "  Press any key..." ;;
            2)
                local payload="POST / HTTP/1.1[crlf]Host: ${DOMAIN}[crlf]Content-Length: 0[crlf]Connection: Upgrade[crlf]Upgrade: websocket[crlf][crlf]"
                echo -e "  ${YELLOW}Payload POST:${NC}"
                echo -e "  ${GREEN}${payload}${NC}"; echo ""
                read -p "  Press any key..." ;;
            3)
                local payload="GET /vmess HTTP/1.1[crlf]Host: ${DOMAIN}[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf]Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==[crlf][crlf]"
                echo -e "  ${YELLOW}Payload WebSocket:${NC}"
                echo -e "  ${GREEN}${payload}${NC}"; echo ""
                read -p "  Press any key..." ;;
            4)
                echo -e "  ${YELLOW}Payload HTTP Custom (HTTP Custom App):${NC}"
                echo -e "  ${GREEN}Host: ${DOMAIN}${NC}"
                echo -e "  ${GREEN}Port: 80${NC}"
                echo -e "  ${GREEN}Payload: GET / HTTP/1.1[crlf]Host: ${DOMAIN}[crlf]Upgrade: websocket[crlf][crlf]${NC}"
                echo ""; read -p "  Press any key..." ;;
            5)
                echo -e "  ${YELLOW}Payload HTTP Injector:${NC}"
                echo -e "  ${GREEN}REAL HOST: ${DOMAIN}${NC}"
                echo -e "  ${GREEN}PROXY: ${DOMAIN}:80${NC}"
                echo -e "  ${GREEN}PAYLOAD: CONNECT [host_port] HTTP/1.0[crlf]Host: ${DOMAIN}[crlf][crlf]${NC}"
                echo ""; read -p "  Press any key..." ;;
            6)
                echo -e "  ${YELLOW}Payload CDN Cloudflare Bug:${NC}"
                echo -e "  ${GREEN}BUG/SNI: bug.com${NC}"
                echo -e "  ${GREEN}HOST: ${DOMAIN}${NC}"
                echo -e "  ${GREEN}PORT TLS: 443${NC}"
                echo -e "  ${GREEN}PATH: /vmess atau /vless atau /trojan${NC}"
                echo ""; read -p "  Press any key..." ;;
            7)
                cat > "$PUBLIC_HTML/payload.txt" << PAYEOF
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  YOUZIN CRABZ - PAYLOAD COLLECTION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Domain : ${DOMAIN}

[GET Payload]
GET / HTTP/1.1[crlf]Host: ${DOMAIN}[crlf]Upgrade: websocket[crlf][crlf]

[POST Payload]
POST / HTTP/1.1[crlf]Host: ${DOMAIN}[crlf]Content-Length: 0[crlf]Upgrade: websocket[crlf][crlf]

[WS Path VMess]
GET /vmess HTTP/1.1[crlf]Host: ${DOMAIN}[crlf]Upgrade: websocket[crlf][crlf]

[WS Path VLess]
GET /vless HTTP/1.1[crlf]Host: ${DOMAIN}[crlf]Upgrade: websocket[crlf][crlf]

[WS Path Trojan]
GET /trojan HTTP/1.1[crlf]Host: ${DOMAIN}[crlf]Upgrade: websocket[crlf][crlf]

[CDN Cloudflare]
BUG: bug.com | PORT TLS: 443 | SNI: ${DOMAIN}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PAYEOF
                local ip_vps; ip_vps=$(get_ip)
                echo -e "  ${GREEN}✔ Payload saved!${NC}"
                echo -e "  Download: http://${ip_vps}:81/payload.txt"
                echo ""; read -p "  Press any key..." ;;
            0) return ;;
        esac
    done
}

# [11] Cron Jobs
adv_cron_jobs() {
    while true; do
        clear; print_menu_header "CRON JOBS"
        local W; W=$(get_width)
        _box_top $W; _box_center $W "${YELLOW}${BOLD}SCHEDULE MANAGER${NC}"; _box_divider $W
        _box_left $W "[1] Lihat Semua Cron Jobs"
        _box_left $W "[2] Auto Delete Expired (Harian)"
        _box_left $W "[3] Auto Renew SSL (Bulanan)"
        _box_left $W "[4] Auto Restart Services (Harian)"
        _box_left $W "[5] Auto Backup (Mingguan)"
        _box_left $W "[6] Custom Cron Job"
        _box_left $W "[7] Hapus Cron Job"
        _box_divider $W; _box_left $W "${RED}[0] Back${NC}"; _box_bottom $W
        echo ""; read -p "  Select [0-7]: " ch
        case $ch in
            1)
                clear; echo -e "  ${CYAN}Cron Jobs Aktif:${NC}"; echo ""
                crontab -l 2>/dev/null | grep -v "^#" | grep -v "^$" | while read line; do
                    echo -e "  ${GREEN}▸${NC} $line"
                done
                ls /etc/cron.d/ 2>/dev/null | while read f; do
                    echo -e "  ${CYAN}[/etc/cron.d/$f]${NC}"
                    grep -v "^#" "/etc/cron.d/$f" 2>/dev/null | grep -v "^$" | while read line; do
                        echo -e "  ${GREEN}▸${NC} $line"
                    done
                done
                echo ""; read -p "  Press any key..." ;;
            2)
                echo "0 0 * * * root bash /root/tunnel.sh delete_expired_auto >> /var/log/vpn-cron.log 2>&1" > /etc/cron.d/vpn-expired
                echo -e "  ${GREEN}✔ Auto delete expired aktif setiap tengah malam!${NC}"; sleep 2 ;;
            3)
                echo "0 3 1 * * root certbot renew --quiet && systemctl reload nginx haproxy >> /var/log/certbot-renew.log 2>&1" > /etc/cron.d/certbot-renew
                echo -e "  ${GREEN}✔ Auto SSL renew aktif tanggal 1 tiap bulan!${NC}"; sleep 2 ;;
            4)
                echo "0 4 * * * root systemctl restart xray nginx haproxy dropbear udp-custom >> /var/log/vpn-restart.log 2>&1" > /etc/cron.d/vpn-restart
                echo -e "  ${GREEN}✔ Auto restart services jam 04:00!${NC}"; sleep 2 ;;
            5)
                echo "0 2 * * 0 root tar -czf /root/backups/auto-backup-\$(date +%Y%m%d).tar.gz /root/akun /root/domain /usr/local/etc/xray/config.json >> /var/log/vpn-backup.log 2>&1" > /etc/cron.d/vpn-backup
                echo -e "  ${GREEN}✔ Auto backup mingguan aktif!${NC}"; sleep 2 ;;
            6)
                read -p "  Cron expression (e.g. 0 2 * * *): " cronexpr
                read -p "  Command: " croncmd
                [[ -n "$cronexpr" && -n "$croncmd" ]] && {
                    echo "${cronexpr} root ${croncmd}" >> /etc/cron.d/vpn-custom
                    echo -e "  ${GREEN}✔ Custom cron added!${NC}"
                }; sleep 2 ;;
            7)
                read -p "  File cron di /etc/cron.d/ yang dihapus: " cronfile
                rm -f "/etc/cron.d/${cronfile}"
                echo -e "  ${GREEN}✔ Cron ${cronfile} dihapus!${NC}"; sleep 2 ;;
            0) return ;;
        esac
    done
}

# [12] System Logs
adv_system_logs() {
    while true; do
        clear; print_menu_header "SYSTEM LOGS"
        local W; W=$(get_width)
        _box_top $W; _box_center $W "${YELLOW}${BOLD}LOG VIEWER${NC}"; _box_divider $W
        _box_left $W "[1]  Xray Access Log"
        _box_left $W "[2]  Xray Error Log"
        _box_left $W "[3]  Nginx Access Log"
        _box_left $W "[4]  Nginx Error Log"
        _box_left $W "[5]  SSH Auth Log"
        _box_left $W "[6]  HAProxy Log"
        _box_left $W "[7]  System Log (syslog)"
        _box_left $W "[8]  Fail2Ban Log"
        _box_left $W "[9]  Telegram Bot Log"
        _box_left $W "[10] Bersihkan Semua Log"
        _box_left $W "[11] Cek Disk Usage Log"
        _box_divider $W; _box_left $W "${RED}[0] Back${NC}"; _box_bottom $W
        echo ""; read -p "  Select [0-11]: " ch
        case $ch in
            1) clear; tail -50 /var/log/xray/access.log 2>/dev/null || echo "Log kosong"; echo ""; read -p "  Press any key..." ;;
            2) clear; tail -50 /var/log/xray/error.log 2>/dev/null || echo "Log kosong"; echo ""; read -p "  Press any key..." ;;
            3) clear; tail -50 /var/log/nginx/access.log 2>/dev/null || echo "Log kosong"; echo ""; read -p "  Press any key..." ;;
            4) clear; tail -50 /var/log/nginx/error.log 2>/dev/null || echo "Log kosong"; echo ""; read -p "  Press any key..." ;;
            5) clear; tail -50 /var/log/auth.log 2>/dev/null || journalctl -u sshd -n 50 --no-pager; echo ""; read -p "  Press any key..." ;;
            6) clear; journalctl -u haproxy -n 50 --no-pager; echo ""; read -p "  Press any key..." ;;
            7) clear; tail -50 /var/log/syslog 2>/dev/null || journalctl -n 50 --no-pager; echo ""; read -p "  Press any key..." ;;
            8) clear; tail -50 /var/log/fail2ban.log 2>/dev/null || echo "Fail2Ban tidak ada"; echo ""; read -p "  Press any key..." ;;
            9) clear; journalctl -u vpn-bot -n 50 --no-pager; echo ""; read -p "  Press any key..." ;;
            10)
                read -p "  Bersihkan semua log? [y/N]: " c
                [[ "$c" == "y" ]] && {
                    > /var/log/xray/access.log
                    > /var/log/xray/error.log
                    > /var/log/nginx/access.log
                    > /var/log/nginx/error.log
                    journalctl --vacuum-time=1d 2>/dev/null
                    echo -e "  ${GREEN}✔ Log dibersihkan!${NC}"
                }; sleep 2 ;;
            11)
                echo -e "  ${CYAN}Disk usage log files:${NC}"; echo ""
                du -sh /var/log/* 2>/dev/null | sort -rh | head -20 | awk '{printf "  %-10s %s\n", $1, $2}'
                echo ""; read -p "  Press any key..." ;;
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
        s.settimeout(TIMEOUT); s.connect((SSH_HOST, SSH_PORT))
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
        s.bind(('0.0.0.0', port)); s.setblocking(False)
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
    systemctl daemon-reload; systemctl enable udp-custom 2>/dev/null
    systemctl restart udp-custom; sleep 1
    systemctl is-active --quiet udp-custom && \
        echo -e "  ${GREEN}✔ UDP OK! (7100-7300)${NC}" || echo -e "  ${RED}✘ UDP Failed!${NC}"
}

#================================================
# TELEGRAM BOT MENU
#================================================

setup_telegram_bot() {
    clear; print_menu_header "SETUP TELEGRAM BOT"
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
    echo -e "  ${GREEN}✔ Bot valid! @${bot_name}${NC}"; echo ""
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

    _install_bot_service; sleep 2
    systemctl is-active --quiet vpn-bot && \
        echo -e "  ${GREEN}✔ Bot aktif! @${bot_name}${NC}" || echo -e "  ${RED}✘ Bot gagal start!${NC}"
    echo ""; read -p "  Press any key to back..."
}

_install_bot_service() {
    mkdir -p /root/bot "$ORDER_DIR"
    pip3 install requests --break-system-packages >/dev/null 2>&1 || pip3 install requests >/dev/null 2>&1

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
                if '=' in line: k,v = line.strip().split('=',1); info[k] = v
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
        return "vmess://"+j(443,True,"/vmess"), "vmess://"+j(80,False,"/vmess"), "vmess://"+base64.b64encode(json.dumps({"v":"2","ps":uname,"add":DOMAIN,"port":"443","id":uid,"aid":"0","net":"grpc","path":"vmess-grpc","tls":"tls","sni":DOMAIN}).encode()).decode()
    elif proto == 'vless':
        return (f"vless://{uid}@bug.com:8442?path=%2Fvless&security=tls&encryption=none&host={DOMAIN}&type=ws&sni={DOMAIN}#{uname}",
                f"vless://{uid}@bug.com:80?path=%2Fvless&security=none&encryption=none&host={DOMAIN}&type=ws#{uname}",
                f"vless://{uid}@{DOMAIN}:443?mode=gun&security=tls&encryption=none&type=grpc&serviceName=vless-grpc&sni={DOMAIN}#{uname}")
    else:
        return (f"trojan://{uid}@bug.com:8441?path=%2Ftrojan&security=tls&host={DOMAIN}&type=ws&sni={DOMAIN}#{uname}",
                f"trojan://{uid}@bug.com:80?path=%2Ftrojan&security=none&host={DOMAIN}&type=ws#{uname}",
                f"trojan://{uid}@{DOMAIN}:443?mode=gun&security=tls&type=grpc&serviceName=trojan-grpc&sni={DOMAIN}#{uname}")

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
    return {'keyboard':[['🆓 Trial Gratis','🛒 Order VPN'],['📋 Cek Akun','ℹ️ Info Server'],['❓ Bantuan','📞 Hubungi Admin']],'resize_keyboard':True}

def kb_trial():
    return {'inline_keyboard':[[{'text':'VMess','callback_data':'trial_vmess'},{'text':'VLess','callback_data':'trial_vless'},{'text':'Trojan','callback_data':'trial_trojan'}],[{'text':'◀️ Kembali','callback_data':'back'}]]}

def kb_order():
    return {'inline_keyboard':[[{'text':'VMess','callback_data':'order_vmess'},{'text':'VLess','callback_data':'order_vless'},{'text':'Trojan','callback_data':'order_trojan'}],[{'text':'◀️ Kembali','callback_data':'back'}]]}

def kb_confirm(oid):
    return {'inline_keyboard':[[{'text':'✅ Konfirmasi','callback_data':f'confirm_{oid}'},{'text':'❌ Tolak','callback_data':f'reject_{oid}'}]]}

def do_trial(proto, cid):
    uname = f'trial-{datetime.now().strftime("%H%M%S")}'
    exp = (datetime.now() + timedelta(hours=1)).strftime('%d %b %Y %H:%M')
    uid, _, tls, ntls, grpc = xray_add(proto, uname, days=1)
    if not uid: send(cid, '❌ Gagal buat akun trial.'); return
    run(f'(sleep 3600; jq --arg em "{uname}" \'del(.inbounds[].settings.clients[]? | select(.email==$em))\' {XRAY_CFG} > /tmp/_xd.json && mv /tmp/_xd.json {XRAY_CFG}; systemctl reload xray 2>/dev/null; rm -f {AKUN_DIR}/{proto}-{uname}.txt) &')
    msg = f'✅ <b>Trial {proto.upper()} (1 Jam)</b>\n👤 <code>{uname}</code> | 🔑 <code>{uid}</code>\n\n🔗 TLS:\n<code>{tls}</code>\n\n🔗 NonTLS:\n<code>{ntls}</code>\n\n⏰ Expired: {exp}'
    send(cid, msg, markup=kb_main())

def handle_msg(msg):
    cid  = msg['chat']['id']
    text = msg.get('text','').strip()
    fname = msg['from'].get('first_name','User')
    uname = msg['from'].get('username','')
    with lock: s = dict(state.get(cid, {}))
    if s.get('step') == 'wait_username':
        new_u = text.replace(' ','_')
        if len(new_u) < 3: send(cid, '❌ Username min 3 karakter!'); return
        proto = s['proto']
        oid = f'{cid}_{int(time.time())}'
        order = {'order_id':oid,'chat_id':cid,'username':new_u,'protocol':proto,'status':'pending','tg_user':uname,'tg_name':fname}
        with open(f'{ORDER_DIR}/{oid}.json','w') as f: json.dump(order, f)
        with lock: state.pop(cid, None)
        pay = get_payment()
        send(cid, f'🛒 <b>Order {proto.upper()}</b>\n👤 <code>{new_u}</code>\n💰 Rp {int(pay["HARGA"]):,}\n🏦 {pay["REK_BANK"]}: {pay["REK_NUMBER"]}\nTransfer & kirim bukti ke admin.')
        send(ADMIN_ID, f'🔔 <b>ORDER BARU {proto.upper()}</b>\n👤 <code>{new_u}</code> | @{uname}', markup=kb_confirm(oid))
        return
    with lock: state.pop(cid, None)
    if text in ['/start','🏠 Menu']:
        send(cid, f'👋 Halo <b>{fname}</b>!\n🤖 Youzin Crabz Tunel\n🌐 <code>{DOMAIN}</code>', markup=kb_main())
    elif text == '🆓 Trial Gratis': send(cid, '🆓 Pilih protocol:', markup=kb_trial())
    elif text == '🛒 Order VPN': send(cid, '🛒 Pilih protocol:', markup=kb_order())
    elif text == '📋 Cek Akun':
        found = [json.load(open(f'{ORDER_DIR}/{fn}')) for fn in os.listdir(ORDER_DIR) if fn.endswith('.json') and str(json.load(open(f'{ORDER_DIR}/{fn}')).get('chat_id')) == str(cid) and json.load(open(f'{ORDER_DIR}/{fn}')).get('status') == 'confirmed'] if os.path.exists(ORDER_DIR) else []
        if not found: send(cid, '📋 Tidak ada akun aktif.', markup=kb_main())
        else: send(cid, '📋 <b>Akun Aktif:</b>\n' + ''.join(f'• {a["protocol"].upper()} → <code>{a["username"]}</code>\n' for a in found), markup=kb_main())
    elif text == 'ℹ️ Info Server': send(cid, f'ℹ️ <b>SERVER</b>\n🌐 <code>{DOMAIN}</code>\n🖥️ <code>{get_ip()}</code>\n🔌 VMess:443 | VLess:8442 | Trojan:8441 | gRPC:443', markup=kb_main())
    elif text == '❓ Bantuan': send(cid, '❓ <b>Cara Order:</b>\n1. 🛒 Order VPN\n2. Pilih protokol\n3. Ketik username\n4. Transfer ke rekening\n5. Kirim bukti pembayaran\n6. Admin konfirmasi', markup=kb_main())
    elif text == '📞 Hubungi Admin':
        send(cid, '📞 Pesan diteruskan ke admin.', markup=kb_main())
        send(ADMIN_ID, f'📞 <b>{fname}</b> (@{uname}) ID:<code>{cid}</code> butuh bantuan!')

def handle_cb(cb):
    cid = cb['message']['chat']['id']
    data = cb['data']
    api('answerCallbackQuery', {'callback_query_id': cb['id']})
    if data.startswith('trial_'): threading.Thread(target=do_trial, args=(data[6:], cid), daemon=True).start()
    elif data.startswith('order_'):
        with lock: state[cid] = {'step':'wait_username','proto':data[6:]}
        send(cid, f'📝 Ketik username untuk {data[6:].upper()}:')
    elif data == 'back': send(cid, '🏠 Menu Utama', markup=kb_main())
    elif data.startswith('confirm_') and cid == ADMIN_ID:
        oid = data[8:]
        try:
            with open(f'{ORDER_DIR}/{oid}.json') as f: order = json.load(f)
        except: send(ADMIN_ID,'❌ Order tidak ada!'); return
        if order.get('status') != 'pending': send(ADMIN_ID,'⚠️ Sudah diproses!'); return
        def do_confirm():
            uid, exp, tls, ntls, grpc = xray_add(order['protocol'], order['username'])
            if not uid: send(ADMIN_ID,'❌ Gagal!'); return
            order['status'] = 'confirmed'
            with open(f'{ORDER_DIR}/{oid}.json','w') as f: json.dump(order, f)
            send(order['chat_id'], f'✅ <b>{order["protocol"].upper()}</b>\n👤 <code>{order["username"]}</code>\n🔑 <code>{uid}</code>\n🔗 TLS:\n<code>{tls}</code>\n🔗 NonTLS:\n<code>{ntls}</code>\n📅 Exp: {exp}', markup=kb_main())
            send(ADMIN_ID, f'✅ Dikirim ke @{order.get("tg_user","?")}')
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
                if 'message' in upd: threading.Thread(target=handle_msg, args=(upd['message'],), daemon=True).start()
                elif 'callback_query' in upd: threading.Thread(target=handle_cb, args=(upd['callback_query'],), daemon=True).start()
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
    systemctl daemon-reload; systemctl enable vpn-bot 2>/dev/null; systemctl restart vpn-bot 2>/dev/null
}

menu_telegram_bot() {
    while true; do
        clear; print_menu_header "TELEGRAM BOT"
        local W; W=$(get_width)
        local bs; bs=$(check_status vpn-bot)
        local cs
        [[ "$bs" == "ON" ]] && cs="${GREEN}RUNNING${NC}" || cs="${RED}STOPPED${NC}"
        _box_top $W; _box_center $W "${YELLOW}${BOLD}TELEGRAM BOT${NC}"; _box_divider $W
        _box_left $W "Status : $(printf "%b" "$cs")"
        _box_divider $W
        _box_left $W "[1] Setup Bot"; _box_left $W "[2] Start Bot"
        _box_left $W "[3] Stop Bot"; _box_left $W "[4] Restart Bot"
        _box_left $W "[5] Lihat Log"
        _box_divider $W; _box_left $W "${RED}[0] Back${NC}"; _box_bottom $W
        echo ""; read -p "  Select [0-5]: " choice
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
# OTHER SYSTEM FUNCTIONS
#================================================

change_domain() {
    clear; print_menu_header "CHANGE DOMAIN"
    echo -e "  Current: ${GREEN}${DOMAIN:-Not Set}${NC}"; echo ""
    setup_domain
    echo -e "  ${YELLOW}Jalankan Fix Certificate [11]!${NC}"; sleep 3
}

fix_certificate() {
    clear; print_menu_header "FIX / RENEW CERTIFICATE"
    [[ -f "$DOMAIN_FILE" ]] && DOMAIN=$(tr -d '\n\r' < "$DOMAIN_FILE" | xargs)
    [[ -z "$DOMAIN" ]] && { echo -e "  ${RED}✘ Domain belum diset!${NC}"; sleep 3; return; }
    echo -e "  Domain: ${GREEN}${DOMAIN}${NC}"; echo ""
    get_ssl_cert
    systemctl restart xray haproxy 2>/dev/null
    echo -e "  ${GREEN}✔ Done!${NC}"; sleep 3
}

run_speedtest() {
    clear; print_menu_header "SPEEDTEST"
    if ! command -v speedtest >/dev/null 2>&1; then
        echo -e "  ${CYAN}Installing Speedtest CLI...${NC}"
        curl -s https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.deb.sh | bash >/dev/null 2>&1
        apt-get install -y speedtest >/dev/null 2>&1
    fi
    echo -e "  ${YELLOW}Testing... harap tunggu ~30 detik${NC}"; echo ""
    if command -v speedtest >/dev/null 2>&1; then
        local result; result=$(speedtest --accept-license --accept-gdpr 2>/dev/null)
        if [[ -n "$result" ]]; then
            echo "$result" | grep -E "Server:|Latency:|Download:|Upload:|Result" | while read line; do
                echo -e "  ${GREEN}▸${NC} $line"
            done
        else
            echo -e "  ${RED}✘ Speedtest gagal!${NC}"
        fi
    else
        echo -e "  ${RED}✘ Speedtest tidak tersedia!${NC}"
    fi
    echo ""; read -p "  Press any key to back..."
}

update_menu() {
    clear; print_menu_header "UPDATE SCRIPT"
    echo -e "  Current Version : ${GREEN}${SCRIPT_VERSION}${NC}"; echo ""
    local latest
    latest=$(curl -s --max-time 10 "$VERSION_URL" 2>/dev/null | tr -d '\n\r ' | xargs)
    if [[ -z "$latest" ]]; then
        echo -e "  ${RED}✘ Cannot connect to GitHub!${NC}"; echo ""; read -p "  Press Enter..."; return
    fi
    echo -e "  Latest Version  : ${GREEN}${latest}${NC}"; echo ""
    if [[ "$latest" == "$SCRIPT_VERSION" ]]; then
        echo -e "  ${GREEN}✔ Script sudah versi terbaru!${NC}"; echo ""; read -p "  Press Enter..."; return
    fi
    read -p "  Update now? [y/N]: " confirm
    [[ "$confirm" != "y" ]] && return
    cp "$SCRIPT_PATH" "$BACKUP_PATH" 2>/dev/null
    local tmp="/tmp/tunnel_new.sh"
    curl -L --max-time 60 "$SCRIPT_URL" -o "$tmp" 2>/dev/null
    if [[ ! -s "$tmp" ]]; then echo -e "  ${RED}✘ Download failed!${NC}"; read -p "  Press Enter..."; return; fi
    bash -n "$tmp" 2>/dev/null && {
        mv "$tmp" "$SCRIPT_PATH"; chmod +x "$SCRIPT_PATH"
        echo -e "  ${GREEN}✔ Update sukses!${NC}"; sleep 2; exec bash "$SCRIPT_PATH"
    } || { echo -e "  ${RED}✘ Syntax error!${NC}"; rm -f "$tmp"; read -p "  Press Enter..."; }
}

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
    [[ -f "$backup_dir/$backup_file" ]] && {
        echo -e "  ${GREEN}✔ Backup created!${NC}"
        echo -e "  File : ${WHITE}${backup_file}${NC}"
        echo -e "  Size : ${CYAN}$(du -h "$backup_dir/$backup_file" | awk '{print $1}')${NC}"
    } || echo -e "  ${RED}✘ Backup failed!${NC}"
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
        printf "  ${CYAN}[%d]${NC} %s\n" "$i" "$(basename "$b")"; ((i++))
    done
    echo ""; read -p "  Select [1-${#backups[@]}] atau 0 cancel: " choice
    [[ "$choice" == "0" ]] && return
    local selected="${backups[$((choice-1))]}"
    read -p "  Continue? [y/N]: " confirm
    [[ "$confirm" != "y" ]] && return
    tar -xzf "$selected" -C / 2>/dev/null && \
        echo -e "  ${GREEN}✔ Restore OK!${NC}" || echo -e "  ${RED}✘ Restore failed!${NC}"
    systemctl restart xray nginx haproxy 2>/dev/null
    echo ""; read -p "  Press any key to back..."
}

_menu_list_all() {
    clear; print_menu_header "ALL ACCOUNTS"
    local total=0; local W; W=$(get_width)
    shopt -s nullglob
    for proto in ssh vmess vless trojan; do
        local files=("$AKUN_DIR"/${proto}-*.txt)
        [[ ${#files[@]} -eq 0 ]] && continue
        _box_top $W
        _box_center $W "${GREEN}${proto^^} ACCOUNTS${NC}"
        _box_divider $W
        for f in "${files[@]}"; do
            local uname exp
            uname=$(basename "$f" .txt | sed "s/${proto}-//")
            exp=$(grep "EXPIRED" "$f" 2>/dev/null | cut -d= -f2-)
            _box_two_col $W "${GREEN}${uname}${NC}" "${YELLOW}${exp}${NC}"
            ((total++))
        done
        _box_bottom $W; echo ""
    done
    shopt -u nullglob
    echo -e "  ${WHITE}Total: ${GREEN}${total}${NC} accounts"
    echo ""; read -p "  Press any key to back..."
}

menu_uninstall() {
    while true; do
        clear; print_menu_header "UNINSTALL MENU"
        local W; W=$(get_width)
        _box_top $W; _box_center $W "${YELLOW}${BOLD}UNINSTALL${NC}"; _box_divider $W
        _box_left $W "[1] Uninstall Xray"; _box_left $W "[2] Uninstall Nginx"
        _box_left $W "[3] Uninstall HAProxy"; _box_left $W "[4] Uninstall Dropbear"
        _box_left $W "[5] Uninstall UDP Custom"; _box_left $W "[6] Uninstall Bot"
        _box_divider $W; _box_left $W "${RED}[7] HAPUS SEMUA${NC}"
        _box_divider $W; _box_left $W "${RED}[0] Back${NC}"; _box_bottom $W
        echo ""; read -p "  Select [0-7]: " choice
        case $choice in
            1) read -p "  Yakin? [y/n]: " c; [[ "$c" == "y" ]] && { systemctl stop xray; systemctl disable xray; bash <(curl -Ls https://github.com/XTLS/Xray-install/raw/main/install-release.sh) --remove >/dev/null 2>&1; echo -e "  ${GREEN}✔ Done!${NC}"; sleep 2; } ;;
            2) read -p "  Yakin? [y/n]: " c; [[ "$c" == "y" ]] && { systemctl stop nginx; apt-get purge -y nginx >/dev/null 2>&1; echo -e "  ${GREEN}✔ Done!${NC}"; sleep 2; } ;;
            3) read -p "  Yakin? [y/n]: " c; [[ "$c" == "y" ]] && { systemctl stop haproxy; apt-get purge -y haproxy >/dev/null 2>&1; echo -e "  ${GREEN}✔ Done!${NC}"; sleep 2; } ;;
            4) read -p "  Yakin? [y/n]: " c; [[ "$c" == "y" ]] && { systemctl stop dropbear; apt-get purge -y dropbear >/dev/null 2>&1; echo -e "  ${GREEN}✔ Done!${NC}"; sleep 2; } ;;
            5) read -p "  Yakin? [y/n]: " c; [[ "$c" == "y" ]] && { systemctl stop udp-custom; systemctl disable udp-custom; rm -f /etc/systemd/system/udp-custom.service /usr/local/bin/udp-custom; systemctl daemon-reload; echo -e "  ${GREEN}✔ Done!${NC}"; sleep 2; } ;;
            6) read -p "  Yakin? [y/n]: " c; [[ "$c" == "y" ]] && { systemctl stop vpn-bot; systemctl disable vpn-bot; rm -f /etc/systemd/system/vpn-bot.service; rm -rf /root/bot; rm -f "$BOT_TOKEN_FILE" "$CHAT_ID_FILE" "$PAYMENT_FILE"; systemctl daemon-reload; echo -e "  ${GREEN}✔ Done!${NC}"; sleep 2; } ;;
            7)
                read -p "  Ketik 'HAPUS' untuk konfirmasi: " confirm
                [[ "$confirm" != "HAPUS" ]] && { echo -e "  ${YELLOW}Dibatalkan.${NC}"; sleep 2; continue; }
                for svc in xray nginx haproxy dropbear udp-custom vpn-keepalive vpn-bot; do
                    systemctl stop "$svc" 2>/dev/null; systemctl disable "$svc" 2>/dev/null
                done
                bash <(curl -Ls https://github.com/XTLS/Xray-install/raw/main/install-release.sh) --remove >/dev/null 2>&1
                apt-get purge -y nginx haproxy dropbear >/dev/null 2>&1
                rm -rf /usr/local/etc/xray /var/log/xray /etc/xray /root/akun /root/bot /root/orders \
                       /root/domain /root/.domain_type "$BOT_TOKEN_FILE" "$CHAT_ID_FILE" "$PAYMENT_FILE"
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
    clear
    echo ""
    echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${YELLOW}  ✦ ✦ ✦  Youzin Crabz Tunel Auto Install  ✦ ✦ ✦${NC}"
    echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    setup_domain
    [[ -z "$DOMAIN" ]] && { echo -e "  ${RED}✘ Domain kosong!${NC}"; exit 1; }

    local domain_type="custom"
    [[ -f "$DOMAIN_TYPE_FILE" ]] && domain_type=$(cat "$DOMAIN_TYPE_FILE")

    clear
    echo -e "  ${WHITE}Domain   :${NC} ${GREEN}${DOMAIN}${NC}"
    echo -e "  ${WHITE}SSL Type :${NC} ${GREEN}$([[ "$domain_type" == "custom" ]] && echo "Let's Encrypt" || echo "Self-Signed")${NC}"
    echo ""

    local LOG="/tmp/install.log"; > "$LOG"

    _run() {
        local label="$1" cmd="$2"
        printf "  ${CYAN}►${NC} %-45s" "${label}..."
        eval "$cmd" >> "$LOG" 2>&1
        [[ $? -eq 0 ]] && printf "${GREEN}OK${NC}\n" || printf "${RED}FAIL${NC}\n"
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
    for pkg in curl wget unzip uuid-runtime net-tools openssl jq python3 python3-pip; do _pkg "$pkg"; done

    echo -e "\n  ${YELLOW}[3/9] VPN Services${NC}"
    for pkg in nginx openssh-server dropbear haproxy certbot; do _pkg "$pkg"; done

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
            _run "Self-signed cert" "_gen_self_signed"; done_msg "Self-signed cert generated"
        fi
    else
        _run "Self-signed cert" "_gen_self_signed"; done_msg "Self-signed cert generated"
    fi
    chmod 644 /etc/xray/xray.* 2>/dev/null

    echo -e "\n  ${YELLOW}[7/9] Creating Configs${NC}"
    _run "Nginx config (optimized WS)" "configure_nginx"
    nginx -t >> "$LOG" 2>&1 && done_msg "Nginx config valid" || fail_msg "Nginx config error"
    _run "Xray config (multi-port)" "create_xray_config"
    done_msg "VMess:8443 VLess:8442 Trojan:8441 gRPC:8444"
    _run "HAProxy config" "configure_haproxy_multiport"
    done_msg "HAProxy 443→8443 & 443→8444"
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
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Courier New',monospace;background:#0a0a1a;color:#eee;display:flex;align-items:center;justify-content:center;min-height:100vh;text-align:center}.box{padding:40px;background:#0d1117;border:1px solid #00d4ff44;border-radius:12px;max-width:500px}h1{color:#00d4ff;margin-bottom:5px}p{color:#666;margin:4px 0;font-size:0.85em}.badge{display:inline-block;background:#00d4ff22;color:#00d4ff;padding:4px 16px;border-radius:20px;margin-top:15px;font-size:12px;border:1px solid #00d4ff33}</style>
</head><body><div class="box"><h1>⚡ YOUZIN CRABZ</h1><p>TUNEL v${SCRIPT_VERSION}</p><p>${DOMAIN}</p><p>${ip_vps}</p><div class="badge">The Professor</div></div></body></html>
IDXEOF

    echo ""
    echo -e "${GREEN}  ╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}  ║      ✔  INSTALASI SELESAI! v${SCRIPT_VERSION}             ║${NC}"
    echo -e "${GREEN}  ╚══════════════════════════════════════════════════╝${NC}"
    echo ""
    printf "  ${WHITE}%-22s${NC}: ${GREEN}%s${NC}\n" "Domain"        "$DOMAIN"
    printf "  ${WHITE}%-22s${NC}: ${GREEN}%s${NC}\n" "IP VPS"        "$ip_vps"
    printf "  ${WHITE}%-22s${NC}: ${CYAN}%s${NC}\n"  "SSH/Dropbear"  "22 | 222"
    printf "  ${WHITE}%-22s${NC}: ${CYAN}%s${NC}\n"  "VMess TLS"     "443 (HAProxy→8443)"
    printf "  ${WHITE}%-22s${NC}: ${CYAN}%s${NC}\n"  "VLess TLS"     "8442 (direct)"
    printf "  ${WHITE}%-22s${NC}: ${CYAN}%s${NC}\n"  "Trojan TLS"    "8441 (direct)"
    printf "  ${WHITE}%-22s${NC}: ${CYAN}%s${NC}\n"  "NonTLS Nginx"  "80 → path /vmess /vless /trojan"
    printf "  ${WHITE}%-22s${NC}: ${CYAN}%s${NC}\n"  "gRPC TLS"      "443 (HAProxy→8444+)"
    printf "  ${WHITE}%-22s${NC}: ${CYAN}%s${NC}\n"  "BadVPN UDP"    "7100-7300"
    printf "  ${WHITE}%-22s${NC}: ${CYAN}%s${NC}\n"  "Download"      "http://${ip_vps}:81/"
    echo ""
    echo -e "  ${YELLOW}💡 Ketik 'menu' untuk membuka panel!${NC}"
    echo -e "  ${YELLOW}Reboot dalam 5 detik...${NC}"
    sleep 5; reboot
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
                    1) create_trial_xray "vmess" ;; 2) create_trial_xray "vless" ;;
                    3) create_trial_xray "trojan" ;;
                esac ;;
            6|06) _menu_list_all ;;
            7|07) cek_expired ;;
            8|08) delete_expired ;;
            9|09) menu_telegram_bot ;;
            10) change_domain ;;
            11) fix_certificate ;;
            12) clear; optimize_vpn; echo -e "  ${GREEN}✔ Optimization done!${NC}"; sleep 2 ;;
            13)
                clear; print_menu_header "RESTART ALL SERVICES"
                for svc in xray nginx sshd dropbear haproxy udp-custom vpn-keepalive vpn-bot; do
                    systemctl restart "$svc" 2>/dev/null && \
                        printf "  ${GREEN}✔${NC} %-20s ${GREEN}Restarted${NC}\n" "$svc" || \
                        printf "  ${RED}✘${NC} %-20s ${RED}Failed${NC}\n" "$svc"
                done; echo ""; sleep 2 ;;
            14) show_info_port ;;
            15) run_speedtest ;;
            16) update_menu ;;
            17) _menu_backup ;;
            18) _menu_restore ;;
            19) menu_uninstall ;;
            20) menu_advanced ;;
            0|00) clear; echo -e "  ${CYAN}Goodbye! — Youzin Crabz Tunel${NC}"; exit 0 ;;
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

# Handle auto backup dari cron
[[ "$1" == "backup_auto" ]] && {
    backup_dir="/root/backups"; mkdir -p "$backup_dir"
    tar -czf "$backup_dir/auto-backup-$(date +%Y%m%d).tar.gz" \
        /root/akun /root/domain /usr/local/etc/xray/config.json 2>/dev/null
    exit 0
}

[[ -f "$DOMAIN_FILE" ]] && DOMAIN=$(tr -d '\n\r' < "$DOMAIN_FILE" | xargs)

if [[ ! -f "$DOMAIN_FILE" ]]; then
    auto_install
fi

setup_menu_command
main_menu
