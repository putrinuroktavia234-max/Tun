#!/bin/bash

#================================================
# Youzin Crabz Tunel
# The Professor
# GitHub: putrinuroktavia234-max/Tunnel
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
SCRIPT_VERSION="3.1.0"
SCRIPT_AUTHOR="The Professor"
GITHUB_USER="putrinuroktavia234-max"
GITHUB_REPO="Tunnel"
GITHUB_BRANCH="main"
SCRIPT_URL="https://raw.githubusercontent.com/${GITHUB_USER}/${GITHUB_REPO}/${GITHUB_BRANCH}/tunnel.sh"
VERSION_URL="https://raw.githubusercontent.com/${GITHUB_USER}/${GITHUB_REPO}/${GITHUB_BRANCH}/version"
SCRIPT_PATH="/root/tunnel.sh"
BACKUP_PATH="/root/tunnel.sh.bak"
PUBLIC_HTML="/var/www/html"
USERNAME="YouzinCrabz"
BOT_TOKEN_FILE="/root/.bot_token"
CHAT_ID_FILE="/root/.chat_id"
ORDER_DIR="/root/orders"
PAYMENT_FILE="/root/.payment_info"
DOMAIN_TYPE_FILE="/root/.domain_type"

#================================================
# PORT VARIABLES - SUDAH DIPERBAIKI TIDAK BENTROK
#================================================
SSH_PORT="22"
DROPBEAR_PORT="222"
NGINX_PORT="80"
NGINX_DL_PORT="81"
HAPROXY_PORT="443"
# TLS ports (via HAProxy 443)
XRAY_VMESS_TLS="8443"
XRAY_VLESS_TLS="8444"
XRAY_TROJAN_TLS="8445"
# NonTLS ports (via Nginx 80)
XRAY_VMESS_NOTLS="8080"
XRAY_VLESS_NOTLS="8081"
XRAY_TROJAN_NOTLS="8082"
# gRPC ports (via HAProxy 443)
XRAY_VMESS_GRPC="8446"
XRAY_VLESS_GRPC="8447"
XRAY_TROJAN_GRPC="8448"

BADVPN_RANGE="7100-7300"
PRICE_MONTHLY="10000"
DURATION_MONTHLY="30"

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

pause() { echo ""; read -p "  Press any key to back..."; }

#================================================
# ANIMASI INSTALL
#================================================

spinner_frames=('⣾' '⣽' '⣻' '⢿' '⡿' '⣟' '⣯' '⣷')
bar_frames=('▱▱▱▱▱▱▱▱▱▱' '▰▱▱▱▱▱▱▱▱▱' '▰▰▱▱▱▱▱▱▱▱' '▰▰▰▱▱▱▱▱▱▱' '▰▰▰▰▱▱▱▱▱▱' '▰▰▰▰▰▱▱▱▱▱' '▰▰▰▰▰▰▱▱▱▱' '▰▰▰▰▰▰▰▱▱▱' '▰▰▰▰▰▰▰▰▱▱' '▰▰▰▰▰▰▰▰▰▱' '▰▰▰▰▰▰▰▰▰▰')

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

fancy_progress() {
    local current="$1"
    local total="$2"
    local label="$3"
    local pct=$(( current * 100 / total ))
    local filled=$(( current * 10 / total ))
    local bar="${bar_frames[$filled]}"
    printf "\r  ${CYAN}[${NC}${GREEN}%s${NC}${CYAN}]${NC} ${WHITE}%3d%%${NC}  ${DIM}%s${NC}   " \
        "$bar" "$pct" "$label"
}

show_progress() {
    fancy_progress "$1" "$2" "$3"
    echo ""
}

done_msg() { printf "  ${GREEN}✔${NC} ${WHITE}%-42s${NC}\n" "$1"; }
fail_msg() { printf "  ${RED}✘${NC} ${WHITE}%-42s${NC}\n" "$1"; }
info_msg() { printf "  ${CYAN}◈${NC} %s\n" "$1"; }

#================================================
# BANNER INSTALL
#================================================

show_install_banner() {
    clear
    echo ""
    echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${YELLOW}  ✦ ✦ ✦  Script Auto Install by Youzin Crabz  ✦ ✦ ✦${NC}"
    echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "  ${WHITE}  Youzin Crabz Tunel${NC}"
    echo -e "      ${DIM}  The Professor${NC}"
    echo ""
    echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

#================================================
# UTILITY FUNCTIONS
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

#================================================
# MENU HEADER
#================================================

print_menu_header() {
    local title="$1"
    local W; W=$(get_width)
    echo ""
    _box_top $W
    _box_center $W "${YELLOW}${BOLD}${title}${NC}"
    _box_bottom $W
    echo ""
}

print_section() {
    local W; W=$(get_width)
    local inner=$(( W - 4 ))
    printf "  ${CYAN}┌"; printf '─%.0s' $(seq 1 $inner); printf "┐${NC}\n"
    printf "  ${CYAN}│${NC}  ${YELLOW}▸${NC} ${WHITE}%-$((inner-3))s${NC}${CYAN}│${NC}\n" "$1"
    printf "  ${CYAN}└"; printf '─%.0s' $(seq 1 $inner); printf "┘${NC}\n"
}

#================================================
# SHOW SYSTEM INFO - DASHBOARD
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

    _box_top $W
    _box_center $W "${YELLOW}${BOLD}✦ YOUZINCRABZ PANEL ✦${NC}"
    _box_center $W "${CYAN}The Professor${NC}"
    _box_bottom $W
    echo ""

    _box_top $W
    _box_center $W "${YELLOW}${BOLD}🖥️  SERVER CORE STATUS${NC}"
    _box_divider $W
    _box_left $W "IP Address  : ${GREEN}${ip_vps}${NC}"
    _box_left $W "Domain      : ${GREEN}${DOMAIN:-N/A}${NC}"
    _box_left $W "OS          : ${WHITE}${os_name}${NC}"
    _box_left $W "Uptime      : ${WHITE}${uptime_str}${NC}"
    _box_left $W "CPU Load    : ${YELLOW}${cpu}%${NC}"
    _box_left $W "RAM Usage   : ${WHITE}${ram_used} / ${ram_total} MB${NC} ${CYAN}[${BAR}]${NC} ${YELLOW}${ram_pct}%${NC}"
    _box_left $W "SSL Status  : ${GREEN}${ssl_type}${NC}"
    _box_left $W "Services    : ${GREEN}${svc_running}/${svc_total} Running${NC}"
    _box_bottom $W
    echo ""

    _box_top $W
    _box_center $W "${YELLOW}${BOLD}👥  ACTIVE ACCOUNTS${NC}"
    _box_divider $W
    _box_center $W "SSH: ${GREEN}${ssh_count}${NC}  │  VMess: ${GREEN}${vmess_count}${NC}  │  VLess: ${GREEN}${vless_count}${NC}  │  Trojan: ${GREEN}${trojan_count}${NC}"
    _box_bottom $W
    echo ""

    _box_top $W
    _box_center $W "${YELLOW}${BOLD}🔌  NETWORK SERVICES${NC}"
    _box_divider $W
    local XRAY_S NGINX_S HAPROXY_S DROPBEAR_S SSH_S UDP_S TELEGRAM_S KEEPALIVE_S
    XRAY_S=$(_svc_status xray)
    NGINX_S=$(_svc_status nginx)
    HAPROXY_S=$(_svc_status haproxy)
    DROPBEAR_S=$(_svc_status dropbear)
    SSH_S=$(_svc_status ssh)
    UDP_S=$(_svc_status udp-custom)
    TELEGRAM_S=$(_svc_status vpn-bot)
    KEEPALIVE_S=$(_svc_status vpn-keepalive)
    _box_two $W "XRAY      ${XRAY_S}" "NGINX      ${NGINX_S}"
    _box_two $W "HAPROXY   ${HAPROXY_S}" "DROPBEAR   ${DROPBEAR_S}"
    _box_two $W "SSH       ${SSH_S}" "UDP CUST   ${UDP_S}"
    _box_two $W "TELEGRAM  ${TELEGRAM_S}" "KEEPALIVE  ${KEEPALIVE_S}"
    _box_bottom $W
    echo ""
}

#================================================
# SHOW MAIN MENU
#================================================

show_menu() {
    local W; W=$(get_width)

    _box_top $W
    _box_center $W "${YELLOW}${BOLD}💎  ACCOUNT MANAGEMENT  💎${NC}"
    _box_divider $W
    _box_two $W "[1] SSH / OpenVPN" "[5] Trial Account"
    _box_two $W "[2] VMess Account" "[6] List All Accounts"
    _box_two $W "[3] VLess Account" "[7] Check Expired"
    _box_two $W "[4] Trojan Account" "[8] Delete Expired"
    _box_bottom $W
    echo ""

    _box_top $W
    _box_center $W "${YELLOW}${BOLD}⚙️  SYSTEM CONTROL${NC}"
    _box_divider $W
    _box_two $W "[9]  Telegram Bot" "[15] Speedtest VPS"
    _box_two $W "[10] Change Domain" "[16] Update Panel"
    _box_two $W "[11] Fix SSL / Cert" "[17] Backup Config"
    _box_two $W "[12] Optimize VPS" "[18] Restore Config"
    _box_two $W "[13] Restart Services" "[19] Uninstall Panel"
    _box_two $W "[14] Port Info" "[20] Advanced Mode"
    _box_divider $W
    _box_left $W "${RED}${BOLD}[0] Exit Panel${NC}"
    _box_divider $W
    _box_left $W "📞 Telegram : ${CYAN}@ridhani16${NC}"
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
    local preview; preview=$(generate_random_domain)
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
        certbot certonly --standalone \
            -d "$DOMAIN" \
            --non-interactive \
            --agree-tos \
            --register-unsafely-without-email \
            >/dev/null 2>&1
        if [[ -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]]; then
            cp "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" /etc/xray/xray.crt
            cp "/etc/letsencrypt/live/$DOMAIN/privkey.pem" /etc/xray/xray.key
        else
            _gen_self_signed
        fi
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
    clear
    print_menu_header "SETUP SWAP 1GB"
    local swap_total
    swap_total=$(free -m | awk 'NR==3{print $2}')
    if [[ "$swap_total" -gt 0 ]]; then
        echo -e "  ${YELLOW}Swap ada: ${swap_total}MB${NC}"
        swapoff -a 2>/dev/null
        sed -i '/swapfile/d' /etc/fstab
        rm -f /swapfile
    fi
    echo -e "  ${CYAN}Creating 1GB swap...${NC}"
    fallocate -l 1G /swapfile 2>/dev/null || \
        dd if=/dev/zero of=/swapfile bs=1M count=1024 2>/dev/null
    chmod 600 /swapfile
    mkswap /swapfile >/dev/null 2>&1
    swapon /swapfile
    grep -q "/swapfile" /etc/fstab || \
        echo "/swapfile none swap sw 0 0" >> /etc/fstab
    echo -e "  ${GREEN}✔ Swap 1GB OK!${NC}"
    sleep 2
}

#================================================
# OPTIMIZE VPN
#================================================

optimize_vpn() {
    cat > /etc/sysctl.d/99-vpn.conf << 'SYSEOF'
net.ipv4.tcp_keepalive_time = 30
net.ipv4.tcp_keepalive_intvl = 5
net.ipv4.tcp_keepalive_probes = 6
net.ipv4.tcp_fin_timeout = 10
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.core.netdev_max_backlog = 250000
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_forward = 1
vm.swappiness = 10
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
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
        sed -i 's/^ClientAliveInterval.*/ClientAliveInterval 30/' "$sshcfg" || \
        echo "ClientAliveInterval 30" >> "$sshcfg"
    grep -q "^ClientAliveCountMax" "$sshcfg" && \
        sed -i 's/^ClientAliveCountMax.*/ClientAliveCountMax 6/' "$sshcfg" || \
        echo "ClientAliveCountMax 6" >> "$sshcfg"
    grep -q "^TCPKeepAlive" "$sshcfg" && \
        sed -i 's/^TCPKeepAlive.*/TCPKeepAlive yes/' "$sshcfg" || \
        echo "TCPKeepAlive yes" >> "$sshcfg"
    systemctl restart sshd 2>/dev/null

    mkdir -p /etc/systemd/system/xray.service.d
    cat > /etc/systemd/system/xray.service.d/override.conf << 'XEOF'
[Service]
Restart=always
RestartSec=3
LimitNOFILE=65535
XEOF

    cat > /usr/local/bin/vpn-keepalive.sh << 'KAEOF'
#!/bin/bash
while true; do
    GW=$(ip route | awk '/default/{print $3; exit}')
    [[ -n "$GW" ]] && ping -c1 -W2 "$GW" >/dev/null 2>&1
    ping -c1 -W2 8.8.8.8 >/dev/null 2>&1
    sleep 25
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
# HAPROXY CONFIG - DIPERBAIKI
#================================================

configure_haproxy() {
    cat > /etc/haproxy/haproxy.cfg << 'HAEOF'
global
    log /dev/log local0
    log /dev/log local1 notice
    maxconn 65535
    tune.ssl.default-dh-param 2048

defaults
    log global
    mode tcp
    option tcplog
    option dontlognull
    option tcp-smart-accept
    option tcp-smart-connect
    timeout connect 5s
    timeout client  1h
    timeout server  1h
    timeout tunnel  1h
    maxconn 65535

frontend front_443
    bind *:443
    mode tcp
    default_backend back_xray_all_tls

backend back_xray_all_tls
    mode tcp
    server xray_tls 127.0.0.1:8443 check inter 3s rise 2 fall 3
HAEOF
}

#================================================
# FIX XRAY PERMISSIONS
#================================================

fix_xray_permissions() {
    mkdir -p /usr/local/etc/xray /var/log/xray
    chmod 755 /usr/local/etc/xray
    chmod 755 /var/log/xray
    touch /var/log/xray/access.log /var/log/xray/error.log
    chmod 644 /var/log/xray/access.log /var/log/xray/error.log
    chmod 644 /usr/local/etc/xray/config.json 2>/dev/null
    chown -R nobody:nogroup /var/log/xray 2>/dev/null
}

#================================================
# CREATE XRAY CONFIG - DIPERBAIKI (TIDAK BENTROK)
# Setiap protokol punya port sendiri
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
      "port": 8443,
      "listen": "127.0.0.1",
      "protocol": "vmess",
      "settings": {"clients": []},
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "certificates": [{"certificateFile": "/etc/xray/xray.crt","keyFile": "/etc/xray/xray.key"}]
        },
        "wsSettings": {"path": "/vmess"}
      },
      "sniffing": {"enabled": true,"destOverride": ["http","tls"]},
      "tag": "vmess-tls"
    },
    {
      "port": 8444,
      "listen": "127.0.0.1",
      "protocol": "vless",
      "settings": {"clients": [],"decryption": "none"},
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "certificates": [{"certificateFile": "/etc/xray/xray.crt","keyFile": "/etc/xray/xray.key"}]
        },
        "wsSettings": {"path": "/vless"}
      },
      "sniffing": {"enabled": true,"destOverride": ["http","tls"]},
      "tag": "vless-tls"
    },
    {
      "port": 8445,
      "listen": "127.0.0.1",
      "protocol": "trojan",
      "settings": {"clients": []},
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "certificates": [{"certificateFile": "/etc/xray/xray.crt","keyFile": "/etc/xray/xray.key"}]
        },
        "wsSettings": {"path": "/trojan"}
      },
      "sniffing": {"enabled": true,"destOverride": ["http","tls"]},
      "tag": "trojan-tls"
    },
    {
      "port": 8080,
      "listen": "127.0.0.1",
      "protocol": "vmess",
      "settings": {"clients": []},
      "streamSettings": {
        "network": "ws",
        "wsSettings": {"path": "/vmess"}
      },
      "sniffing": {"enabled": true,"destOverride": ["http","tls"]},
      "tag": "vmess-notls"
    },
    {
      "port": 8081,
      "listen": "127.0.0.1",
      "protocol": "vless",
      "settings": {"clients": [],"decryption": "none"},
      "streamSettings": {
        "network": "ws",
        "wsSettings": {"path": "/vless"}
      },
      "sniffing": {"enabled": true,"destOverride": ["http","tls"]},
      "tag": "vless-notls"
    },
    {
      "port": 8082,
      "listen": "127.0.0.1",
      "protocol": "trojan",
      "settings": {"clients": []},
      "streamSettings": {
        "network": "ws",
        "wsSettings": {"path": "/trojan"}
      },
      "sniffing": {"enabled": true,"destOverride": ["http","tls"]},
      "tag": "trojan-notls"
    },
    {
      "port": 8446,
      "listen": "127.0.0.1",
      "protocol": "vmess",
      "settings": {"clients": []},
      "streamSettings": {
        "network": "grpc",
        "security": "tls",
        "tlsSettings": {
          "certificates": [{"certificateFile": "/etc/xray/xray.crt","keyFile": "/etc/xray/xray.key"}]
        },
        "grpcSettings": {"serviceName": "vmess-grpc"}
      },
      "tag": "vmess-grpc"
    },
    {
      "port": 8447,
      "listen": "127.0.0.1",
      "protocol": "vless",
      "settings": {"clients": [],"decryption": "none"},
      "streamSettings": {
        "network": "grpc",
        "security": "tls",
        "tlsSettings": {
          "certificates": [{"certificateFile": "/etc/xray/xray.crt","keyFile": "/etc/xray/xray.key"}]
        },
        "grpcSettings": {"serviceName": "vless-grpc"}
      },
      "tag": "vless-grpc"
    },
    {
      "port": 8448,
      "listen": "127.0.0.1",
      "protocol": "trojan",
      "settings": {"clients": []},
      "streamSettings": {
        "network": "grpc",
        "security": "tls",
        "tlsSettings": {
          "certificates": [{"certificateFile": "/etc/xray/xray.crt","keyFile": "/etc/xray/xray.key"}]
        },
        "grpcSettings": {"serviceName": "trojan-grpc"}
      },
      "tag": "trojan-grpc"
    }
  ],
  "outbounds": [
    {"protocol": "freedom","settings": {"domainStrategy": "UseIPv4"},"tag": "direct"},
    {"protocol": "blackhole","settings": {},"tag": "block"}
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [{"type": "field","ip": ["geoip:private"],"outboundTag": "block"}]
  }
}
XRAYEOF
    fix_xray_permissions
}

#================================================
# INFO PORT - DIPERBAIKI SESUAI PORT BARU
#================================================

show_info_port() {
    clear
    print_menu_header "SERVER PORT INFORMATION"
    local W; W=$(get_width)
    local inner=$(( W - 4 ))
    printf "  ${CYAN}┌"; printf '─%.0s' $(seq 1 $inner); printf "┐${NC}\n"
    printf "  ${CYAN}│${NC}  ${YELLOW}%-28s${NC} : ${GREEN}%-$((inner-34))s${NC}  ${CYAN}│${NC}\n" "SSH OpenSSH"         "22"
    printf "  ${CYAN}│${NC}  ${YELLOW}%-28s${NC} : ${GREEN}%-$((inner-34))s${NC}  ${CYAN}│${NC}\n" "Dropbear"            "222"
    printf "  ${CYAN}│${NC}  ${YELLOW}%-28s${NC} : ${GREEN}%-$((inner-34))s${NC}  ${CYAN}│${NC}\n" "Nginx NonTLS"        "80"
    printf "  ${CYAN}│${NC}  ${YELLOW}%-28s${NC} : ${GREEN}%-$((inner-34))s${NC}  ${CYAN}│${NC}\n" "Nginx Download"      "81"
    printf "  ${CYAN}│${NC}  ${YELLOW}%-28s${NC} : ${GREEN}%-$((inner-34))s${NC}  ${CYAN}│${NC}\n" "HAProxy TLS"         "443"
    printf "  ${CYAN}│${NC}  ${WHITE}%-28s${NC} : ${GREEN}%-$((inner-34))s${NC}  ${CYAN}│${NC}\n" "VMess TLS (WS)"      "443 → Xray:8443"
    printf "  ${CYAN}│${NC}  ${WHITE}%-28s${NC} : ${GREEN}%-$((inner-34))s${NC}  ${CYAN}│${NC}\n" "VLess TLS (WS)"      "443 → Xray:8444"
    printf "  ${CYAN}│${NC}  ${WHITE}%-28s${NC} : ${GREEN}%-$((inner-34))s${NC}  ${CYAN}│${NC}\n" "Trojan TLS (WS)"     "443 → Xray:8445"
    printf "  ${CYAN}│${NC}  ${WHITE}%-28s${NC} : ${GREEN}%-$((inner-34))s${NC}  ${CYAN}│${NC}\n" "VMess NonTLS (WS)"   "80 → Xray:8080"
    printf "  ${CYAN}│${NC}  ${WHITE}%-28s${NC} : ${GREEN}%-$((inner-34))s${NC}  ${CYAN}│${NC}\n" "VLess NonTLS (WS)"   "80 → Xray:8081"
    printf "  ${CYAN}│${NC}  ${WHITE}%-28s${NC} : ${GREEN}%-$((inner-34))s${NC}  ${CYAN}│${NC}\n" "Trojan NonTLS (WS)"  "80 → Xray:8082"
    printf "  ${CYAN}│${NC}  ${WHITE}%-28s${NC} : ${GREEN}%-$((inner-34))s${NC}  ${CYAN}│${NC}\n" "VMess gRPC TLS"      "443 → Xray:8446"
    printf "  ${CYAN}│${NC}  ${WHITE}%-28s${NC} : ${GREEN}%-$((inner-34))s${NC}  ${CYAN}│${NC}\n" "VLess gRPC TLS"      "443 → Xray:8447"
    printf "  ${CYAN}│${NC}  ${WHITE}%-28s${NC} : ${GREEN}%-$((inner-34))s${NC}  ${CYAN}│${NC}\n" "Trojan gRPC TLS"     "443 → Xray:8448"
    printf "  ${CYAN}│${NC}  ${YELLOW}%-28s${NC} : ${GREEN}%-$((inner-34))s${NC}  ${CYAN}│${NC}\n" "BadVPN UDP"          "7100-7300"
    printf "  ${CYAN}└"; printf '─%.0s' $(seq 1 $inner); printf "┘${NC}\n"
    echo ""
    pause
}

#================================================
# CREATE ACCOUNT TEMPLATE - XRAY
# DIPERBAIKI: tag sesuai port baru
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
        systemctl restart xray 2>/dev/null
        sleep 1
    else
        rm -f "$temp"
        echo -e "  ${RED}✘ Failed update Xray!${NC}"
        sleep 2; return 1
    fi

    mkdir -p "$AKUN_DIR"
    printf "UUID=%s\nQUOTA=%s\nIPLIMIT=%s\nEXPIRED=%s\nCREATED=%s\n" \
        "$uuid" "$quota" "$iplimit" "$exp" "$created" \
        > "$AKUN_DIR/${protocol}-${username}.txt"

    local link_tls link_notls link_grpc

    if [[ "$protocol" == "vmess" ]]; then
        local j_tls j_notls j_grpc
        j_tls=$(printf '{"v":"2","ps":"%s","add":"bug.com","port":"443","id":"%s","aid":"0","net":"ws","path":"/vmess","type":"none","host":"%s","tls":"tls"}' "$username" "$uuid" "$DOMAIN")
        link_tls="vmess://$(printf '%s' "$j_tls" | base64 -w 0)"
        j_notls=$(printf '{"v":"2","ps":"%s","add":"bug.com","port":"80","id":"%s","aid":"0","net":"ws","path":"/vmess","type":"none","host":"%s","tls":"none"}' "$username" "$uuid" "$DOMAIN")
        link_notls="vmess://$(printf '%s' "$j_notls" | base64 -w 0)"
        j_grpc=$(printf '{"v":"2","ps":"%s","add":"%s","port":"443","id":"%s","aid":"0","net":"grpc","path":"vmess-grpc","type":"none","host":"bug.com","tls":"tls"}' "$username" "$DOMAIN" "$uuid")
        link_grpc="vmess://$(printf '%s' "$j_grpc" | base64 -w 0)"
    elif [[ "$protocol" == "vless" ]]; then
        link_tls="vless://${uuid}@bug.com:443?path=%2Fvless&security=tls&encryption=none&host=${DOMAIN}&type=ws&sni=${DOMAIN}#${username}-TLS"
        link_notls="vless://${uuid}@bug.com:80?path=%2Fvless&security=none&encryption=none&host=${DOMAIN}&type=ws#${username}-NonTLS"
        link_grpc="vless://${uuid}@${DOMAIN}:443?mode=gun&security=tls&encryption=none&type=grpc&serviceName=vless-grpc&sni=bug.com#${username}-gRPC"
    elif [[ "$protocol" == "trojan" ]]; then
        link_tls="trojan://${uuid}@bug.com:443?path=%2Ftrojan&security=tls&host=${DOMAIN}&type=ws&sni=${DOMAIN}#${username}-TLS"
        link_notls="trojan://${uuid}@bug.com:80?path=%2Ftrojan&security=none&host=${DOMAIN}&type=ws#${username}-NonTLS"
        link_grpc="trojan://${uuid}@${DOMAIN}:443?mode=gun&security=tls&type=grpc&serviceName=trojan-grpc&sni=bug.com#${username}-gRPC"
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
 Port TLS         : 443 (HAProxy → Xray)
 Port NonTLS      : 80 (Nginx → Xray)
 Port gRPC        : 443 (HAProxy → Xray)
 Network          : WebSocket / gRPC
 Path WS          : /${protocol}
 ServiceName gRPC : ${protocol}-grpc
 TLS              : enabled
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Link TLS         :
 ${link_tls}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Link NonTLS      :
 ${link_notls}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Link gRPC        :
 ${link_grpc}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Download         : http://${ip_vps}:81/${protocol}-${username}.txt
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Aktif Selama     : ${days} Hari
 Dibuat Pada      : ${created}
 Berakhir Pada    : ${exp}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
DLEOF

    _print_xray_result "$protocol" "$username" "$ip_vps" "$uuid" "$quota" "$iplimit" \
        "$link_tls" "$link_notls" "$link_grpc" "$days" "$created" "$exp"

    local dl_link="http://${ip_vps}:81/${protocol}-${username}.txt"
    send_telegram_admin \
"✅ <b>New ${protocol^^} Account - Youzin Crabz Tunel</b>
━━━━━━━━━━━━━━━━━━━━━━━━━
👤 Username   : <code>${username}</code>
🔑 UUID       : <code>${uuid}</code>
🌐 Domain     : <code>${DOMAIN}</code>
🖥️ IP VPS     : <code>${ip_vps}</code>
📦 Protocol   : ${protocol^^}
📊 Quota      : ${quota} GB
🔒 IP Limit   : ${iplimit} IP
━━━━━━━━━━━━━━━━━━━━━━━━━
🔌 Port TLS   : 443
🔌 Port NonTLS: 80
🔌 Port gRPC  : 443
━━━━━━━━━━━━━━━━━━━━━━━━━
📅 Dibuat     : ${created}
⏳ Berakhir   : ${exp}
🔗 Download   : ${dl_link}
━━━━━━━━━━━━━━━━━━━━━━━━━
<i>Powered by The Professor</i>"

    pause
}

#================================================
# PRINT XRAY RESULT
#================================================

_print_xray_result() {
    local protocol="$1" username="$2" ip_vps="$3" uuid="$4"
    local quota="$5" iplimit="$6" link_tls="$7" link_notls="$8"
    local link_grpc="$9" days="${10}" created="${11}" exp="${12}"

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
    printf "  ${WHITE}%-16s${NC} : %s\n" "Port TLS"    "443 (HAProxy)"
    printf "  ${WHITE}%-16s${NC} : %s\n" "Port NonTLS" "80 (Nginx)"
    printf "  ${WHITE}%-16s${NC} : %s\n" "Port gRPC"   "443 (HAProxy)"
    printf "  ${WHITE}%-16s${NC} : %s\n" "Network"     "WebSocket / gRPC"
    printf "  ${WHITE}%-16s${NC} : %s\n" "Path WS"     "/${protocol}"
    printf "  ${WHITE}%-16s${NC} : %s\n" "ServiceName" "${protocol}-grpc"
    printf "  ${WHITE}%-16s${NC} : %s\n" "TLS"         "enabled"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    printf "  ${YELLOW}%-16s${NC} :\n" "Link TLS"
    echo "  $link_tls"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    printf "  ${YELLOW}%-16s${NC} :\n" "Link NonTLS"
    echo "  $link_notls"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    printf "  ${YELLOW}%-16s${NC} :\n" "Link gRPC"
    echo "  $link_grpc"
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
        systemctl restart xray 2>/dev/null
        sleep 1
    else
        rm -f "$temp"
        echo -e "  ${RED}✘ Failed!${NC}"
        sleep 2; return
    fi

    mkdir -p "$AKUN_DIR"
    printf "UUID=%s\nQUOTA=1\nIPLIMIT=1\nEXPIRED=%s\nCREATED=%s\nTRIAL=1\n" \
        "$uuid" "$exp" "$created" \
        > "$AKUN_DIR/${protocol}-${username}.txt"

    (
        sleep 3600
        local tmp2; tmp2=$(mktemp)
        jq --arg email "$username" \
           'del(.inbounds[].settings.clients[]? | select(.email == $email))' \
           "$XRAY_CONFIG" > "$tmp2" 2>/dev/null && \
           mv "$tmp2" "$XRAY_CONFIG" || rm -f "$tmp2"
        chmod 644 "$XRAY_CONFIG" 2>/dev/null
        fix_xray_permissions
        systemctl restart xray 2>/dev/null
        rm -f "$AKUN_DIR/${protocol}-${username}.txt"
        rm -f "$PUBLIC_HTML/${protocol}-${username}.txt"
    ) &
    disown $!

    local link_tls link_notls link_grpc

    if [[ "$protocol" == "vmess" ]]; then
        local j_tls j_notls j_grpc
        j_tls=$(printf '{"v":"2","ps":"%s","add":"bug.com","port":"443","id":"%s","aid":"0","net":"ws","path":"/vmess","type":"none","host":"%s","tls":"tls"}' "$username" "$uuid" "$DOMAIN")
        link_tls="vmess://$(printf '%s' "$j_tls" | base64 -w 0)"
        j_notls=$(printf '{"v":"2","ps":"%s","add":"bug.com","port":"80","id":"%s","aid":"0","net":"ws","path":"/vmess","type":"none","host":"%s","tls":"none"}' "$username" "$uuid" "$DOMAIN")
        link_notls="vmess://$(printf '%s' "$j_notls" | base64 -w 0)"
        j_grpc=$(printf '{"v":"2","ps":"%s","add":"%s","port":"443","id":"%s","aid":"0","net":"grpc","path":"vmess-grpc","type":"none","host":"bug.com","tls":"tls"}' "$username" "$DOMAIN" "$uuid")
        link_grpc="vmess://$(printf '%s' "$j_grpc" | base64 -w 0)"
    elif [[ "$protocol" == "vless" ]]; then
        link_tls="vless://${uuid}@bug.com:443?path=%2Fvless&security=tls&encryption=none&host=${DOMAIN}&type=ws&sni=${DOMAIN}#${username}-TLS"
        link_notls="vless://${uuid}@bug.com:80?path=%2Fvless&security=none&encryption=none&host=${DOMAIN}&type=ws#${username}-NonTLS"
        link_grpc="vless://${uuid}@${DOMAIN}:443?mode=gun&security=tls&encryption=none&type=grpc&serviceName=vless-grpc&sni=bug.com#${username}-gRPC"
    elif [[ "$protocol" == "trojan" ]]; then
        link_tls="trojan://${uuid}@bug.com:443?path=%2Ftrojan&security=tls&host=${DOMAIN}&type=ws&sni=${DOMAIN}#${username}-TLS"
        link_notls="trojan://${uuid}@bug.com:80?path=%2Ftrojan&security=none&host=${DOMAIN}&type=ws#${username}-NonTLS"
        link_grpc="trojan://${uuid}@${DOMAIN}:443?mode=gun&security=tls&type=grpc&serviceName=trojan-grpc&sni=bug.com#${username}-gRPC"
    fi

    clear
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${WHITE}${BOLD}YOUZIN CRABZ TUNEL${NC} — ${YELLOW}Trial ${protocol^^} (1 Jam)${NC}"
    echo -e "  ${DIM}The Professor${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    printf "  ${WHITE}%-16s${NC} : ${GREEN}%s${NC}\n" "Username"    "$username"
    printf "  ${WHITE}%-16s${NC} : ${GREEN}%s${NC}\n" "IP VPS"      "$ip_vps"
    printf "  ${WHITE}%-16s${NC} : ${GREEN}%s${NC}\n" "Domain"      "$DOMAIN"
    printf "  ${WHITE}%-16s${NC} : ${CYAN}%s${NC}\n"  "UUID"        "$uuid"
    printf "  ${WHITE}%-16s${NC} : 1 GB\n"             "Quota"
    printf "  ${WHITE}%-16s${NC} : 1 IP\n"             "IP Limit"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    printf "  ${WHITE}%-16s${NC} : %s\n" "Port TLS"    "443 (HAProxy)"
    printf "  ${WHITE}%-16s${NC} : %s\n" "Port NonTLS" "80 (Nginx)"
    printf "  ${WHITE}%-16s${NC} : %s\n" "Port gRPC"   "443 (HAProxy)"
    printf "  ${WHITE}%-16s${NC} : %s\n" "Path WS"     "/${protocol}"
    printf "  ${WHITE}%-16s${NC} : %s\n" "ServiceName" "${protocol}-grpc"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    printf "  ${YELLOW}Link TLS${NC} :\n  %s\n" "$link_tls"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    printf "  ${YELLOW}Link NonTLS${NC} :\n  %s\n" "$link_notls"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    printf "  ${YELLOW}Link gRPC${NC} :\n  %s\n" "$link_grpc"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    printf "  ${WHITE}%-16s${NC} : ${YELLOW}1 Jam (Auto Delete)${NC}\n" "Aktif Selama"
    printf "  ${WHITE}%-16s${NC} : %s\n"  "Dibuat"   "$created"
    printf "  ${WHITE}%-16s${NC} : ${RED}%s${NC}\n" "Berakhir" "$exp"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    pause
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

    pause
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

    send_telegram_admin \
"🆓 <b>SSH Trial - Youzin Crabz Tunel</b>
━━━━━━━━━━━━━━━━━━━━━━━━━
👤 Username : <code>${username}</code>
🔑 Password : <code>${password}</code>
🌐 Domain   : <code>${DOMAIN}</code>
🖥️ IP VPS   : <code>${ip_vps}</code>
━━━━━━━━━━━━━━━━━━━━━━━━━
⏰ Aktif    : 1 Jam (Auto Delete)
📅 Expired  : ${exp}
━━━━━━━━━━━━━━━━━━━━━━━━━
<i>Powered by The Professor</i>"

    pause
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
    echo -e "  ${DIM}The Professor${NC}"
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
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    printf "  ${WHITE}%-16s${NC} : GET / HTTP/1.1[crlf]Host: %s[crlf]Upgrade: ws[crlf][crlf]\n" "Payload" "$DOMAIN"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    printf "  ${WHITE}%-16s${NC} : ${YELLOW}%s${NC}\n"    "Aktif Selama"  "$days"
    printf "  ${WHITE}%-16s${NC} : %s\n"                   "Dibuat Pada"   "$created"
    printf "  ${WHITE}%-16s${NC} : ${RED}%s${NC}\n"        "Berakhir Pada" "$exp"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

#================================================
# DELETE / RENEW / LIST / CHECK LOGIN
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
    chmod 644 "$XRAY_CONFIG" 2>/dev/null
    fix_xray_permissions
    systemctl restart xray 2>/dev/null
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
    pause
}

check_user_login() {
    local protocol="$1"
    clear
    print_menu_header "ACTIVE ${protocol^^} LOGINS"
    if [[ "$protocol" == "ssh" ]]; then
        echo -e "  ${WHITE}Active SSH sessions:${NC}"
        who 2>/dev/null || echo "  None"
        echo ""
        echo -e "  ${WHITE}Login count:${NC}"
        who 2>/dev/null | awk '{print $1}' | sort | uniq -c | sort -rn
    else
        echo -e "  ${WHITE}Xray ${protocol^^} active connections:${NC}"
        ss -tn 2>/dev/null | grep -E ":8443|:8444|:8445|:8080|:8081|:8082|:8446|:8447|:8448" | \
            awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -20
        echo ""
        if [[ -f /var/log/xray/access.log ]]; then
            echo -e "  ${WHITE}Recent from access log:${NC}"
            grep -i "$protocol" /var/log/xray/access.log 2>/dev/null | tail -10 || echo "  No data"
        fi
    fi
    echo ""
    pause
}

#================================================
# CEK EXPIRED
#================================================

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
                echo -e "  ${RED}✘ EXPIRED${NC}: $uname"
                echo -e "    ${YELLOW}($exp_str)${NC}"
            else
                echo -e "  ${YELLOW}⚠ ${diff} hari${NC}: $uname"
                echo -e "    ${CYAN}($exp_str)${NC}"
            fi
        fi
    done
    shopt -u nullglob
    [[ $found -eq 0 ]] && echo -e "  ${GREEN}✔ Tidak ada akun expired!${NC}"
    echo ""
    pause
}

#================================================
# DELETE EXPIRED
#================================================

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
            chmod 644 "$XRAY_CONFIG" 2>/dev/null
            [[ "$protocol" == "ssh" ]] && userdel -f "$uname" 2>/dev/null
            rm -f "$f"
            rm -f "$PUBLIC_HTML/${fname}.txt"
            ((count++))
        fi
    done
    shopt -u nullglob
    if [[ $count -gt 0 ]]; then
        fix_xray_permissions
        systemctl restart xray 2>/dev/null
        echo ""
        echo -e "  ${GREEN}✔ Deleted ${count} accounts!${NC}"
    else
        echo -e "  ${GREEN}✔ Tidak ada akun expired!${NC}"
    fi
    echo ""
    pause
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
        echo -e "  ${WHITE}[1]${NC} Create SSH"
        echo -e "  ${WHITE}[2]${NC} Trial SSH (1 Jam)"
        echo -e "  ${WHITE}[3]${NC} Delete SSH"
        echo -e "  ${WHITE}[4]${NC} Renew SSH"
        echo -e "  ${WHITE}[5]${NC} Cek Login SSH"
        echo -e "  ${WHITE}[6]${NC} List User SSH"
        echo -e "  ${WHITE}[0]${NC} Back To Menu"
        echo ""
        read -p "  Select: " choice
        case $choice in
            1) create_ssh ;; 2) create_ssh_trial ;;
            3) delete_account "ssh" ;; 4) renew_account "ssh" ;;
            5) check_user_login "ssh" ;; 6) list_accounts "ssh" ;;
            0) return ;;
        esac
    done
}

menu_vmess() {
    while true; do
        clear; print_menu_header "VMESS MENU"
        echo -e "  ${WHITE}[1]${NC} Create VMess"
        echo -e "  ${WHITE}[2]${NC} Trial VMess (1 Jam)"
        echo -e "  ${WHITE}[3]${NC} Delete VMess"
        echo -e "  ${WHITE}[4]${NC} Renew VMess"
        echo -e "  ${WHITE}[5]${NC} Cek Login VMess"
        echo -e "  ${WHITE}[6]${NC} List User VMess"
        echo -e "  ${WHITE}[0]${NC} Back To Menu"
        echo ""
        read -p "  Select: " choice
        case $choice in
            1) create_vmess ;; 2) create_trial_xray "vmess" ;;
            3) delete_account "vmess" ;; 4) renew_account "vmess" ;;
            5) check_user_login "vmess" ;; 6) list_accounts "vmess" ;;
            0) return ;;
        esac
    done
}

menu_vless() {
    while true; do
        clear; print_menu_header "VLESS MENU"
        echo -e "  ${WHITE}[1]${NC} Create VLess"
        echo -e "  ${WHITE}[2]${NC} Trial VLess (1 Jam)"
        echo -e "  ${WHITE}[3]${NC} Delete VLess"
        echo -e "  ${WHITE}[4]${NC} Renew VLess"
        echo -e "  ${WHITE}[5]${NC} Cek Login VLess"
        echo -e "  ${WHITE}[6]${NC} List User VLess"
        echo -e "  ${WHITE}[0]${NC} Back To Menu"
        echo ""
        read -p "  Select: " choice
        case $choice in
            1) create_vless ;; 2) create_trial_xray "vless" ;;
            3) delete_account "vless" ;; 4) renew_account "vless" ;;
            5) check_user_login "vless" ;; 6) list_accounts "vless" ;;
            0) return ;;
        esac
    done
}

menu_trojan() {
    while true; do
        clear; print_menu_header "TROJAN MENU"
        echo -e "  ${WHITE}[1]${NC} Create Trojan"
        echo -e "  ${WHITE}[2]${NC} Trial Trojan (1 Jam)"
        echo -e "  ${WHITE}[3]${NC} Delete Trojan"
        echo -e "  ${WHITE}[4]${NC} Renew Trojan"
        echo -e "  ${WHITE}[5]${NC} Cek Login Trojan"
        echo -e "  ${WHITE}[6]${NC} List User Trojan"
        echo -e "  ${WHITE}[0]${NC} Back To Menu"
        echo ""
        read -p "  Select: " choice
        case $choice in
            1) create_trojan ;; 2) create_trial_xray "trojan" ;;
            3) delete_account "trojan" ;; 4) renew_account "trojan" ;;
            5) check_user_login "trojan" ;; 6) list_accounts "trojan" ;;
            0) return ;;
        esac
    done
}

#================================================
# HELPER: LIST ALL & BACKUP & RESTORE
#================================================

_menu_list_all() {
    clear; print_menu_header "ALL ACCOUNTS"
    local total=0
    shopt -s nullglob
    for proto in ssh vmess vless trojan; do
        local files=("$AKUN_DIR"/${proto}-*.txt)
        [[ ${#files[@]} -eq 0 ]] && continue
        echo -e "  ${GREEN}── ${proto^^} ACCOUNTS ─────────────────────────────────${NC}"
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
    echo ""
    pause
}

_menu_backup() {
    clear; print_menu_header "BACKUP SYSTEM"
    local backup_dir="/root/backups"
    local backup_file="vpn-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
    mkdir -p "$backup_dir"
    echo -e "  ${YELLOW}Creating backup...${NC}"
    tar -czf "$backup_dir/$backup_file" \
        /root/domain /root/.domain_type /root/akun \
        /root/.bot_token /root/.chat_id /root/.payment_info \
        /etc/xray/xray.crt /etc/xray/xray.key \
        /usr/local/etc/xray/config.json \
        /etc/haproxy/haproxy.cfg \
        /etc/nginx/sites-available/default \
        /etc/default/dropbear \
        /etc/ssh/sshd_config \
        2>/dev/null
    if [[ -f "$backup_dir/$backup_file" ]]; then
        local sz; sz=$(du -h "$backup_dir/$backup_file" | awk '{print $1}')
        echo -e "  ${GREEN}✔ Backup created!${NC}"
        echo -e "  File : ${WHITE}$backup_file${NC}"
        echo -e "  Size : ${CYAN}${sz}${NC}"
        echo -e "  Path : ${CYAN}${backup_dir}/${backup_file}${NC}"
    else
        echo -e "  ${RED}✘ Backup failed!${NC}"
    fi
    echo ""
    pause
}

_menu_restore() {
    clear; print_menu_header "RESTORE SYSTEM"
    local backup_dir="/root/backups"
    [[ ! -d "$backup_dir" ]] && { echo -e "  ${RED}No backup directory!${NC}"; sleep 2; return; }
    shopt -s nullglob
    local backups=($(ls -t "$backup_dir"/*.tar.gz 2>/dev/null))
    shopt -u nullglob
    [[ ${#backups[@]} -eq 0 ]] && { echo -e "  ${RED}No backups found!${NC}"; sleep 2; return; }
    local i=1
    for backup in "${backups[@]}"; do
        printf "  ${CYAN}[%d]${NC} %-40s ${YELLOW}%s${NC}\n" "$i" "$(basename "$backup")" "$(du -h "$backup" | awk '{print $1}')"
        ((i++))
    done
    echo ""
    read -p "  Select [1-${#backups[@]}] or 0 to cancel: " choice
    [[ "$choice" == "0" ]] || [[ ! "$choice" =~ ^[0-9]+$ ]] && { echo -e "  ${YELLOW}Cancelled${NC}"; sleep 1; return; }
    local selected="${backups[$((choice-1))]}"
    read -p "  Continue? [y/N]: " confirm
    [[ "$confirm" != "y" ]] && { echo -e "  ${YELLOW}Cancelled${NC}"; sleep 1; return; }
    tar -xzf "$selected" -C / 2>/dev/null && \
        echo -e "  ${GREEN}✔ Restore successful!${NC}" || \
        echo -e "  ${RED}✘ Restore failed!${NC}"
    systemctl restart xray nginx haproxy 2>/dev/null
    echo ""
    pause
}

#================================================
# CHANGE DOMAIN & FIX CERT & SPEEDTEST & UPDATE
#================================================

change_domain() {
    clear
    print_menu_header "CHANGE DOMAIN"
    echo -e "  Current: ${GREEN}${DOMAIN:-Not Set}${NC}"
    echo ""
    setup_domain
    echo -e "  ${YELLOW}Jalankan Fix Certificate [11]!${NC}"
    sleep 3
}

fix_certificate() {
    clear
    print_menu_header "FIX / RENEW CERTIFICATE"
    [[ -f "$DOMAIN_FILE" ]] && \
        DOMAIN=$(tr -d '\n\r' < "$DOMAIN_FILE" | xargs)
    [[ -z "$DOMAIN" ]] && {
        echo -e "  ${RED}✘ Domain belum diset!${NC}"
        sleep 3; return
    }
    echo -e "  Domain: ${GREEN}${DOMAIN}${NC}"
    echo ""
    systemctl stop haproxy 2>/dev/null
    systemctl stop nginx   2>/dev/null
    sleep 1
    get_ssl_cert
    systemctl start nginx   2>/dev/null
    systemctl start haproxy 2>/dev/null
    systemctl restart xray  2>/dev/null
    echo -e "  ${GREEN}✔ Done!${NC}"
    sleep 3
}

run_speedtest() {
    clear
    print_menu_header "SPEEDTEST BY OOKLA"
    if ! command -v speedtest >/dev/null 2>&1 && \
       ! command -v speedtest-cli >/dev/null 2>&1; then
        echo -e "  ${CYAN}Installing Speedtest CLI...${NC}"
        curl -s https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.deb.sh \
            | bash >/dev/null 2>&1
        apt-get install -y speedtest >/dev/null 2>&1
        if ! command -v speedtest >/dev/null 2>&1; then
            pip3 install speedtest-cli --break-system-packages >/dev/null 2>&1
        fi
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
            local W; W=$(get_width)
            local inner=$(( W - 4 ))
            printf "  ${CYAN}┌"; printf '─%.0s' $(seq 1 $inner); printf "┐${NC}\n"
            printf "  ${CYAN}│${NC}  ${WHITE}%-16s${NC}: ${GREEN}%-$((inner-20))s${NC}  ${CYAN}│${NC}\n" "Server"    "$server"
            printf "  ${CYAN}│${NC}  ${WHITE}%-16s${NC}: ${GREEN}%-$((inner-20))s${NC}  ${CYAN}│${NC}\n" "Latency"   "$latency"
            printf "  ${CYAN}│${NC}  ${WHITE}%-16s${NC}: ${GREEN}%-$((inner-20))s${NC}  ${CYAN}│${NC}\n" "Download"  "$dl"
            printf "  ${CYAN}│${NC}  ${WHITE}%-16s${NC}: ${GREEN}%-$((inner-20))s${NC}  ${CYAN}│${NC}\n" "Upload"    "$ul"
            [[ -n "$url" ]] && \
            printf "  ${CYAN}│${NC}  ${WHITE}%-16s${NC}: ${CYAN}%-$((inner-20))s${NC}  ${CYAN}│${NC}\n" "Result URL" "$url"
            printf "  ${CYAN}└"; printf '─%.0s' $(seq 1 $inner); printf "┘${NC}\n"
        else
            echo -e "  ${RED}✘ Speedtest gagal!${NC}"
        fi
    else
        echo -e "  ${RED}✘ Speedtest tidak tersedia!${NC}"
    fi
    echo ""
    pause
}

update_menu() {
    clear
    print_menu_header "UPDATE SCRIPT"
    echo -e "  Current Version : ${GREEN}${SCRIPT_VERSION}${NC}"
    echo ""
    echo -e "  ${CYAN}Checking GitHub for updates...${NC}"
    local latest
    latest=$(curl -s --max-time 10 "$VERSION_URL" 2>/dev/null | tr -d '\n\r ' | xargs)
    if [[ -z "$latest" ]]; then
        echo -e "  ${RED}✘ Cannot connect to GitHub!${NC}"
        echo ""; pause; return
    fi
    echo -e "  Latest Version  : ${GREEN}${latest}${NC}"
    echo ""
    if [[ "$latest" == "$SCRIPT_VERSION" ]]; then
        echo -e "  ${GREEN}✔ You are using the latest version!${NC}"
        echo ""; pause; return
    fi
    read -p "  Update now? [y/N]: " confirm
    [[ "$confirm" != "y" ]] && return
    echo ""
    cp "$SCRIPT_PATH" "$BACKUP_PATH" 2>/dev/null && \
        echo -e "  ${GREEN}✔ Backup created${NC}"
    local tmp="/tmp/tunnel_new.sh"
    curl -L --max-time 60 "$SCRIPT_URL" -o "$tmp" 2>/dev/null
    if [[ ! -s "$tmp" ]]; then
        echo -e "  ${RED}✘ Download failed!${NC}"
        cp "$BACKUP_PATH" "$SCRIPT_PATH"
        pause; return
    fi
    bash -n "$tmp" 2>/dev/null && echo -e "  ${GREEN}✔ Syntax OK${NC}" || {
        echo -e "  ${RED}✘ Syntax error!${NC}"
        cp "$BACKUP_PATH" "$SCRIPT_PATH"; rm -f "$tmp"
        pause; return
    }
    mv "$tmp" "$SCRIPT_PATH"
    chmod +x "$SCRIPT_PATH"
    echo -e "  ${GREEN}✔ Update sukses! v${SCRIPT_VERSION} → v${latest}${NC}"
    sleep 2
    exec bash "$SCRIPT_PATH"
}

_adv_port_management() {
    while true; do
        clear
        print_menu_header "PORT MANAGEMENT"

        echo -e "  ${CYAN}── PORTS CURRENTLY LISTENING ──────────────────${NC}"
        echo ""
        # Tampilkan port dengan nama service yang jelas
        while IFS= read -r line; do
            local port svc
            port=$(echo "$line" | awk '{print $5}' | rev | cut -d: -f1 | rev)
            svc=$(echo "$line" | awk '{print $NF}' | grep -oP '\("[^"]+"\)' | tr -d '()"')
            printf "  ${GREEN}%-8s${NC} %s\n" "$port" "$svc"
        done < <(ss -tlnp 2>/dev/null | grep LISTEN | sort -t: -k2 -n)

        echo ""
        echo -e "  ${CYAN}── XRAY INTERNAL PORTS ─────────────────────────${NC}"
        printf "  ${WHITE}%-12s${NC} → %-8s %s\n" "VMess TLS"    "8443" "(via HAProxy 443)"
        printf "  ${WHITE}%-12s${NC} → %-8s %s\n" "VLess TLS"    "8444" "(via HAProxy 443)"
        printf "  ${WHITE}%-12s${NC} → %-8s %s\n" "Trojan TLS"   "8445" "(via HAProxy 443)"
        printf "  ${WHITE}%-12s${NC} → %-8s %s\n" "VMess NonTLS" "8080" "(via Nginx 80)"
        printf "  ${WHITE}%-12s${NC} → %-8s %s\n" "VLess NonTLS" "8081" "(via Nginx 80)"
        printf "  ${WHITE}%-12s${NC} → %-8s %s\n" "Trojan NonTLS""8082" "(via Nginx 80)"
        printf "  ${WHITE}%-12s${NC} → %-8s %s\n" "VMess gRPC"   "8446" "(via HAProxy 443)"
        printf "  ${WHITE}%-12s${NC} → %-8s %s\n" "VLess gRPC"   "8447" "(via HAProxy 443)"
        printf "  ${WHITE}%-12s${NC} → %-8s %s\n" "Trojan gRPC"  "8448" "(via HAProxy 443)"
        echo ""
        echo -e "  ${CYAN}── ACTIONS ──────────────────────────────────────${NC}"
        echo -e "  ${WHITE}[1]${NC} Cek port bentrok"
        echo -e "  ${WHITE}[2]${NC} Test koneksi port"
        echo -e "  ${WHITE}[3]${NC} Buka port di firewall (UFW)"
        echo -e "  ${WHITE}[4]${NC} Tutup port di firewall (UFW)"
        echo -e "  ${WHITE}[0]${NC} Back"
        echo ""
        read -p "  Select: " c
        case $c in
            1)
                clear; print_menu_header "CEK PORT BENTROK"
                echo -e "  ${YELLOW}Checking duplicate ports on Xray...${NC}"
                echo ""
                local ports_used=()
                local has_conflict=0
                if [[ -f "$XRAY_CONFIG" ]]; then
                    while IFS= read -r port; do
                        if [[ " ${ports_used[*]} " =~ " ${port} " ]]; then
                            echo -e "  ${RED}✘ BENTROK! Port ${port} dipakai lebih dari 1 inbound!${NC}"
                            has_conflict=1
                        else
                            ports_used+=("$port")
                        fi
                    done < <(jq -r '.inbounds[].port' "$XRAY_CONFIG" 2>/dev/null | sort -n)
                    if [[ $has_conflict -eq 0 ]]; then
                        echo -e "  ${GREEN}✔ Tidak ada port bentrok di Xray config!${NC}"
                    fi
                fi
                echo ""
                echo -e "  ${YELLOW}Checking system port conflicts...${NC}"
                ss -tlnp 2>/dev/null | awk 'NR>1 {print $4}' | sort | uniq -d | while read -r dup; do
                    echo -e "  ${RED}✘ Port duplikat di sistem: ${dup}${NC}"
                done
                pause
                ;;
            2)
                clear; print_menu_header "TEST KONEKSI PORT"
                read -p "  Port yang mau ditest: " testport
                [[ ! "$testport" =~ ^[0-9]+$ ]] && { echo -e "  ${RED}✘ Invalid!${NC}"; sleep 1; continue; }
                echo ""
                if ss -tlnp | grep -q ":${testport} "; then
                    echo -e "  ${GREEN}✔ Port ${testport} LISTENING${NC}"
                    local svcname
                    svcname=$(ss -tlnp | grep ":${testport} " | grep -oP '"\K[^"]+(?=")')
                    [[ -n "$svcname" ]] && echo -e "  ${CYAN}  Service: ${svcname}${NC}"
                else
                    echo -e "  ${RED}✘ Port ${testport} TIDAK listening${NC}"
                fi
                echo ""
                echo -e "  ${YELLOW}Test curl ke localhost:${testport}...${NC}"
                local curl_result
                curl_result=$(curl -s --max-time 3 -o /dev/null -w "%{http_code}" "http://127.0.0.1:${testport}" 2>/dev/null)
                [[ -n "$curl_result" ]] && \
                    echo -e "  ${GREEN}  HTTP Response: ${curl_result}${NC}" || \
                    echo -e "  ${YELLOW}  Tidak ada response HTTP (mungkin TCP-only)${NC}"
                pause
                ;;
            3)
                read -p "  Port yang mau dibuka (contoh: 8080 atau 8080/tcp): " newport
                [[ -z "$newport" ]] && continue
                if command -v ufw >/dev/null 2>&1; then
                    ufw allow "$newport" >/dev/null 2>&1
                    echo -e "  ${GREEN}✔ Port ${newport} dibuka di UFW!${NC}"
                else
                    iptables -I INPUT -p tcp --dport "${newport%%/*}" -j ACCEPT 2>/dev/null
                    echo -e "  ${GREEN}✔ Port ${newport} dibuka di iptables!${NC}"
                fi
                sleep 2
                ;;
            4)
                read -p "  Port yang mau ditutup: " delport
                [[ -z "$delport" ]] && continue
                if command -v ufw >/dev/null 2>&1; then
                    ufw deny "$delport" >/dev/null 2>&1
                    echo -e "  ${YELLOW}Port ${delport} ditutup di UFW!${NC}"
                else
                    iptables -D INPUT -p tcp --dport "${delport%%/*}" -j ACCEPT 2>/dev/null
                    echo -e "  ${YELLOW}Port ${delport} ditutup di iptables!${NC}"
                fi
                sleep 2
                ;;
            0) return ;;
        esac
    done
}

# ================================================
# [2] PROTOCOL SETTINGS - FULLY FUNCTIONAL
# ================================================
_adv_protocol_settings() {
    while true; do
        clear
        print_menu_header "PROTOCOL SETTINGS"

        if [[ ! -f "$XRAY_CONFIG" ]]; then
            echo -e "  ${RED}✘ Xray config tidak ditemukan!${NC}"; pause; return
        fi

        echo -e "  ${CYAN}── XRAY VERSION ──────────────────────────────────${NC}"
        local xver; xver=$(xray version 2>/dev/null | head -1)
        echo -e "  ${GREEN}${xver:-Tidak terdeteksi}${NC}"
        echo ""

        echo -e "  ${CYAN}── INBOUND LIST ──────────────────────────────────${NC}"
        local idx=1
        while IFS= read -r line; do
            printf "  ${CYAN}[%2d]${NC} %s\n" "$idx" "$line"
            ((idx++))
        done < <(jq -r '.inbounds[] | "port:\(.port) | \(.protocol) | \(.tag // "no-tag") | \(.streamSettings.network // "tcp")"' "$XRAY_CONFIG" 2>/dev/null)
        echo ""

        echo -e "  ${WHITE}[1]${NC} Lihat full config"
        echo -e "  ${WHITE}[2]${NC} Restart Xray"
        echo -e "  ${WHITE}[3]${NC} Test config (syntax check)"
        echo -e "  ${WHITE}[4]${NC} Ganti path WebSocket"
        echo -e "  ${WHITE}[5]${NC} Ganti port Xray internal"
        echo -e "  ${WHITE}[6]${NC} Cek status semua inbound"
        echo -e "  ${WHITE}[0]${NC} Back"
        echo ""
        read -p "  Select: " c
        case $c in
            1)
                clear
                echo -e "${CYAN}── XRAY CONFIG ─────────────────────────────────${NC}"
                cat "$XRAY_CONFIG" | python3 -m json.tool 2>/dev/null || cat "$XRAY_CONFIG"
                pause
                ;;
            2)
                echo -e "  ${YELLOW}Restarting Xray...${NC}"
                systemctl restart xray
                sleep 2
                systemctl is-active --quiet xray && \
                    echo -e "  ${GREEN}✔ Xray RUNNING${NC}" || \
                    echo -e "  ${RED}✘ Xray FAILED${NC}"
                pause
                ;;
            3)
                clear; print_menu_header "SYNTAX CHECK"
                echo -e "  ${YELLOW}Testing config...${NC}"
                local test_out
                test_out=$(xray run -test -config "$XRAY_CONFIG" 2>&1)
                if echo "$test_out" | grep -q "Configuration OK"; then
                    echo -e "  ${GREEN}✔ Configuration OK!${NC}"
                else
                    echo -e "  ${RED}✘ Config ERROR:${NC}"
                    echo "$test_out" | tail -20
                fi
                pause
                ;;
            4)
                clear; print_menu_header "GANTI PATH WEBSOCKET"
                echo -e "  ${YELLOW}Path saat ini:${NC}"
                jq -r '.inbounds[] | select(.streamSettings.network=="ws") | "\(.tag): \(.streamSettings.wsSettings.path // "/")"' "$XRAY_CONFIG" 2>/dev/null
                echo ""
                read -p "  Tag yang mau diganti (contoh: vmess-tls): " tag
                read -p "  Path baru (contoh: /vmess2): " newpath
                [[ -z "$tag" || -z "$newpath" ]] && { echo -e "  ${RED}✘ Input kosong!${NC}"; sleep 1; continue; }
                local tmp; tmp=$(mktemp)
                jq --arg tag "$tag" --arg path "$newpath" \
                    '(.inbounds[] | select(.tag==$tag).streamSettings.wsSettings.path) = $path' \
                    "$XRAY_CONFIG" > "$tmp" 2>/dev/null && mv "$tmp" "$XRAY_CONFIG" || rm -f "$tmp"
                chmod 644 "$XRAY_CONFIG"
                systemctl restart xray >/dev/null 2>&1
                echo -e "  ${GREEN}✔ Path tag '${tag}' → '${newpath}' berhasil diupdate!${NC}"
                pause
                ;;
            5)
                clear; print_menu_header "GANTI PORT INTERNAL XRAY"
                echo -e "  ${YELLOW}Inbound saat ini:${NC}"
                jq -r '.inbounds[] | "\(.tag // "notag"): \(.port)"' "$XRAY_CONFIG" 2>/dev/null
                echo ""
                read -p "  Tag inbound: " tag
                read -p "  Port baru  : " newport
                [[ ! "$newport" =~ ^[0-9]+$ ]] && { echo -e "  ${RED}✘ Port harus angka!${NC}"; sleep 1; continue; }
                # Cek port sudah dipakai
                if jq -r '.inbounds[].port' "$XRAY_CONFIG" 2>/dev/null | grep -q "^${newport}$"; then
                    echo -e "  ${RED}✘ Port ${newport} sudah dipakai inbound lain!${NC}"
                    sleep 2; continue
                fi
                local tmp; tmp=$(mktemp)
                jq --arg tag "$tag" --argjson port "$newport" \
                    '(.inbounds[] | select(.tag==$tag).port) = $port' \
                    "$XRAY_CONFIG" > "$tmp" 2>/dev/null && mv "$tmp" "$XRAY_CONFIG" || rm -f "$tmp"
                chmod 644 "$XRAY_CONFIG"
                systemctl restart xray >/dev/null 2>&1
                echo -e "  ${GREEN}✔ Port '${tag}' → ${newport} berhasil!${NC}"
                pause
                ;;
            6)
                clear; print_menu_header "STATUS INBOUND"
                jq -r '.inbounds[] | "\(.port) \(.protocol) \(.tag // "notag")"' "$XRAY_CONFIG" 2>/dev/null | \
                while read -r port proto tag; do
                    if ss -tlnp | grep -q ":${port} "; then
                        printf "  ${GREEN}✔${NC} port:%-6s %-10s ${GREEN}LISTENING${NC}\n" "$port" "$proto"
                    else
                        printf "  ${RED}✘${NC} port:%-6s %-10s ${RED}NOT LISTENING${NC}\n" "$port" "$proto"
                    fi
                done
                pause
                ;;
            0) return ;;
        esac
    done
}

# ================================================
# [3] AUTO BACKUP - FULLY FUNCTIONAL
# ================================================
_adv_auto_backup() {
    while true; do
        clear
        print_menu_header "AUTO BACKUP CONFIG"

        local backup_dir="/root/backups"
        mkdir -p "$backup_dir"

        echo -e "  ${CYAN}── STATUS BACKUP ─────────────────────────────────${NC}"
        local cron_status
        cron_status=$(crontab -l 2>/dev/null | grep "vpn-backup")
        if [[ -n "$cron_status" ]]; then
            echo -e "  ${GREEN}✔ Auto Backup: AKTIF${NC}"
            echo -e "  ${DIM}  ${cron_status}${NC}"
        else
            echo -e "  ${YELLOW}⚠ Auto Backup: TIDAK AKTIF${NC}"
        fi
        echo ""

        echo -e "  ${CYAN}── BACKUP FILES ──────────────────────────────────${NC}"
        local bcount=0
        shopt -s nullglob
        for f in "$backup_dir"/*.tar.gz; do
            local sz; sz=$(du -h "$f" | awk '{print $1}')
            local dt; dt=$(stat -c %y "$f" | cut -d. -f1)
            printf "  ${GREEN}▸${NC} %-40s ${CYAN}%s${NC} ${DIM}%s${NC}\n" "$(basename "$f")" "$sz" "$dt"
            ((bcount++))
        done
        shopt -u nullglob
        [[ $bcount -eq 0 ]] && echo -e "  ${DIM}Belum ada backup${NC}"
        echo ""

        echo -e "  ${WHITE}[1]${NC} Backup Sekarang"
        echo -e "  ${WHITE}[2]${NC} Enable Auto Backup (jam 02:00 setiap hari)"
        echo -e "  ${WHITE}[3]${NC} Enable Auto Backup (setiap 6 jam)"
        echo -e "  ${WHITE}[4]${NC} Enable Auto Backup (setiap Minggu)"
        echo -e "  ${WHITE}[5]${NC} Disable Auto Backup"
        echo -e "  ${WHITE}[6]${NC} Hapus backup lama (>7 hari)"
        echo -e "  ${WHITE}[7]${NC} Upload backup ke Telegram"
        echo -e "  ${WHITE}[0]${NC} Back"
        echo ""
        read -p "  Select: " c
        case $c in
            1)
                clear; print_menu_header "BACKUP SEKARANG"
                local bfile="${backup_dir}/vpn-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
                echo -e "  ${YELLOW}Creating backup...${NC}"
                tar -czf "$bfile" \
                    /root/domain \
                    /root/.domain_type \
                    /root/akun \
                    /root/.bot_token \
                    /root/.chat_id \
                    /root/.payment_info \
                    /etc/xray/xray.crt \
                    /etc/xray/xray.key \
                    /usr/local/etc/xray/config.json \
                    /etc/haproxy/haproxy.cfg \
                    /etc/nginx/sites-available/default \
                    /etc/default/dropbear \
                    /etc/ssh/sshd_config \
                    2>/dev/null
                if [[ -f "$bfile" ]]; then
                    local sz; sz=$(du -h "$bfile" | awk '{print $1}')
                    echo -e "  ${GREEN}✔ Backup berhasil!${NC}"
                    echo -e "  ${WHITE}File : ${CYAN}$(basename "$bfile")${NC}"
                    echo -e "  ${WHITE}Size : ${CYAN}${sz}${NC}"
                    echo -e "  ${WHITE}Path : ${CYAN}${bfile}${NC}"
                else
                    echo -e "  ${RED}✘ Backup gagal!${NC}"
                fi
                pause
                ;;
            2)
                # Hapus cron lama, tambah baru
                local cron_cmd="0 2 * * * tar -czf ${backup_dir}/vpn-backup-\$(date +\\%Y\\%m\\%d-\\%H\\%M\\%S).tar.gz /root/akun /root/domain /usr/local/etc/xray/config.json /etc/xray 2>/dev/null && find ${backup_dir} -name '*.tar.gz' -mtime +7 -delete"
                (crontab -l 2>/dev/null | grep -v "vpn-backup"; echo "$cron_cmd") | crontab -
                echo -e "  ${GREEN}✔ Auto backup aktif jam 02:00 setiap hari!${NC}"
                sleep 2
                ;;
            3)
                local cron_cmd="0 */6 * * * tar -czf ${backup_dir}/vpn-backup-\$(date +\\%Y\\%m\\%d-\\%H\\%M\\%S).tar.gz /root/akun /root/domain /usr/local/etc/xray/config.json /etc/xray 2>/dev/null && find ${backup_dir} -name '*.tar.gz' -mtime +3 -delete"
                (crontab -l 2>/dev/null | grep -v "vpn-backup"; echo "$cron_cmd") | crontab -
                echo -e "  ${GREEN}✔ Auto backup aktif setiap 6 jam!${NC}"
                sleep 2
                ;;
            4)
                local cron_cmd="0 2 * * 0 tar -czf ${backup_dir}/vpn-backup-\$(date +\\%Y\\%m\\%d-\\%H\\%M\\%S).tar.gz /root/akun /root/domain /usr/local/etc/xray/config.json /etc/xray 2>/dev/null && find ${backup_dir} -name '*.tar.gz' -mtime +30 -delete"
                (crontab -l 2>/dev/null | grep -v "vpn-backup"; echo "$cron_cmd") | crontab -
                echo -e "  ${GREEN}✔ Auto backup aktif setiap Minggu!${NC}"
                sleep 2
                ;;
            5)
                crontab -l 2>/dev/null | grep -v "vpn-backup" | crontab -
                echo -e "  ${YELLOW}Auto backup dimatikan.${NC}"
                sleep 2
                ;;
            6)
                local count; count=$(find "$backup_dir" -name "*.tar.gz" -mtime +7 2>/dev/null | wc -l)
                find "$backup_dir" -name "*.tar.gz" -mtime +7 -delete 2>/dev/null
                echo -e "  ${GREEN}✔ ${count} file backup lama dihapus!${NC}"
                sleep 2
                ;;
            7)
                if [[ ! -f /root/.bot_token || ! -f /root/.chat_id ]]; then
                    echo -e "  ${RED}✘ Bot Telegram belum dikonfigurasi!${NC}"
                    sleep 2; continue
                fi
                local latest_bak
                latest_bak=$(ls -t "$backup_dir"/*.tar.gz 2>/dev/null | head -1)
                if [[ -z "$latest_bak" ]]; then
                    echo -e "  ${RED}✘ Tidak ada file backup!${NC}"
                    sleep 2; continue
                fi
                local token; token=$(cat /root/.bot_token)
                local chatid; chatid=$(cat /root/.chat_id)
                echo -e "  ${YELLOW}Mengirim backup ke Telegram...${NC}"
                curl -s -F "chat_id=${chatid}" \
                    -F "document=@${latest_bak}" \
                    -F "caption=🗄 VPN Backup - $(date '+%d %b %Y %H:%M')" \
                    "https://api.telegram.org/bot${token}/sendDocument" \
                    --max-time 60 >/dev/null 2>&1 && \
                    echo -e "  ${GREEN}✔ Backup terkirim ke Telegram!${NC}" || \
                    echo -e "  ${RED}✘ Gagal kirim!${NC}"
                sleep 2
                ;;
            0) return ;;
        esac
    done
}

# ================================================
# [4] SSH BRUTE FORCE PROTECTION - PERSISTENT
# ================================================
_adv_ssh_brute_protection() {
    while true; do
        clear
        print_menu_header "SSH BRUTE FORCE PROTECTION"

        # Cek status
        local status_f2b status_ipt
        command -v fail2ban-client >/dev/null 2>&1 && \
            systemctl is-active --quiet fail2ban && \
            status_f2b="${GREEN}AKTIF (Fail2Ban)${NC}" || \
            status_f2b="${YELLOW}TIDAK AKTIF${NC}"

        iptables -L INPUT -n 2>/dev/null | grep -q "recent.*SSH" && \
            status_ipt="${GREEN}AKTIF (iptables)${NC}" || \
            status_ipt="${YELLOW}TIDAK AKTIF${NC}"

        echo -e "  Fail2Ban  : $(echo -e $status_f2b)"
        echo -e "  iptables  : $(echo -e $status_ipt)"
        echo ""

        echo -e "  ${WHITE}[1]${NC} Aktifkan via Fail2Ban ${GREEN}(RECOMMENDED - Persistent)${NC}"
        echo -e "  ${WHITE}[2]${NC} Aktifkan via iptables (Manual)"
        echo -e "  ${WHITE}[3]${NC} Lihat IP yang diblokir"
        echo -e "  ${WHITE}[4]${NC} Unban IP tertentu"
        echo -e "  ${WHITE}[5]${NC} Reset semua blokir"
        echo -e "  ${WHITE}[6]${NC} Lihat log percobaan login gagal"
        echo -e "  ${WHITE}[0]${NC} Back"
        echo ""
        read -p "  Select: " c
        case $c in
            1)
                # Install fail2ban jika belum ada
                if ! command -v fail2ban-client >/dev/null 2>&1; then
                    echo -e "  ${YELLOW}Installing Fail2Ban...${NC}"
                    apt-get install -y fail2ban >/dev/null 2>&1
                fi
                # Buat konfigurasi jail yang proper
                cat > /etc/fail2ban/jail.local << 'F2BEOF'
[DEFAULT]
bantime  = 3600
findtime  = 600
maxretry = 5
ignoreip = 127.0.0.1/8

[sshd]
enabled  = true
port     = 22,222
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 5
bantime  = 3600

[dropbear]
enabled  = true
port     = 222
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 5
bantime  = 3600
F2BEOF
                systemctl enable fail2ban >/dev/null 2>&1
                systemctl restart fail2ban >/dev/null 2>&1
                sleep 2
                systemctl is-active --quiet fail2ban && \
                    echo -e "  ${GREEN}✔ Fail2Ban aktif! Max 5 percobaan/10 menit, ban 1 jam${NC}" || \
                    echo -e "  ${RED}✘ Fail2Ban gagal start!${NC}"
                pause
                ;;
            2)
                # iptables rules + simpan ke file agar persistent
                iptables -I INPUT -p tcp --dport 22 -m state --state NEW -m recent --set --name SSH_BRUTE 2>/dev/null
                iptables -I INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 6 --name SSH_BRUTE -j DROP 2>/dev/null
                iptables -I INPUT -p tcp --dport 222 -m state --state NEW -m recent --set --name DROP_BRUTE 2>/dev/null
                iptables -I INPUT -p tcp --dport 222 -m state --state NEW -m recent --update --seconds 60 --hitcount 6 --name DROP_BRUTE -j DROP 2>/dev/null
                # Simpan rules agar persistent saat reboot
                if command -v iptables-save >/dev/null 2>&1; then
                    mkdir -p /etc/iptables
                    iptables-save > /etc/iptables/rules.v4 2>/dev/null
                    # Buat service restore otomatis
                    if [[ ! -f /etc/network/if-pre-up.d/iptables ]]; then
                        cat > /etc/network/if-pre-up.d/iptables << 'IPTEOF'
#!/bin/sh
iptables-restore < /etc/iptables/rules.v4
exit 0
IPTEOF
                        chmod +x /etc/network/if-pre-up.d/iptables
                    fi
                fi
                echo -e "  ${GREEN}✔ SSH Brute Protection aktif + disimpan (persistent)!${NC}"
                pause
                ;;
            3)
                clear; print_menu_header "IP YANG DIBLOKIR"
                if command -v fail2ban-client >/dev/null 2>&1 && systemctl is-active --quiet fail2ban; then
                    echo -e "  ${CYAN}── Fail2Ban Banned IPs ──${NC}"
                    fail2ban-client status sshd 2>/dev/null
                    echo ""
                fi
                echo -e "  ${CYAN}── iptables Blocked IPs ──${NC}"
                iptables -L INPUT -n 2>/dev/null | grep -E "DROP|REJECT" | head -20
                pause
                ;;
            4)
                read -p "  IP yang mau di-unban: " unban_ip
                [[ -z "$unban_ip" ]] && continue
                if command -v fail2ban-client >/dev/null 2>&1; then
                    fail2ban-client set sshd unbanip "$unban_ip" 2>/dev/null && \
                        echo -e "  ${GREEN}✔ ${unban_ip} di-unban dari Fail2Ban!${NC}"
                fi
                iptables -D INPUT -s "$unban_ip" -j DROP 2>/dev/null && \
                    echo -e "  ${GREEN}✔ ${unban_ip} di-unban dari iptables!${NC}"
                sleep 2
                ;;
            5)
                if command -v fail2ban-client >/dev/null 2>&1; then
                    fail2ban-client unban --all 2>/dev/null
                fi
                iptables -F INPUT 2>/dev/null
                # Allow kembali port penting
                iptables -I INPUT -p tcp --dport 22 -j ACCEPT 2>/dev/null
                iptables -I INPUT -p tcp --dport 222 -j ACCEPT 2>/dev/null
                iptables -I INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null
                iptables -I INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null
                echo -e "  ${GREEN}✔ Semua blokir direset!${NC}"
                sleep 2
                ;;
            6)
                clear
                echo -e "  ${CYAN}── 30 Login Gagal Terakhir ──${NC}"
                grep -i "failed\|invalid\|disconnect" /var/log/auth.log 2>/dev/null | tail -30 || \
                    journalctl -u ssh -n 30 --no-pager 2>/dev/null | grep -i "fail\|invalid"
                pause
                ;;
            0) return ;;
        esac
    done
}

# ================================================
# [5] FAIL2BAN SETUP - FULLY FUNCTIONAL
# ================================================
_adv_fail2ban() {
    while true; do
        clear
        print_menu_header "FAIL2BAN MANAGEMENT"

        local f2b_status
        if command -v fail2ban-client >/dev/null 2>&1; then
            systemctl is-active --quiet fail2ban && \
                f2b_status="${GREEN}RUNNING${NC}" || \
                f2b_status="${RED}STOPPED${NC}"
        else
            f2b_status="${YELLOW}BELUM INSTALL${NC}"
        fi
        echo -e "  Status : $(echo -e $f2b_status)"
        echo ""

        echo -e "  ${WHITE}[1]${NC} Install & Setup Fail2Ban"
        echo -e "  ${WHITE}[2]${NC} Lihat status semua jail"
        echo -e "  ${WHITE}[3]${NC} Lihat IP banned"
        echo -e "  ${WHITE}[4]${NC} Ban IP manual"
        echo -e "  ${WHITE}[5]${NC} Unban IP"
        echo -e "  ${WHITE}[6]${NC} Restart Fail2Ban"
        echo -e "  ${WHITE}[7]${NC} Lihat config jail"
        echo -e "  ${WHITE}[8]${NC} Hapus Fail2Ban"
        echo -e "  ${WHITE}[0]${NC} Back"
        echo ""
        read -p "  Select: " c
        case $c in
            1)
                echo -e "  ${YELLOW}Installing Fail2Ban...${NC}"
                apt-get install -y fail2ban >/dev/null 2>&1
                cat > /etc/fail2ban/jail.local << 'F2BEOF'
[DEFAULT]
bantime   = 3600
findtime  = 600
maxretry  = 5
ignoreip  = 127.0.0.1/8
backend   = systemd

[sshd]
enabled  = true
port     = 22,222
maxretry = 5
bantime  = 3600

[nginx-limit-req]
enabled  = false
port     = http,https
logpath  = /var/log/nginx/error.log

[nginx-botsearch]
enabled  = false
port     = http,https
logpath  = /var/log/nginx/access.log
maxretry = 2
F2BEOF
                systemctl enable fail2ban >/dev/null 2>&1
                systemctl restart fail2ban >/dev/null 2>&1
                sleep 2
                systemctl is-active --quiet fail2ban && \
                    echo -e "  ${GREEN}✔ Fail2Ban aktif!${NC}" || \
                    echo -e "  ${RED}✘ Gagal!${NC}"
                pause
                ;;
            2)
                clear
                if command -v fail2ban-client >/dev/null 2>&1; then
                    fail2ban-client status 2>/dev/null
                    echo ""
                    fail2ban-client status sshd 2>/dev/null
                fi
                pause
                ;;
            3)
                clear
                echo -e "  ${CYAN}── BANNED IPs ──${NC}"
                if command -v fail2ban-client >/dev/null 2>&1; then
                    fail2ban-client status sshd 2>/dev/null | grep "Banned IP"
                fi
                pause
                ;;
            4)
                read -p "  IP yang mau di-ban: " ban_ip
                [[ -z "$ban_ip" ]] && continue
                fail2ban-client set sshd banip "$ban_ip" 2>/dev/null && \
                    echo -e "  ${GREEN}✔ ${ban_ip} di-ban!${NC}" || \
                    echo -e "  ${RED}✘ Gagal ban!${NC}"
                sleep 2
                ;;
            5)
                read -p "  IP yang mau di-unban: " uip
                [[ -z "$uip" ]] && continue
                fail2ban-client set sshd unbanip "$uip" 2>/dev/null && \
                    echo -e "  ${GREEN}✔ ${uip} di-unban!${NC}" || \
                    echo -e "  ${RED}✘ Gagal!${NC}"
                sleep 2
                ;;
            6)
                systemctl restart fail2ban && \
                    echo -e "  ${GREEN}✔ Restarted!${NC}" || \
                    echo -e "  ${RED}✘ Gagal!${NC}"
                sleep 2
                ;;
            7)
                clear
                cat /etc/fail2ban/jail.local 2>/dev/null || echo -e "  ${YELLOW}Config tidak ditemukan${NC}"
                pause
                ;;
            8)
                read -p "  Yakin hapus Fail2Ban? [y/N]: " yn
                [[ "$yn" != "y" ]] && continue
                systemctl stop fail2ban 2>/dev/null
                systemctl disable fail2ban 2>/dev/null
                apt-get purge -y fail2ban >/dev/null 2>&1
                rm -f /etc/fail2ban/jail.local
                echo -e "  ${GREEN}✔ Fail2Ban dihapus!${NC}"
                sleep 2
                ;;
            0) return ;;
        esac
    done
}

# ================================================
# [6] DDOS PROTECTION - PERSISTENT + WHITELIST
# ================================================
_adv_ddos_protection() {
    while true; do
        clear
        print_menu_header "DDOS PROTECTION"

        local ddos_status
        iptables -L INPUT -n 2>/dev/null | grep -q "connlimit\|syncookies\|limit" && \
            ddos_status="${GREEN}AKTIF${NC}" || \
            ddos_status="${YELLOW}TIDAK AKTIF${NC}"
        echo -e "  Status : $(echo -e $ddos_status)"
        echo ""

        echo -e "  ${WHITE}[1]${NC} Aktifkan DDoS Protection ${GREEN}(Full)${NC}"
        echo -e "  ${WHITE}[2]${NC} Aktifkan Rate Limiting saja"
        echo -e "  ${WHITE}[3]${NC} Tambah IP ke Whitelist"
        echo -e "  ${WHITE}[4]${NC} Lihat statistik koneksi"
        echo -e "  ${WHITE}[5]${NC} Lihat top IP koneksi terbanyak"
        echo -e "  ${WHITE}[6]${NC} Blokir IP secara manual"
        echo -e "  ${WHITE}[7]${NC} Reset semua rules"
        echo -e "  ${WHITE}[0]${NC} Back"
        echo ""
        read -p "  Select: " c
        case $c in
            1)
                echo -e "  ${YELLOW}Mengaktifkan DDoS Protection...${NC}"
                # SYN Flood protection
                sysctl -w net.ipv4.tcp_syncookies=1 >/dev/null 2>&1
                sysctl -w net.ipv4.tcp_max_syn_backlog=2048 >/dev/null 2>&1
                sysctl -w net.ipv4.tcp_synack_retries=2 >/dev/null 2>&1
                # Tulis ke sysctl.d agar persistent
                cat > /etc/sysctl.d/99-ddos.conf << 'SEOF'
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.conf.all.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
SEOF
                sysctl -p /etc/sysctl.d/99-ddos.conf >/dev/null 2>&1

                # iptables rules
                # Drop invalid packets
                iptables -A INPUT -m state --state INVALID -j DROP 2>/dev/null
                # SYN flood
                iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP 2>/dev/null
                # Limit new connections per IP
                iptables -A INPUT -p tcp --dport 443 -m connlimit --connlimit-above 80 --connlimit-mask 32 -j REJECT --reject-with tcp-reset 2>/dev/null
                iptables -A INPUT -p tcp --dport 80 -m connlimit --connlimit-above 80 --connlimit-mask 32 -j REJECT --reject-with tcp-reset 2>/dev/null
                # Rate limit ICMP
                iptables -A INPUT -p icmp -m limit --limit 10/s --limit-burst 20 -j ACCEPT 2>/dev/null
                iptables -A INPUT -p icmp -j DROP 2>/dev/null
                # Rate limit new connections
                iptables -A INPUT -p tcp --syn -m limit --limit 100/s --limit-burst 200 -j ACCEPT 2>/dev/null

                # Simpan iptables rules (persistent)
                mkdir -p /etc/iptables
                iptables-save > /etc/iptables/rules.v4 2>/dev/null

                echo -e "  ${GREEN}✔ DDoS Protection AKTIF + disimpan persistent!${NC}"
                pause
                ;;
            2)
                iptables -A INPUT -p tcp --dport 443 -m limit --limit 200/s --limit-burst 400 -j ACCEPT 2>/dev/null
                iptables -A INPUT -p tcp --dport 443 -j DROP 2>/dev/null
                iptables -A INPUT -p tcp --dport 80 -m limit --limit 200/s --limit-burst 400 -j ACCEPT 2>/dev/null
                iptables -A INPUT -p tcp --dport 80 -j DROP 2>/dev/null
                mkdir -p /etc/iptables
                iptables-save > /etc/iptables/rules.v4 2>/dev/null
                echo -e "  ${GREEN}✔ Rate Limiting aktif!${NC}"
                sleep 2
                ;;
            3)
                read -p "  IP yang mau di-whitelist (contoh: 1.2.3.4): " wip
                [[ -z "$wip" ]] && continue
                iptables -I INPUT -s "$wip" -j ACCEPT 2>/dev/null
                mkdir -p /etc/iptables
                iptables-save > /etc/iptables/rules.v4 2>/dev/null
                echo -e "  ${GREEN}✔ ${wip} ditambahkan ke whitelist!${NC}"
                sleep 2
                ;;
            4)
                clear; print_menu_header "STATISTIK KONEKSI"
                echo -e "  ${CYAN}── Active Connections by State ──${NC}"
                ss -s 2>/dev/null
                echo ""
                echo -e "  ${CYAN}── Total koneksi per port ──${NC}"
                ss -tn 2>/dev/null | awk 'NR>1 {print $5}' | cut -d: -f2 | sort | uniq -c | sort -rn | head -10
                pause
                ;;
            5)
                clear; print_menu_header "TOP IP KONEKSI"
                echo -e "  ${CYAN}── Top 20 IP dengan koneksi terbanyak ──${NC}"
                ss -tn 2>/dev/null | awk 'NR>1 {print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -20 | \
                while read count ip; do
                    printf "  ${YELLOW}%4s${NC} koneksi - ${GREEN}%s${NC}\n" "$count" "$ip"
                done
                pause
                ;;
            6)
                read -p "  IP yang mau diblokir: " bip
                [[ -z "$bip" ]] && continue
                iptables -I INPUT -s "$bip" -j DROP 2>/dev/null
                mkdir -p /etc/iptables
                iptables-save > /etc/iptables/rules.v4 2>/dev/null
                echo -e "  ${GREEN}✔ ${bip} diblokir!${NC}"
                sleep 2
                ;;
            7)
                read -p "  Yakin reset semua rules? [y/N]: " yn
                [[ "$yn" != "y" ]] && continue
                iptables -F >/dev/null 2>&1
                iptables -X >/dev/null 2>&1
                iptables -Z >/dev/null 2>&1
                # Restore rules dasar (jangan sampai lockout)
                iptables -P INPUT ACCEPT
                iptables -P FORWARD ACCEPT
                iptables -P OUTPUT ACCEPT
                # Allow port VPN penting
                for port in 22 222 80 81 443 8080 8081 8082 8443 8444 8445 8446 8447 8448; do
                    iptables -A INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null
                done
                mkdir -p /etc/iptables
                iptables-save > /etc/iptables/rules.v4 2>/dev/null
                echo -e "  ${GREEN}✔ Rules direset! Port penting sudah di-allow.${NC}"
                sleep 2
                ;;
            0) return ;;
        esac
    done
}

# ================================================
# [7] FIREWALL RULES - SAFE (tidak bisa lockout)
# ================================================
_adv_firewall() {
    while true; do
        clear
        print_menu_header "FIREWALL RULES (UFW)"

        local ufw_status
        if command -v ufw >/dev/null 2>&1; then
            ufw_status=$(ufw status 2>/dev/null | head -1)
        else
            ufw_status="UFW belum terinstall"
        fi
        echo -e "  Status : ${CYAN}${ufw_status}${NC}"
        echo ""

        echo -e "  ${WHITE}[1]${NC} Enable UFW ${GREEN}(safe - allow port penting dulu)${NC}"
        echo -e "  ${WHITE}[2]${NC} Disable UFW"
        echo -e "  ${WHITE}[3]${NC} Lihat semua rules"
        echo -e "  ${WHITE}[4]${NC} Tambah rule ALLOW port"
        echo -e "  ${WHITE}[5]${NC} Tambah rule DENY port"
        echo -e "  ${WHITE}[6]${NC} Hapus rule berdasar nomor"
        echo -e "  ${WHITE}[7]${NC} Allow IP tertentu (full access)"
        echo -e "  ${WHITE}[8]${NC} Reset UFW ke default"
        echo -e "  ${WHITE}[0]${NC} Back"
        echo ""
        read -p "  Select: " c
        case $c in
            1)
                if ! command -v ufw >/dev/null 2>&1; then
                    echo -e "  ${YELLOW}Installing UFW...${NC}"
                    apt-get install -y ufw >/dev/null 2>&1
                fi
                echo -e "  ${YELLOW}Allow port penting sebelum enable...${NC}"
                # WAJIB allow dulu sebelum enable supaya tidak lockout
                ufw allow 22/tcp comment "SSH" >/dev/null 2>&1
                ufw allow 222/tcp comment "Dropbear" >/dev/null 2>&1
                ufw allow 80/tcp comment "Nginx NonTLS" >/dev/null 2>&1
                ufw allow 81/tcp comment "Nginx Download" >/dev/null 2>&1
                ufw allow 443/tcp comment "HAProxy TLS" >/dev/null 2>&1
                ufw allow 8080:8082/tcp comment "Xray NonTLS" >/dev/null 2>&1
                ufw allow 8443:8448/tcp comment "Xray TLS & gRPC" >/dev/null 2>&1
                echo "y" | ufw enable >/dev/null 2>&1
                echo -e "  ${GREEN}✔ UFW enabled! Semua port VPN sudah di-allow.${NC}"
                pause
                ;;
            2)
                ufw disable >/dev/null 2>&1
                echo -e "  ${YELLOW}UFW disabled.${NC}"
                sleep 2
                ;;
            3)
                clear
                ufw status numbered 2>/dev/null || echo -e "  ${YELLOW}UFW tidak aktif${NC}"
                pause
                ;;
            4)
                read -p "  Port yang mau di-allow (contoh: 9000 atau 9000/tcp): " ap
                [[ -z "$ap" ]] && continue
                read -p "  Keterangan (opsional): " apcomment
                ufw allow "$ap" comment "${apcomment:-custom}" >/dev/null 2>&1 && \
                    echo -e "  ${GREEN}✔ Port ${ap} di-allow!${NC}" || \
                    echo -e "  ${RED}✘ Gagal!${NC}"
                sleep 2
                ;;
            5)
                read -p "  Port yang mau di-deny: " dp
                [[ -z "$dp" ]] && continue
                ufw deny "$dp" >/dev/null 2>&1 && \
                    echo -e "  ${YELLOW}Port ${dp} di-deny!${NC}" || \
                    echo -e "  ${RED}✘ Gagal!${NC}"
                sleep 2
                ;;
            6)
                clear
                ufw status numbered 2>/dev/null
                echo ""
                read -p "  Nomor rule yang mau dihapus: " rnum
                [[ ! "$rnum" =~ ^[0-9]+$ ]] && continue
                echo "y" | ufw delete "$rnum" >/dev/null 2>&1 && \
                    echo -e "  ${GREEN}✔ Rule #${rnum} dihapus!${NC}" || \
                    echo -e "  ${RED}✘ Gagal!${NC}"
                sleep 2
                ;;
            7)
                read -p "  IP yang diberi full access: " fip
                [[ -z "$fip" ]] && continue
                ufw allow from "$fip" >/dev/null 2>&1 && \
                    echo -e "  ${GREEN}✔ ${fip} diberi full access!${NC}" || \
                    echo -e "  ${RED}✘ Gagal!${NC}"
                sleep 2
                ;;
            8)
                read -p "  Yakin reset UFW? [y/N]: " yn
                [[ "$yn" != "y" ]] && continue
                echo "y" | ufw reset >/dev/null 2>&1
                # Allow port penting lagi setelah reset
                ufw allow 22/tcp >/dev/null 2>&1
                ufw allow 443/tcp >/dev/null 2>&1
                ufw allow 80/tcp >/dev/null 2>&1
                echo -e "  ${GREEN}✔ UFW direset! SSH & port utama di-allow.${NC}"
                sleep 2
                ;;
            0) return ;;
        esac
    done
}

# ================================================
# [8] BANDWIDTH MONITOR - REALTIME
# ================================================
_adv_bandwidth_monitor() {
    while true; do
        clear
        print_menu_header "BANDWIDTH MONITOR"

        echo -e "  ${WHITE}[1]${NC} Realtime monitor (iftop) ${GREEN}← RECOMMENDED${NC}"
        echo -e "  ${WHITE}[2]${NC} Statistik harian (vnstat)"
        echo -e "  ${WHITE}[3]${NC} Statistik bulanan (vnstat)"
        echo -e "  ${WHITE}[4]${NC} Live bandwidth usage (manual)"
        echo -e "  ${WHITE}[5]${NC} Cek usage per akun (Xray log)"
        echo -e "  ${WHITE}[6]${NC} Install tools monitoring"
        echo -e "  ${WHITE}[0]${NC} Back"
        echo ""
        read -p "  Select: " c
        case $c in
            1)
                if command -v iftop >/dev/null 2>&1; then
                    echo -e "  ${YELLOW}Press Q untuk keluar dari iftop${NC}"
                    sleep 1
                    iftop -i "$(ip route | awk '/default/{print $5; exit}')" 2>/dev/null || \
                        iftop 2>/dev/null
                else
                    echo -e "  ${RED}✘ iftop belum terinstall. Pilih [6] untuk install.${NC}"
                    sleep 2
                fi
                ;;
            2)
                if command -v vnstat >/dev/null 2>&1; then
                    clear
                    echo -e "  ${CYAN}── Statistik Harian ──${NC}"
                    vnstat -d 2>/dev/null
                else
                    echo -e "  ${RED}✘ vnstat belum terinstall. Pilih [6] untuk install.${NC}"
                    sleep 2
                fi
                pause
                ;;
            3)
                if command -v vnstat >/dev/null 2>&1; then
                    clear
                    echo -e "  ${CYAN}── Statistik Bulanan ──${NC}"
                    vnstat -m 2>/dev/null
                else
                    echo -e "  ${RED}✘ vnstat belum terinstall.${NC}"
                    sleep 2
                fi
                pause
                ;;
            4)
                clear
                print_menu_header "LIVE BANDWIDTH (10 detik)"
                local iface; iface=$(ip route | awk '/default/{print $5; exit}')
                echo -e "  Interface: ${CYAN}${iface}${NC}"
                echo ""
                local rx1 tx1 rx2 tx2
                rx1=$(cat /sys/class/net/${iface}/statistics/rx_bytes 2>/dev/null || echo 0)
                tx1=$(cat /sys/class/net/${iface}/statistics/tx_bytes 2>/dev/null || echo 0)
                echo -e "  ${YELLOW}Mengukur selama 5 detik...${NC}"
                sleep 5
                rx2=$(cat /sys/class/net/${iface}/statistics/rx_bytes 2>/dev/null || echo 0)
                tx2=$(cat /sys/class/net/${iface}/statistics/tx_bytes 2>/dev/null || echo 0)
                local rx_speed tx_speed
                rx_speed=$(( (rx2 - rx1) / 5 / 1024 ))
                tx_speed=$(( (tx2 - tx1) / 5 / 1024 ))
                echo ""
                printf "  ${WHITE}%-12s${NC} : ${GREEN}%s KB/s${NC}\n" "Download" "$rx_speed"
                printf "  ${WHITE}%-12s${NC} : ${YELLOW}%s KB/s${NC}\n" "Upload" "$tx_speed"
                printf "  ${WHITE}%-12s${NC} : ${CYAN}%s GB${NC}\n" "Total RX" "$(( rx2 / 1024 / 1024 / 1024 ))"
                printf "  ${WHITE}%-12s${NC} : ${CYAN}%s GB${NC}\n" "Total TX" "$(( tx2 / 1024 / 1024 / 1024 ))"
                pause
                ;;
            5)
                clear
                print_menu_header "USAGE PER AKUN (Xray Log)"
                if [[ -f /var/log/xray/access.log ]]; then
                    echo -e "  ${CYAN}── Top koneksi dari access log ──${NC}"
                    grep -oP 'email: \K[^\s]+' /var/log/xray/access.log 2>/dev/null | \
                        sort | uniq -c | sort -rn | head -20 | \
                        while read count email; do
                            printf "  ${YELLOW}%4s${NC} koneksi - ${GREEN}%s${NC}\n" "$count" "$email"
                        done || echo -e "  ${DIM}Tidak ada data${NC}"
                else
                    echo -e "  ${RED}✘ Xray access log tidak ditemukan${NC}"
                fi
                pause
                ;;
            6)
                echo -e "  ${YELLOW}Installing monitoring tools...${NC}"
                apt-get install -y iftop vnstat nethogs >/dev/null 2>&1
                systemctl enable vnstat >/dev/null 2>&1
                systemctl start vnstat >/dev/null 2>&1
                echo -e "  ${GREEN}✔ iftop, vnstat, nethogs terinstall!${NC}"
                pause
                ;;
            0) return ;;
        esac
    done
}

# ================================================
# [9] USER IP LIMITS - DENGAN ENFORCEMENT
# ================================================
_adv_user_limits() {
    while true; do
        clear
        print_menu_header "USER IP LIMITS"

        echo -e "  ${CYAN}── DAFTAR AKUN & IP LIMIT ──────────────────────${NC}"
        echo ""
        shopt -s nullglob
        local files=("$AKUN_DIR"/*.txt)
        shopt -u nullglob
        if [[ ${#files[@]} -gt 0 ]]; then
            printf "  ${WHITE}%-20s %-10s %-8s %-10s${NC}\n" "USERNAME" "PROTOKOL" "IP LIMIT" "STATUS"
            printf "  ${DIM}%-20s %-10s %-8s %-10s${NC}\n" "────────────────────" "──────────" "────────" "──────────"
            for f in "${files[@]}"; do
                local fname proto uname limit
                fname=$(basename "$f" .txt)
                proto=${fname%%-*}
                uname=${fname#*-}
                limit=$(grep "IPLIMIT" "$f" 2>/dev/null | cut -d= -f2)
                # Hitung koneksi aktif user ini dari Xray log
                local active=0
                if [[ -f /var/log/xray/access.log ]]; then
                    active=$(grep -c "email: ${uname}" /var/log/xray/access.log 2>/dev/null || echo 0)
                fi
                printf "  ${GREEN}%-20s${NC} ${CYAN}%-10s${NC} %-8s ${YELLOW}%s aktif${NC}\n" \
                    "$uname" "$proto" "${limit:-N/A} IP" "$active"
            done
        else
            echo -e "  ${RED}Tidak ada akun!${NC}"
        fi
        echo ""

        echo -e "  ${WHITE}[1]${NC} Update IP limit akun"
        echo -e "  ${WHITE}[2]${NC} Update IP limit semua akun sekaligus"
        echo -e "  ${WHITE}[3]${NC} Lihat koneksi aktif real-time"
        echo -e "  ${WHITE}[4]${NC} Kick/disconnect user (restart xray)"
        echo -e "  ${WHITE}[0]${NC} Back"
        echo ""
        read -p "  Select: " c
        case $c in
            1)
                read -p "  Nama file akun (contoh: vmess-user1): " akun
                [[ -z "$akun" ]] && continue
                if [[ ! -f "$AKUN_DIR/${akun}.txt" ]]; then
                    echo -e "  ${RED}✘ Akun tidak ditemukan!${NC}"
                    sleep 2; continue
                fi
                local curlimit
                curlimit=$(grep "IPLIMIT" "$AKUN_DIR/${akun}.txt" | cut -d= -f2)
                echo -e "  Limit saat ini: ${YELLOW}${curlimit}${NC}"
                read -p "  IP Limit baru : " newlimit
                [[ ! "$newlimit" =~ ^[0-9]+$ ]] && { echo -e "  ${RED}✘ Harus angka!${NC}"; sleep 1; continue; }
                sed -i "s/IPLIMIT=.*/IPLIMIT=${newlimit}/" "$AKUN_DIR/${akun}.txt"
                echo -e "  ${GREEN}✔ IP Limit ${akun} → ${newlimit} IP${NC}"
                sleep 2
                ;;
            2)
                read -p "  Set semua akun ke berapa IP? : " bulklimit
                [[ ! "$bulklimit" =~ ^[0-9]+$ ]] && { echo -e "  ${RED}✘ Harus angka!${NC}"; sleep 1; continue; }
                local count=0
                shopt -s nullglob
                for f in "$AKUN_DIR"/*.txt; do
                    sed -i "s/IPLIMIT=.*/IPLIMIT=${bulklimit}/" "$f"
                    ((count++))
                done
                shopt -u nullglob
                echo -e "  ${GREEN}✔ ${count} akun diupdate ke ${bulklimit} IP!${NC}"
                sleep 2
                ;;
            3)
                clear
                print_menu_header "KONEKSI AKTIF REAL-TIME"
                echo -e "  ${CYAN}── Dari Xray (via ss) ──${NC}"
                ss -tn 2>/dev/null | grep -E ":8443|:8444|:8445|:8080|:8081|:8082|:8446|:8447|:8448" | \
                    awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -20 | \
                    while read count ip; do
                        printf "  ${YELLOW}%4s${NC} koneksi - ${GREEN}%s${NC}\n" "$count" "$ip"
                    done || echo -e "  ${DIM}Tidak ada koneksi${NC}"
                pause
                ;;
            4)
                read -p "  Yakin restart Xray (semua user disconnect sesaat)? [y/N]: " yn
                [[ "$yn" != "y" ]] && continue
                systemctl restart xray && \
                    echo -e "  ${GREEN}✔ Xray restarted! User akan reconnect otomatis.${NC}" || \
                    echo -e "  ${RED}✘ Gagal restart!${NC}"
                sleep 2
                ;;
            0) return ;;
        esac
    done
}

# ================================================
# [10] CUSTOM PAYLOAD GENERATOR - FULLY FUNCTIONAL
# ================================================
_adv_custom_payload() {
    while true; do
        clear
        print_menu_header "CUSTOM PAYLOAD GENERATOR"
        [[ -f "$DOMAIN_FILE" ]] && DOMAIN=$(tr -d '\n\r' < "$DOMAIN_FILE" | xargs)

        echo -e "  Domain aktif: ${GREEN}${DOMAIN:-belum diset}${NC}"
        echo ""
        echo -e "  ${WHITE}[1]${NC} HTTP Upgrade (untuk SSH/WS)"
        echo -e "  ${WHITE}[2]${NC} HTTP CONNECT (untuk proxy)"
        echo -e "  ${WHITE}[3]${NC} HTTP GET dengan Host spoof"
        echo -e "  ${WHITE}[4]${NC} HTTP POST (bug CDN)"
        echo -e "  ${WHITE}[5]${NC} Custom payload (input manual)"
        echo -e "  ${WHITE}[6]${NC} Format HC (HTTP Custom)"
        echo -e "  ${WHITE}[7]${NC} Generate payload dengan domain lain"
        echo -e "  ${WHITE}[0]${NC} Back"
        echo ""
        read -p "  Select: " c

        local show_domain="${DOMAIN:-yourdomain.com}"
        case $c in
            1)
                clear; print_menu_header "PAYLOAD: HTTP UPGRADE"
                echo ""
                echo -e "  ${CYAN}── Payload ──────────────────────────────────────${NC}"
                echo -e "  ${GREEN}GET / HTTP/1.1[crlf]Host: ${show_domain}[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]${NC}"
                echo ""
                echo -e "  ${CYAN}── Format HTTP Injector ─────────────────────────${NC}"
                printf "  GET / HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n" "$show_domain"
                echo ""
                echo -e "  ${CYAN}── Format Netmod/KPN ────────────────────────────${NC}"
                echo -e "  ${YELLOW}GET / HTTP/1.1[crlf]Host: ${show_domain}[crlf]Upgrade: websocket[crlf][crlf]${NC}"
                pause
                ;;
            2)
                clear; print_menu_header "PAYLOAD: HTTP CONNECT"
                echo ""
                echo -e "  ${GREEN}CONNECT ${show_domain}:443 HTTP/1.1[crlf]Host: ${show_domain}[crlf][crlf]${NC}"
                echo ""
                echo -e "  ${CYAN}Untuk port 80:${NC}"
                echo -e "  ${GREEN}CONNECT ${show_domain}:80 HTTP/1.1[crlf]Host: ${show_domain}[crlf][crlf]${NC}"
                pause
                ;;
            3)
                clear; print_menu_header "PAYLOAD: HTTP GET HOST SPOOF"
                read -p "  Bug host (contoh: free.domain.com): " bughost
                [[ -z "$bughost" ]] && bughost="bug.example.com"
                echo ""
                echo -e "  ${GREEN}GET http://${show_domain}/ HTTP/1.1[crlf]Host: ${bughost}[crlf]Connection: Keep-Alive[crlf][crlf]${NC}"
                pause
                ;;
            4)
                clear; print_menu_header "PAYLOAD: HTTP POST CDN"
                echo ""
                echo -e "  ${GREEN}POST / HTTP/1.1[crlf]Host: ${show_domain}[crlf]Content-Length: 9999[crlf][crlf]${NC}"
                echo ""
                echo -e "  ${CYAN}Dengan bug host:${NC}"
                read -p "  Bug host: " bughost2
                [[ -z "$bughost2" ]] && bughost2="bug.example.com"
                echo -e "  ${GREEN}POST / HTTP/1.1[crlf]Host: ${bughost2}[crlf]X-Online-Host: ${show_domain}[crlf]Content-Length: 9999[crlf][crlf]${NC}"
                pause
                ;;
            5)
                clear; print_menu_header "CUSTOM PAYLOAD MANUAL"
                echo -e "  ${YELLOW}Gunakan [crlf] untuk line break${NC}"
                echo -e "  ${YELLOW}Gunakan [host] untuk domain otomatis${NC}"
                echo ""
                read -p "  Masukkan payload: " custompayload
                # Replace placeholder
                custompayload="${custompayload//\[host\]/$show_domain}"
                echo ""
                echo -e "  ${CYAN}── Hasil ──────────────────────────────────────${NC}"
                echo -e "  ${GREEN}${custompayload}${NC}"
                echo ""
                # Simpan ke file
                read -p "  Simpan ke file? [y/N]: " saveit
                if [[ "$saveit" == "y" ]]; then
                    echo "$custompayload" > "$PUBLIC_HTML/payload.txt"
                    local ip_vps; ip_vps=$(get_ip 2>/dev/null || curl -s ifconfig.me)
                    echo -e "  ${GREEN}✔ Disimpan! Download: http://${ip_vps}:81/payload.txt${NC}"
                fi
                pause
                ;;
            6)
                clear; print_menu_header "FORMAT HTTP CUSTOM (HC)"
                echo ""
                echo -e "  ${CYAN}── Format Lengkap ───────────────────────────────${NC}"
                printf "  ${WHITE}%-18s${NC}: ${GREEN}%s:80@[username]:[password]${NC}\n" "Format HC" "$show_domain"
                printf "  ${WHITE}%-18s${NC}: ${GREEN}%s${NC}\n" "SSH Host" "$show_domain"
                printf "  ${WHITE}%-18s${NC}: ${GREEN}%s${NC}\n" "SSH Port" "22"
                printf "  ${WHITE}%-18s${NC}: ${GREEN}%s${NC}\n" "Proxy Type" "HTTP"
                echo ""
                echo -e "  ${CYAN}── Payload HC ───────────────────────────────────${NC}"
                echo -e "  ${GREEN}GET / HTTP/1.1[crlf]Host: ${show_domain}[crlf]Upgrade: websocket[crlf][crlf]${NC}"
                pause
                ;;
            7)
                read -p "  Domain alternatif: " altdomain
                [[ -z "$altdomain" ]] && continue
                clear; print_menu_header "PAYLOAD DOMAIN: ${altdomain}"
                echo ""
                echo -e "  ${CYAN}[1] HTTP Upgrade:${NC}"
                echo -e "  ${GREEN}GET / HTTP/1.1[crlf]Host: ${altdomain}[crlf]Upgrade: websocket[crlf][crlf]${NC}"
                echo ""
                echo -e "  ${CYAN}[2] HTTP CONNECT:${NC}"
                echo -e "  ${GREEN}CONNECT ${altdomain}:443 HTTP/1.1[crlf]Host: ${altdomain}[crlf][crlf]${NC}"
                echo ""
                echo -e "  ${CYAN}[3] HC Format:${NC}"
                echo -e "  ${GREEN}${altdomain}:80@[username]:[password]${NC}"
                pause
                ;;
            0) return ;;
        esac
    done
}

# ================================================
# [11] CRON JOBS - FULLY FUNCTIONAL
# ================================================
_adv_cron_jobs() {
    while true; do
        clear
        print_menu_header "CRON JOBS MANAGER"

        echo -e "  ${CYAN}── CRON JOBS AKTIF ──────────────────────────────${NC}"
        local crons
        crons=$(crontab -l 2>/dev/null)
        if [[ -n "$crons" ]]; then
            echo "$crons" | while IFS= read -r line; do
                [[ -z "$line" || "$line" =~ ^# ]] && continue
                printf "  ${GREEN}▸${NC} %s\n" "$line"
            done
        else
            echo -e "  ${DIM}Belum ada cron jobs${NC}"
        fi
        echo ""

        echo -e "  ${WHITE}[1]${NC} Auto hapus akun expired (jam 00:00)"
        echo -e "  ${WHITE}[2]${NC} Auto restart Xray (jam 04:00)"
        echo -e "  ${WHITE}[3]${NC} Auto restart semua service (jam 03:00)"
        echo -e "  ${WHITE}[4]${NC} Auto renew SSL certificate (sebulan sekali)"
        echo -e "  ${WHITE}[5]${NC} Auto backup (jam 02:00)"
        echo -e "  ${WHITE}[6]${NC} Auto bersihkan log Xray (jam 01:00)"
        echo -e "  ${WHITE}[7]${NC} Tambah cron custom"
        echo -e "  ${WHITE}[8]${NC} Hapus cron tertentu"
        echo -e "  ${WHITE}[9]${NC} Hapus semua cron"
        echo -e "  ${WHITE}[0]${NC} Back"
        echo ""
        read -p "  Select: " c
        case $c in
            1)
                # Buat script delete expired yang benar
                cat > /usr/local/bin/vpn-delete-expired.sh << 'DELEOF'
#!/bin/bash
AKUN_DIR="/root/akun"
XRAY_CONFIG="/usr/local/etc/xray/config.json"
PUBLIC_HTML="/var/www/html"
today=$(date +%s)
shopt -s nullglob
for f in "$AKUN_DIR"/*.txt; do
    exp_str=$(grep "EXPIRED=" "$f" 2>/dev/null | head -1 | cut -d= -f2-)
    [[ -z "$exp_str" ]] && continue
    exp_ts=$(date -d "$exp_str" +%s 2>/dev/null)
    [[ -z "$exp_ts" ]] && continue
    if [[ $exp_ts -lt $today ]]; then
        fname=$(basename "$f" .txt)
        protocol=${fname%%-*}
        uname=${fname#*-}
        tmp=$(mktemp)
        jq --arg email "$uname" \
           'del(.inbounds[].settings.clients[]? | select(.email == $email))' \
           "$XRAY_CONFIG" > "$tmp" 2>/dev/null && mv "$tmp" "$XRAY_CONFIG" || rm -f "$tmp"
        chmod 644 "$XRAY_CONFIG" 2>/dev/null
        [[ "$protocol" == "ssh" ]] && userdel -f "$uname" 2>/dev/null
        rm -f "$f" "$PUBLIC_HTML/${fname}.txt" "$PUBLIC_HTML/${fname}-clash.yaml"
    fi
done
shopt -u nullglob
systemctl restart xray 2>/dev/null
DELEOF
                chmod +x /usr/local/bin/vpn-delete-expired.sh
                (crontab -l 2>/dev/null | grep -v "vpn-delete-expired"; \
                 echo "0 0 * * * /usr/local/bin/vpn-delete-expired.sh >> /var/log/vpn-expired.log 2>&1") | crontab -
                echo -e "  ${GREEN}✔ Auto delete expired aktif jam 00:00 setiap hari!${NC}"
                sleep 2
                ;;
            2)
                (crontab -l 2>/dev/null | grep -v "restart xray"; \
                 echo "0 4 * * * systemctl restart xray >> /var/log/vpn-cron.log 2>&1") | crontab -
                echo -e "  ${GREEN}✔ Auto restart Xray jam 04:00 aktif!${NC}"
                sleep 2
                ;;
            3)
                (crontab -l 2>/dev/null | grep -v "restart-all-vpn"; \
                 echo "0 3 * * * systemctl restart xray nginx haproxy dropbear >> /var/log/vpn-cron.log 2>&1 # restart-all-vpn") | crontab -
                echo -e "  ${GREEN}✔ Auto restart semua service jam 03:00 aktif!${NC}"
                sleep 2
                ;;
            4)
                [[ -f "$DOMAIN_FILE" ]] && DOMAIN=$(tr -d '\n\r' < "$DOMAIN_FILE" | xargs)
                if [[ -z "$DOMAIN" ]]; then
                    echo -e "  ${RED}✘ Domain belum diset!${NC}"; sleep 2; continue
                fi
                (crontab -l 2>/dev/null | grep -v "certbot renew"; \
                 echo "0 0 1 * * certbot renew --quiet && cp /etc/letsencrypt/live/${DOMAIN}/fullchain.pem /etc/xray/xray.crt && cp /etc/letsencrypt/live/${DOMAIN}/privkey.pem /etc/xray/xray.key && systemctl restart xray haproxy nginx >> /var/log/vpn-ssl-renew.log 2>&1") | crontab -
                echo -e "  ${GREEN}✔ Auto renew SSL tanggal 1 setiap bulan aktif!${NC}"
                sleep 2
                ;;
            5)
                (crontab -l 2>/dev/null | grep -v "vpn-backup"; \
                 echo "0 2 * * * tar -czf /root/backups/vpn-backup-\$(date +\%Y\%m\%d).tar.gz /root/akun /root/domain /usr/local/etc/xray/config.json /etc/xray 2>/dev/null && find /root/backups -name '*.tar.gz' -mtime +7 -delete") | crontab -
                echo -e "  ${GREEN}✔ Auto backup jam 02:00 aktif!${NC}"
                sleep 2
                ;;
            6)
                (crontab -l 2>/dev/null | grep -v "xray-log-clean"; \
                 echo "0 1 * * * truncate -s 0 /var/log/xray/access.log /var/log/xray/error.log 2>/dev/null # xray-log-clean") | crontab -
                echo -e "  ${GREEN}✔ Auto bersihkan log Xray jam 01:00 aktif!${NC}"
                sleep 2
                ;;
            7)
                echo -e "  ${YELLOW}Format cron: menit jam hari bulan hari-minggu perintah${NC}"
                echo -e "  ${DIM}Contoh: 0 4 * * * systemctl restart xray${NC}"
                echo ""
                read -p "  Cron expression: " custom_cron
                [[ -z "$custom_cron" ]] && continue
                (crontab -l 2>/dev/null; echo "$custom_cron") | crontab -
                echo -e "  ${GREEN}✔ Cron ditambahkan!${NC}"
                sleep 2
                ;;
            8)
                clear
                print_menu_header "HAPUS CRON TERTENTU"
                crontab -l 2>/dev/null | grep -v "^#" | grep -v "^$" | nl -ba
                echo ""
                read -p "  Nomor baris yang mau dihapus: " linenum
                [[ ! "$linenum" =~ ^[0-9]+$ ]] && continue
                # Hapus baris ke-N
                crontab -l 2>/dev/null | grep -v "^#" | grep -v "^$" | \
                    sed "${linenum}d" | crontab -
                echo -e "  ${GREEN}✔ Cron baris ${linenum} dihapus!${NC}"
                sleep 2
                ;;
            9)
                read -p "  Yakin hapus semua cron? [y/N]: " yn
                [[ "$yn" != "y" ]] && continue
                crontab -r 2>/dev/null
                echo -e "  ${GREEN}✔ Semua cron dihapus!${NC}"
                sleep 2
                ;;
            0) return ;;
        esac
    done
}

# ================================================
# [12] SYSTEM LOGS - DENGAN FILTER & SEARCH
# ================================================
_adv_system_logs() {
    while true; do
        clear
        print_menu_header "SYSTEM LOGS VIEWER"

        # Tampilkan ukuran log
        echo -e "  ${CYAN}── UKURAN LOG FILES ──────────────────────────────${NC}"
        for logfile in /var/log/xray/access.log /var/log/xray/error.log /var/log/nginx/error.log /var/log/auth.log; do
            if [[ -f "$logfile" ]]; then
                local sz; sz=$(du -h "$logfile" | awk '{print $1}')
                printf "  ${GREEN}%-40s${NC} ${CYAN}%s${NC}\n" "$(basename $logfile)" "$sz"
            fi
        done
        echo ""

        echo -e "  ${WHITE}[1]${NC} Xray Access Log (tail 50)"
        echo -e "  ${WHITE}[2]${NC} Xray Error Log (tail 50)"
        echo -e "  ${WHITE}[3]${NC} Nginx Error Log"
        echo -e "  ${WHITE}[4]${NC} SSH Auth Log (login/fail)"
        echo -e "  ${WHITE}[5]${NC} System Journal (journalctl)"
        echo -e "  ${WHITE}[6]${NC} Cari di log (grep)"
        echo -e "  ${WHITE}[7]${NC} Monitor log real-time (tail -f)"
        echo -e "  ${WHITE}[8]${NC} Bersihkan log (truncate)"
        echo -e "  ${WHITE}[9]${NC} Lihat log service tertentu"
        echo -e "  ${WHITE}[0]${NC} Back"
        echo ""
        read -p "  Select: " c
        case $c in
            1)
                clear
                echo -e "  ${CYAN}── XRAY ACCESS LOG (50 baris terakhir) ──${NC}"
                tail -50 /var/log/xray/access.log 2>/dev/null || echo "  Log kosong/tidak ada"
                pause
                ;;
            2)
                clear
                echo -e "  ${CYAN}── XRAY ERROR LOG (50 baris terakhir) ──${NC}"
                tail -50 /var/log/xray/error.log 2>/dev/null || echo "  Log kosong/tidak ada"
                pause
                ;;
            3)
                clear
                echo -e "  ${CYAN}── NGINX ERROR LOG ──${NC}"
                tail -50 /var/log/nginx/error.log 2>/dev/null || echo "  Log kosong/tidak ada"
                pause
                ;;
            4)
                clear
                echo -e "  ${CYAN}── SSH AUTH LOG ──${NC}"
                echo -e "  ${YELLOW}Login berhasil:${NC}"
                grep -i "accepted\|session opened" /var/log/auth.log 2>/dev/null | tail -20
                echo ""
                echo -e "  ${RED}Login GAGAL:${NC}"
                grep -i "failed\|invalid\|refused" /var/log/auth.log 2>/dev/null | tail -20
                pause
                ;;
            5)
                clear
                echo -e "  ${CYAN}── SYSTEM JOURNAL ──${NC}"
                journalctl -n 50 --no-pager 2>/dev/null
                pause
                ;;
            6)
                clear; print_menu_header "CARI DI LOG"
                echo -e "  Pilih log:"
                echo -e "  ${WHITE}[1]${NC} Xray Access  ${WHITE}[2]${NC} Xray Error  ${WHITE}[3]${NC} Auth  ${WHITE}[4]${NC} Nginx"
                read -p "  Log: " logchoice
                local logpath
                case $logchoice in
                    1) logpath="/var/log/xray/access.log" ;;
                    2) logpath="/var/log/xray/error.log" ;;
                    3) logpath="/var/log/auth.log" ;;
                    4) logpath="/var/log/nginx/error.log" ;;
                    *) continue ;;
                esac
                read -p "  Kata kunci pencarian: " keyword
                [[ -z "$keyword" ]] && continue
                clear
                echo -e "  ${CYAN}── Hasil pencarian '${keyword}' di $(basename $logpath) ──${NC}"
                grep -i --color=always "$keyword" "$logpath" 2>/dev/null | tail -50 || \
                    echo -e "  ${YELLOW}Tidak ditemukan${NC}"
                pause
                ;;
            7)
                clear; print_menu_header "MONITOR LOG REAL-TIME"
                echo -e "  Pilih log:"
                echo -e "  ${WHITE}[1]${NC} Xray Access  ${WHITE}[2]${NC} Xray Error  ${WHITE}[3]${NC} Auth  ${WHITE}[4]${NC} Nginx  ${WHITE}[5]${NC} All Xray"
                read -p "  Log (tekan Ctrl+C untuk stop): " logchoice2
                case $logchoice2 in
                    1) tail -f /var/log/xray/access.log 2>/dev/null ;;
                    2) tail -f /var/log/xray/error.log 2>/dev/null ;;
                    3) tail -f /var/log/auth.log 2>/dev/null ;;
                    4) tail -f /var/log/nginx/error.log 2>/dev/null ;;
                    5) tail -f /var/log/xray/access.log /var/log/xray/error.log 2>/dev/null ;;
                esac
                ;;
            8)
                clear; print_menu_header "BERSIHKAN LOG"
                echo -e "  ${YELLOW}Pilih log yang mau dibersihkan:${NC}"
                echo -e "  ${WHITE}[1]${NC} Xray Access Log"
                echo -e "  ${WHITE}[2]${NC} Xray Error Log"
                echo -e "  ${WHITE}[3]${NC} Semua log Xray"
                echo -e "  ${WHITE}[4]${NC} Nginx Error Log"
                echo -e "  ${WHITE}[5]${NC} Semua log VPN"
                read -p "  Select: " lc
                case $lc in
                    1) truncate -s 0 /var/log/xray/access.log 2>/dev/null; echo -e "  ${GREEN}✔ Xray access log dibersihkan!${NC}" ;;
                    2) truncate -s 0 /var/log/xray/error.log 2>/dev/null; echo -e "  ${GREEN}✔ Xray error log dibersihkan!${NC}" ;;
                    3) truncate -s 0 /var/log/xray/access.log /var/log/xray/error.log 2>/dev/null; echo -e "  ${GREEN}✔ Semua log Xray dibersihkan!${NC}" ;;
                    4) truncate -s 0 /var/log/nginx/error.log 2>/dev/null; echo -e "  ${GREEN}✔ Nginx log dibersihkan!${NC}" ;;
                    5)
                        truncate -s 0 /var/log/xray/access.log /var/log/xray/error.log /var/log/nginx/error.log 2>/dev/null
                        echo -e "  ${GREEN}✔ Semua log VPN dibersihkan!${NC}"
                        ;;
                esac
                sleep 2
                ;;
            9)
                read -p "  Nama service (contoh: xray/nginx/haproxy/dropbear): " svcname
                [[ -z "$svcname" ]] && continue
                clear
                echo -e "  ${CYAN}── LOG: ${svcname} ──${NC}"
                journalctl -u "$svcname" -n 100 --no-pager 2>/dev/null || \
                    echo -e "  ${RED}✘ Service tidak ditemukan${NC}"
                pause
                ;;
            0) return ;;
        esac
    done
}

# ================================================
# MAIN ADVANCED MENU
# ================================================
menu_advanced() {
    while true; do
        clear
        local W; W=$(get_width)
        printf "${CYAN}╔"; printf '═%.0s' $(seq 1 $((W-2))); printf "╗${NC}\n"
        printf "${CYAN}║${NC}  ${YELLOW}${BOLD}%-$((W-4))s${NC}${CYAN}║${NC}\n" "⚙  ADVANCED SETTINGS - YOUZIN CRABZ TUNEL"
        printf "${CYAN}╚"; printf '═%.0s' $(seq 1 $((W-2))); printf "╝${NC}\n"
        echo ""
        printf "  ${WHITE}[1]${NC}  %-28s ${WHITE}[7]${NC}  %s\n"  "Port Management"       "Firewall Rules (UFW)"
        printf "  ${WHITE}[2]${NC}  %-28s ${WHITE}[8]${NC}  %s\n"  "Protocol Settings"     "Bandwidth Monitor"
        printf "  ${WHITE}[3]${NC}  %-28s ${WHITE}[9]${NC}  %s\n"  "Auto Backup"           "User IP Limits"
        printf "  ${WHITE}[4]${NC}  %-28s ${WHITE}[10]${NC} %s\n"  "SSH Brute Protection"  "Custom Payload"
        printf "  ${WHITE}[5]${NC}  %-28s ${WHITE}[11]${NC} %s\n"  "Fail2Ban Management"   "Cron Jobs Manager"
        printf "  ${WHITE}[6]${NC}  %-28s ${WHITE}[12]${NC} %s\n"  "DDoS Protection"       "System Logs Viewer"
        echo ""
        printf "  ${RED}[0]${NC}  Back to Main Menu\n"
        echo ""
        read -p "  Select [0-12]: " choice

        case $choice in
            1)  _adv_port_management ;;
            2)  _adv_protocol_settings ;;
            3)  _adv_auto_backup ;;
            4)  _adv_ssh_brute_protection ;;
            5)  _adv_fail2ban ;;
            6)  _adv_ddos_protection ;;
            7)  _adv_firewall ;;
            8)  _adv_bandwidth_monitor ;;
            9)  _adv_user_limits ;;
            10) _adv_custom_payload ;;
            11) _adv_cron_jobs ;;
            12) _adv_system_logs ;;
            0)  return ;;
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
BUF      = 8192
TIMEOUT  = 10

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
RestartSec=3
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
    sleep 2
}

#================================================
# SETUP TELEGRAM BOT
#================================================

setup_telegram_bot() {
    clear
    print_menu_header "SETUP TELEGRAM BOT"
    echo -e "  ${YELLOW}Cara mendapatkan Bot Token:${NC}"
    echo -e "  1. Buka Telegram cari ${WHITE}@BotFather${NC}"
    echo -e "  2. Ketik /newbot ikuti instruksi"
    echo -e "  3. Copy TOKEN yang diberikan"
    echo ""
    echo -e "  ${YELLOW}Cara mendapatkan Chat ID:${NC}"
    echo -e "  1. Cari ${WHITE}@userinfobot${NC} di Telegram"
    echo -e "  2. Ketik /start lihat ID kamu"
    echo ""
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
    bot_name=$(echo "$test_result" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print(d['result']['username'])
" 2>/dev/null)
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
            -d text="✅ Youzin Crabz Tunel Bot Aktif!
Domain: ${DOMAIN}
Powered by The Professor" \
            -d parse_mode="HTML" \
            --max-time 10 >/dev/null 2>&1
    else
        echo -e "  ${RED}✘ Bot gagal start!${NC}"
        journalctl -u vpn-bot -n 10 --no-pager
    fi
    echo ""
    pause
}

#================================================
# INSTALL BOT SERVICE (Python bot)
#================================================

_install_bot_service() {
    mkdir -p /root/bot "$ORDER_DIR"
    pip3 install requests --break-system-packages >/dev/null 2>&1 || \
        pip3 install requests >/dev/null 2>&1

    cat > /root/bot/bot.py << 'BOTEOF'
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, json, time, subprocess
import threading
from datetime import datetime, timedelta

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    os.system('pip3 install requests --break-system-packages -q')
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry

TOKEN     = open('/root/.bot_token').read().strip()
ADMIN_ID  = int(open('/root/.chat_id').read().strip())
DOMAIN    = open('/root/domain').read().strip() if os.path.exists('/root/domain') else 'N/A'
ORDER_DIR = '/root/orders'
AKUN_DIR  = '/root/akun'
HTML_DIR  = '/var/www/html'
API       = f'https://api.telegram.org/bot{TOKEN}'

os.makedirs(ORDER_DIR, exist_ok=True)
os.makedirs(AKUN_DIR,  exist_ok=True)
os.makedirs(HTML_DIR,  exist_ok=True)

user_state = {}
state_lock = threading.Lock()

def make_session():
    s = requests.Session()
    retry = Retry(total=2, backoff_factor=0.3, status_forcelist=[500,502,503,504])
    adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=50)
    s.mount('https://', adapter)
    s.mount('http://', adapter)
    return s

SESSION = make_session()

def get_payment():
    info = {'REK_NAME':'N/A','REK_NUMBER':'N/A','REK_BANK':'N/A','HARGA':'10000'}
    try:
        with open('/root/.payment_info') as f:
            for line in f:
                line = line.strip()
                if '=' in line:
                    k,v = line.split('=',1)
                    info[k.strip()] = v.strip()
    except: pass
    return info

def api_post(method, data, timeout=6):
    try:
        r = SESSION.post(f'{API}/{method}', data=data, timeout=timeout)
        return r.json()
    except Exception as e:
        print(f'API {method}: {e}', flush=True)
        return {}

def send(chat_id, text, markup=None, parse_mode='HTML'):
    data = {'chat_id':chat_id,'text':text,'parse_mode':parse_mode}
    if markup: data['reply_markup'] = json.dumps(markup)
    return api_post('sendMessage', data)

def answer_cb(cb_id, text='', alert=False):
    api_post('answerCallbackQuery', {'callback_query_id':cb_id,'text':text,'show_alert':alert})

def get_updates(offset=0):
    try:
        r = SESSION.get(f'{API}/getUpdates', params={'offset':offset,'timeout':15,'limit':100}, timeout=20)
        return r.json().get('result', [])
    except: return []

def kb_main():
    return {'keyboard':[
        ['🆓 Trial Gratis','🛒 Order VPN'],
        ['📋 Cek Akun Saya','ℹ️ Info Server'],
        ['❓ Bantuan','📞 Hubungi Admin']
    ],'resize_keyboard':True,'one_time_keyboard':False}

def kb_trial():
    return {'inline_keyboard':[
        [{'text':'🔵 SSH','callback_data':'trial_ssh'},{'text':'🟢 VMess','callback_data':'trial_vmess'}],
        [{'text':'🟡 VLess','callback_data':'trial_vless'},{'text':'🔴 Trojan','callback_data':'trial_trojan'}],
        [{'text':'◀️ Kembali','callback_data':'back_main'}]
    ]}

def kb_order():
    return {'inline_keyboard':[
        [{'text':'🔵 SSH','callback_data':'order_ssh'},{'text':'🟢 VMess','callback_data':'order_vmess'}],
        [{'text':'🟡 VLess','callback_data':'order_vless'},{'text':'🔴 Trojan','callback_data':'order_trojan'}],
        [{'text':'◀️ Kembali','callback_data':'back_main'}]
    ]}

def kb_confirm(order_id):
    return {'inline_keyboard':[[
        {'text':'✅ Konfirmasi','callback_data':f'confirm_{order_id}'},
        {'text':'❌ Tolak','callback_data':f'reject_{order_id}'}
    ]]}

def kb_cancel():
    return {'inline_keyboard':[[{'text':'❌ Batalkan','callback_data':'cancel_order'}]]}

def get_ip():
    for url in ['https://ifconfig.me','https://ipinfo.io/ip','https://api.ipify.org']:
        try:
            r = SESSION.get(url, timeout=3)
            if r.status_code == 200: return r.text.strip()
        except: pass
    return 'N/A'

def run_cmd(cmd):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=90)
        return r.stdout.strip()
    except Exception as e:
        print(f'CMD: {e}', flush=True)
        return ''

def save_order(oid, data):
    with open(f'{ORDER_DIR}/{oid}.json','w') as f: json.dump(data, f, indent=2)

def load_order(oid):
    p = f'{ORDER_DIR}/{oid}.json'
    if not os.path.exists(p): return None
    with open(p) as f: return json.load(f)

def make_ssh(username, password, days=30):
    exp_date = (datetime.now() + timedelta(days=days)).strftime('%Y-%m-%d')
    exp_str = (datetime.now() + timedelta(days=days)).strftime('%d %b, %Y')
    created = datetime.now().strftime('%d %b, %Y')
    run_cmd(f'useradd -M -s /bin/false -e {exp_date} {username} 2>/dev/null')
    run_cmd(f'echo "{username}:{password}" | chpasswd')
    with open(f'{AKUN_DIR}/ssh-{username}.txt','w') as f:
        f.write(f'USERNAME={username}\nPASSWORD={password}\nIPLIMIT=1\nEXPIRED={exp_str}\nCREATED={created}\n')
    ip = get_ip()
    with open(f'{HTML_DIR}/ssh-{username}.txt','w') as f:
        f.write(f'YOUZIN CRABZ TUNEL - SSH\nUsername: {username}\nPassword: {password}\nExpired: {exp_str}\n')
    return exp_str, ip

def make_xray(protocol, username, days=30, quota=100):
    import uuid as uuidlib, base64
    uid = str(uuidlib.uuid4())
    exp_str = (datetime.now() + timedelta(days=days)).strftime('%d %b, %Y')
    created = datetime.now().strftime('%d %b, %Y')
    cfg = '/usr/local/etc/xray/config.json'
    if protocol == 'trojan':
        cmd = f'jq --arg pw "{uid}" --arg em "{username}" \'(.inbounds[] | select(.tag | startswith("trojan")).settings.clients) += [{{"password":$pw,"email":$em}}]\' {cfg} > /tmp/_xr.json && mv /tmp/_xr.json {cfg} && chmod 644 {cfg} && systemctl restart xray'
    elif protocol == 'vless':
        cmd = f'jq --arg uid "{uid}" --arg em "{username}" \'(.inbounds[] | select(.tag | startswith("vless")).settings.clients) += [{{"id":$uid,"email":$em}}]\' {cfg} > /tmp/_xr.json && mv /tmp/_xr.json {cfg} && chmod 644 {cfg} && systemctl restart xray'
    else:
        cmd = f'jq --arg uid "{uid}" --arg em "{username}" \'(.inbounds[] | select(.tag | startswith("vmess")).settings.clients) += [{{"id":$uid,"email":$em,"alterId":0}}]\' {cfg} > /tmp/_xr.json && mv /tmp/_xr.json {cfg} && chmod 644 {cfg} && systemctl restart xray'
    run_cmd(cmd)
    with open(f'{AKUN_DIR}/{protocol}-{username}.txt','w') as f:
        f.write(f'UUID={uid}\nQUOTA={quota}\nIPLIMIT=1\nEXPIRED={exp_str}\nCREATED={created}\n')
    ip = get_ip()
    if protocol == 'vmess':
        j_tls = f'{{"v":"2","ps":"{username}","add":"bug.com","port":"443","id":"{uid}","aid":"0","net":"ws","path":"/{protocol}","type":"none","host":"{DOMAIN}","tls":"tls"}}'
        link_tls = "vmess://" + base64.b64encode(j_tls.encode()).decode()
        j_ntls = f'{{"v":"2","ps":"{username}","add":"bug.com","port":"80","id":"{uid}","aid":"0","net":"ws","path":"/{protocol}","type":"none","host":"{DOMAIN}","tls":"none"}}'
        link_ntls = "vmess://" + base64.b64encode(j_ntls.encode()).decode()
        j_grpc = f'{{"v":"2","ps":"{username}","add":"{DOMAIN}","port":"443","id":"{uid}","aid":"0","net":"grpc","path":"{protocol}-grpc","type":"none","host":"bug.com","tls":"tls"}}'
        link_grpc = "vmess://" + base64.b64encode(j_grpc.encode()).decode()
    elif protocol == 'vless':
        link_tls = f"vless://{uid}@bug.com:443?path=%2F{protocol}&security=tls&encryption=none&host={DOMAIN}&type=ws&sni={DOMAIN}#{username}-TLS"
        link_ntls = f"vless://{uid}@bug.com:80?path=%2F{protocol}&security=none&encryption=none&host={DOMAIN}&type=ws#{username}-NonTLS"
        link_grpc = f"vless://{uid}@{DOMAIN}:443?mode=gun&security=tls&encryption=none&type=grpc&serviceName={protocol}-grpc&sni=bug.com#{username}-gRPC"
    else:
        link_tls = f"trojan://{uid}@bug.com:443?path=%2F{protocol}&security=tls&host={DOMAIN}&type=ws&sni={DOMAIN}#{username}-TLS"
        link_ntls = f"trojan://{uid}@bug.com:80?path=%2F{protocol}&security=none&host={DOMAIN}&type=ws#{username}-NonTLS"
        link_grpc = f"trojan://{uid}@{DOMAIN}:443?mode=gun&security=tls&type=grpc&serviceName={protocol}-grpc&sni=bug.com#{username}-gRPC"
    return (uid, exp_str, ip, link_tls, link_ntls, link_grpc)

def fmt_ssh_msg(username, password, ip, exp_str, title, durasi="30 Hari"):
    return f'''✅ <b>{title}</b>
━━━━━━━━━━━━━━━━━━━━━━━━━
👤 Username : <code>{username}</code>
🔑 Password : <code>{password}</code>
🌐 Domain   : <code>{DOMAIN}</code>
🖥️ IP VPS   : <code>{ip}</code>
━━━━━━━━━━━━━━━━━━━━━━━━━
⏰ Aktif    : {durasi}
📅 Expired  : {exp_str}
━━━━━━━━━━━━━━━━━━━━━━━━━
<i>The Professor</i>'''

def fmt_xray_msg(protocol, username, uid, ip, exp_str, link_tls, link_ntls, link_grpc, title, durasi="30 Hari"):
    return f'''✅ <b>{title}</b>
━━━━━━━━━━━━━━━━━━━━━━━━━
👤 Username : <code>{username}</code>
🔑 UUID     : <code>{uid}</code>
🌐 Domain   : <code>{DOMAIN}</code>
🖥️ IP VPS   : <code>{ip}</code>
━━━━━━━━━━━━━━━━━━━━━━━━━
🔗 <b>Link TLS:</b>
<code>{link_tls}</code>
━━━━━━━━━━━━━━━━━━━━━━━━━
🔗 <b>Link NonTLS:</b>
<code>{link_ntls}</code>
━━━━━━━━━━━━━━━━━━━━━━━━━
🔗 <b>Link gRPC:</b>
<code>{link_grpc}</code>
━━━━━━━━━━━━━━━━━━━━━━━━━
⏰ Aktif  : {durasi}
📅 Expired: {exp_str}
━━━━━━━━━━━━━━━━━━━━━━━━━
<i>The Professor</i>'''

def do_trial(protocol, chat_id):
    ts = datetime.now().strftime('%H%M%S')
    username = f'trial-{ts}'
    ip = get_ip()
    exp_1h = (datetime.now() + timedelta(hours=1)).strftime('%d %b %Y %H:%M')
    if protocol == 'ssh':
        password = '1'
        exp_date = (datetime.now() + timedelta(days=1)).strftime('%Y-%m-%d')
        run_cmd(f'useradd -M -s /bin/false -e {exp_date} {username} 2>/dev/null')
        run_cmd(f'echo "{username}:{password}" | chpasswd')
        run_cmd(f'(sleep 3600; userdel -f {username} 2>/dev/null; rm -f {AKUN_DIR}/ssh-{username}.txt {HTML_DIR}/ssh-{username}.txt) & disown')
        msg = fmt_ssh_msg(username, password, ip, exp_1h, 'Trial SSH Berhasil! 🆓', '1 Jam (Auto Hapus)')
        msg += '\n⚠️ <i>Auto hapus setelah 1 jam</i>'
        send(chat_id, msg, markup=kb_main())
    else:
        try:
            uid, _, ip, link_tls, link_ntls, link_grpc = make_xray(protocol, username, days=1, quota=1)
        except Exception as e:
            send(chat_id, f'❌ Gagal buat akun: {e}')
            return
        del_cmd = f'(sleep 3600; jq --arg email "{username}" \'del(.inbounds[].settings.clients[]? | select(.email == $email))\' /usr/local/etc/xray/config.json > /tmp/xd.json && mv /tmp/xd.json /usr/local/etc/xray/config.json; chmod 644 /usr/local/etc/xray/config.json; systemctl restart xray; rm -f {AKUN_DIR}/{protocol}-{username}.txt {HTML_DIR}/{protocol}-{username}.txt) & disown'
        run_cmd(del_cmd)
        msg = fmt_xray_msg(protocol, username, uid, ip, exp_1h, link_tls, link_ntls, link_grpc, f'Trial {protocol.upper()} Berhasil! 🆓', '1 Jam (Auto Hapus)')
        msg += '\n⚠️ <i>Auto hapus setelah 1 jam</i>'
        send(chat_id, msg, markup=kb_main())

def deliver_account(chat_id, protocol, username):
    import random, string
    try:
        if protocol == 'ssh':
            password = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
            exp_str, ip = make_ssh(username, password, days=30)
            msg = fmt_ssh_msg(username, password, ip, exp_str, 'Akun SSH Berhasil! ✅')
        else:
            uid, exp_str, ip, link_tls, link_ntls, link_grpc = make_xray(protocol, username, days=30, quota=100)
            msg = fmt_xray_msg(protocol, username, uid, ip, exp_str, link_tls, link_ntls, link_grpc, f'Akun {protocol.upper()} Berhasil! ✅')
        msg += '\n💰 Terima kasih! 🙏'
        send(chat_id, msg, markup=kb_main())
        return True, msg
    except Exception as e:
        return False, str(e)

def on_start(msg):
    chat_id = msg['chat']['id']
    fname = msg['from'].get('first_name','User')
    send(chat_id, f'👋 Halo <b>{fname}</b>!\n\n🤖 <b>Youzin Crabz Tunel Bot</b>\n🌐 Server: <code>{DOMAIN}</code>\n<i>Powered by The Professor</i>\n\nPilih menu 👇', markup=kb_main())

def on_info(msg):
    chat_id = msg['chat']['id']
    ip = get_ip()
    send(chat_id, f'ℹ️ <b>INFO SERVER</b>\n🌐 Domain : <code>{DOMAIN}</code>\n🖥️ IP VPS : <code>{ip}</code>\n🔌 SSH: 22 | Dropbear: 222\n🔌 TLS: 443 | NonTLS: 80 | gRPC: 443', markup=kb_main())

def on_cek_akun(msg):
    chat_id = msg['chat']['id']
    found = []
    if not os.path.exists(ORDER_DIR):
        send(chat_id, '📋 Tidak ada akun aktif.', markup=kb_main()); return
    for fn in os.listdir(ORDER_DIR):
        if not fn.endswith('.json'): continue
        try:
            with open(f'{ORDER_DIR}/{fn}') as f: order = json.load(f)
            if str(order.get('chat_id')) == str(chat_id) and order.get('status') == 'confirmed':
                found.append(order)
        except: pass
    if not found:
        send(chat_id, '📋 Tidak ada akun aktif.\nGunakan 🛒 Order VPN.', markup=kb_main()); return
    text = '📋 <b>Akun Aktif Kamu</b>\n━━━━━━━━━━━━━━━━━━━━━━━━━\n'
    for a in found: text += f'📦 {a["protocol"].upper()} → {a["username"]}\n'
    send(chat_id, text, markup=kb_main())

def on_contact(msg):
    chat_id = msg['chat']['id']
    fname = msg['from'].get('first_name','User')
    uname = msg['from'].get('username','')
    send(chat_id, '📞 Pesan diteruskan ke admin.', markup=kb_main())
    send(ADMIN_ID, f'📞 <b>User butuh bantuan!</b>\n👤 {fname}\n📱 @{uname}\n🆔 <code>{chat_id}</code>')

def on_callback(cb):
    chat_id = cb['message']['chat']['id']
    cb_id = cb['id']
    data = cb['data']
    uname = cb['from'].get('username','')
    fname = cb['from'].get('first_name','User')
    answer_cb(cb_id)
    if data.startswith('trial_'):
        protocol = data.replace('trial_','')
        send(chat_id, f'⏳ Membuat trial {protocol.upper()}...')
        threading.Thread(target=do_trial, args=(protocol, chat_id), daemon=True).start()
    elif data.startswith('order_'):
        protocol = data.replace('order_','')
        with state_lock: user_state[chat_id] = {'step':'wait_username','protocol':protocol}
        send(chat_id, f'🛒 <b>Order {protocol.upper()}</b>\n✏️ Ketik username (3-20 karakter):', markup=kb_cancel())
    elif data == 'cancel_order':
        with state_lock: user_state.pop(chat_id, None)
        send(chat_id, '❌ Order dibatalkan.', markup=kb_main())
    elif data == 'back_main':
        send(chat_id, '🏠 Menu Utama', markup=kb_main())
    elif data.startswith('confirm_') and chat_id == ADMIN_ID:
        oid = data.replace('confirm_','')
        order = load_order(oid)
        if not order: send(ADMIN_ID,'❌ Order tidak ada!'); return
        if order.get('status') != 'pending': send(ADMIN_ID,'⚠️ Sudah diproses!'); return
        send(ADMIN_ID,'⏳ Membuat akun...')
        def do_confirm():
            ok, result = deliver_account(order['chat_id'], order['protocol'], order['username'])
            if ok:
                order['status'] = 'confirmed'
                save_order(oid, order)
                send(ADMIN_ID, f'✅ Akun dikirim ke @{order.get("tg_user","?")}')
            else: send(ADMIN_ID, f'❌ Gagal: {result}')
        threading.Thread(target=do_confirm, daemon=True).start()
    elif data.startswith('reject_') and chat_id == ADMIN_ID:
        oid = data.replace('reject_','')
        order = load_order(oid)
        if not order: send(ADMIN_ID,'❌ Tidak ada!'); return
        order['status'] = 'rejected'
        save_order(oid, order)
        send(order['chat_id'], '❌ Order ditolak. Hubungi admin.', markup=kb_main())
        send(ADMIN_ID, f'❌ Order ditolak.')

def on_msg(msg):
    if 'text' not in msg: return
    chat_id = msg['chat']['id']
    text = msg['text'].strip()
    with state_lock: state = user_state.get(chat_id, {})
    if state.get('step') == 'wait_username':
        new_u = text.strip().replace(' ','_')
        if len(new_u) < 3 or len(new_u) > 20:
            send(chat_id, '❌ Username 3-20 karakter!', markup=kb_cancel()); return
        protocol = state['protocol']
        oid = f'{chat_id}_{int(time.time())}'
        fname = msg['from'].get('first_name','User')
        uname = msg['from'].get('username','')
        order = {'order_id':oid,'chat_id':chat_id,'username':new_u,'protocol':protocol,'status':'pending','created_at':datetime.now().isoformat(),'tg_user':uname,'tg_name':fname}
        save_order(oid, order)
        with state_lock: user_state.pop(chat_id, None)
        pay = get_payment()
        harga = int(pay.get('HARGA',10000))
        send(chat_id, f'🛒 <b>Detail Order</b>\n🆔 Order ID: <code>{oid}</code>\n📦 Paket: {protocol.upper()} 30 Hari\n👤 Username: <code>{new_u}</code>\n💰 Nominal: <b>Rp {harga:,}</b>\n<i>Transfer lalu kirim bukti ke admin</i>')
        send(ADMIN_ID, f'🔔 <b>ORDER BARU!</b>\n🆔 {oid}\n📦 {protocol.upper()}\n👤 <code>{new_u}</code>\n📱 @{uname}\n💰 Rp {harga:,}', markup=kb_confirm(oid))
        return
    with state_lock: user_state.pop(chat_id, None)
    if text in ['/start','🏠 Menu']: on_start(msg)
    elif text == '🆓 Trial Gratis': send(chat_id, '🆓 <b>Trial Gratis 1 Jam</b>\nPilih protocol:', markup=kb_trial())
    elif text == '🛒 Order VPN': send(chat_id, '🛒 <b>Order VPN 30 Hari</b>\nPilih protocol:', markup=kb_order())
    elif text == '📋 Cek Akun Saya': on_cek_akun(msg)
    elif text == 'ℹ️ Info Server': on_info(msg)
    elif text == '📞 Hubungi Admin': on_contact(msg)
    elif text in ['/help','❓ Bantuan']:
        send(chat_id, '❓ <b>PANDUAN BOT</b>\n\n🆓 Trial → Akun 1 jam gratis\n🛒 Order → Beli akun 30 hari\n📋 Cek → Lihat akun aktif\nℹ️ Info → Port & domain', markup=kb_main())

def main():
    print(f'Youzin Crabz Tunel Bot aktif!', flush=True)
    offset = 0
    pool = []
    while True:
        try:
            updates = get_updates(offset)
            for upd in updates:
                offset = upd['update_id'] + 1
                t = None
                if 'message' in upd: t = threading.Thread(target=on_msg, args=(upd['message'],), daemon=True)
                elif 'callback_query' in upd: t = threading.Thread(target=on_callback, args=(upd['callback_query'],), daemon=True)
                if t: t.start(); pool.append(t)
            pool = [x for x in pool if x.is_alive()]
        except KeyboardInterrupt: break
        except Exception as e: print(f'Loop: {e}', flush=True); time.sleep(2)

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
RestartSec=3
StandardOutput=journal
StandardError=journal
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
SVCEOF

    systemctl daemon-reload
    systemctl enable vpn-bot 2>/dev/null
    systemctl restart vpn-bot 2>/dev/null
    sleep 2
}

#================================================
# MENU TELEGRAM BOT
#================================================

menu_telegram_bot() {
    while true; do
        clear
        print_menu_header "TELEGRAM BOT"
        local bs; bs=$(check_status vpn-bot)
        local cs
        [[ "$bs" == "ON" ]] && cs="${GREEN}RUNNING${NC}" || cs="${RED}STOPPED${NC}"
        printf "  Status: $(echo -e $cs)\n\n"
        echo -e "  ${WHITE}[1]${NC} Setup Bot"
        echo -e "  ${WHITE}[2]${NC} Start Bot"
        echo -e "  ${WHITE}[3]${NC} Stop Bot"
        echo -e "  ${WHITE}[4]${NC} Restart Bot"
        echo -e "  ${WHITE}[5]${NC} Lihat Log"
        echo -e "  ${WHITE}[6]${NC} Order Pending"
        echo -e "  ${WHITE}[7]${NC} Info Bot"
        echo -e "  ${WHITE}[0]${NC} Back To Menu"
        echo ""
        read -p "  Select: " choice
        case $choice in
            1) setup_telegram_bot ;;
            2) systemctl start vpn-bot && echo -e "  ${GREEN}✔ Started!${NC}"; sleep 2 ;;
            3) systemctl stop vpn-bot && echo -e "  ${YELLOW}Stopped!${NC}"; sleep 2 ;;
            4) systemctl restart vpn-bot && echo -e "  ${GREEN}✔ Restarted!${NC}"; sleep 2 ;;
            5) clear; journalctl -u vpn-bot -n 50 --no-pager; echo ""; pause ;;
            6)
                clear; print_menu_header "ORDER PENDING"
                local found=0
                shopt -s nullglob
                for f in "$ORDER_DIR"/*.json; do
                    [[ ! -f "$f" ]] && continue
                    local st
                    st=$(python3 -c "import json; d=json.load(open('$f')); print(d.get('status',''))" 2>/dev/null)
                    if [[ "$st" == "pending" ]]; then
                        found=1
                        python3 -c "
import json; d=json.load(open('$f'))
print(f'  ID: {d[\"order_id\"]}')
print(f'  Protocol: {d[\"protocol\"].upper()}')
print(f'  Username: {d[\"username\"]}')
print(f'  TG: @{d.get(\"tg_user\",\"N/A\")}')
print('  ---')
" 2>/dev/null
                    fi
                done
                shopt -u nullglob
                [[ $found -eq 0 ]] && echo -e "  ${GREEN}✔ Tidak ada pending!${NC}"
                echo ""; pause
                ;;
            7)
                clear; print_menu_header "BOT INFO"
                if [[ -f "$BOT_TOKEN_FILE" ]]; then
                    local aid; aid=$(cat "$CHAT_ID_FILE" 2>/dev/null)
                    printf "  %-16s : %s\n" "Status"   "$bs"
                    printf "  %-16s : %s\n" "Admin ID" "$aid"
                    if [[ -f "$PAYMENT_FILE" ]]; then
                        source "$PAYMENT_FILE"
                        printf "  %-16s : %s\n" "Bank"      "$REK_BANK"
                        printf "  %-16s : %s\n" "No Rek"    "$REK_NUMBER"
                        printf "  %-16s : Rp %s\n" "Harga"  "$HARGA"
                    fi
                else
                    echo -e "  ${RED}Bot belum setup!${NC}"
                fi
                echo ""; pause
                ;;
            0) return ;;
        esac
    done
}

#================================================
# UNINSTALL MENU
#================================================

menu_uninstall() {
    while true; do
        clear; print_menu_header "UNINSTALL MENU"
        echo -e "  ${WHITE}[1]${NC} Uninstall Xray       ${WHITE}[5]${NC} Uninstall UDP Custom"
        echo -e "  ${WHITE}[2]${NC} Uninstall Nginx      ${WHITE}[6]${NC} Uninstall Bot Telegram"
        echo -e "  ${WHITE}[3]${NC} Uninstall HAProxy    ${WHITE}[7]${NC} Uninstall Keepalive"
        echo -e "  ${WHITE}[4]${NC} Uninstall Dropbear   ${RED}[8]${NC} ${RED}HAPUS SEMUA SCRIPT${NC}"
        echo -e "  ${WHITE}[0]${NC} Back To Menu"
        echo ""
        read -p "  Select: " choice
        case $choice in
            1) _uninstall_xray ;; 2) _uninstall_nginx ;;
            3) _uninstall_haproxy ;; 4) _uninstall_dropbear ;;
            5) _uninstall_udp ;; 6) _uninstall_bot ;;
            7) _uninstall_keepalive ;; 8) _uninstall_all ;;
            0) return ;;
        esac
    done
}

_uninstall_xray() {
    clear; print_menu_header "UNINSTALL XRAY"
    read -p "  Yakin? [y/n]: " c; [[ "$c" != "y" ]] && return
    systemctl stop xray 2>/dev/null; systemctl disable xray 2>/dev/null
    bash <(curl -Ls https://github.com/XTLS/Xray-install/raw/main/install-release.sh) --remove >/dev/null 2>&1
    rm -rf /usr/local/etc/xray /var/log/xray /etc/xray
    echo -e "  ${GREEN}✔ Xray uninstalled!${NC}"; sleep 2
}

_uninstall_nginx() {
    clear; print_menu_header "UNINSTALL NGINX"
    read -p "  Yakin? [y/n]: " c; [[ "$c" != "y" ]] && return
    systemctl stop nginx 2>/dev/null; systemctl disable nginx 2>/dev/null
    apt-get purge -y nginx nginx-common >/dev/null 2>&1
    echo -e "  ${GREEN}✔ Nginx uninstalled!${NC}"; sleep 2
}

_uninstall_haproxy() {
    clear; print_menu_header "UNINSTALL HAPROXY"
    read -p "  Yakin? [y/n]: " c; [[ "$c" != "y" ]] && return
    systemctl stop haproxy 2>/dev/null; systemctl disable haproxy 2>/dev/null
    apt-get purge -y haproxy >/dev/null 2>&1
    echo -e "  ${GREEN}✔ HAProxy uninstalled!${NC}"; sleep 2
}

_uninstall_dropbear() {
    clear; print_menu_header "UNINSTALL DROPBEAR"
    read -p "  Yakin? [y/n]: " c; [[ "$c" != "y" ]] && return
    systemctl stop dropbear 2>/dev/null; systemctl disable dropbear 2>/dev/null
    apt-get purge -y dropbear >/dev/null 2>&1
    echo -e "  ${GREEN}✔ Dropbear uninstalled!${NC}"; sleep 2
}

_uninstall_udp() {
    clear; print_menu_header "UNINSTALL UDP"
    read -p "  Yakin? [y/n]: " c; [[ "$c" != "y" ]] && return
    systemctl stop udp-custom 2>/dev/null; systemctl disable udp-custom 2>/dev/null
    rm -f /etc/systemd/system/udp-custom.service /usr/local/bin/udp-custom
    systemctl daemon-reload
    echo -e "  ${GREEN}✔ UDP uninstalled!${NC}"; sleep 2
}

_uninstall_bot() {
    clear; print_menu_header "UNINSTALL BOT"
    read -p "  Yakin? [y/n]: " c; [[ "$c" != "y" ]] && return
    systemctl stop vpn-bot 2>/dev/null; systemctl disable vpn-bot 2>/dev/null
    rm -f /etc/systemd/system/vpn-bot.service
    rm -rf /root/bot
    rm -f "$BOT_TOKEN_FILE" "$CHAT_ID_FILE" "$PAYMENT_FILE"
    systemctl daemon-reload
    echo -e "  ${GREEN}✔ Bot uninstalled!${NC}"; sleep 2
}

_uninstall_keepalive() {
    clear; print_menu_header "UNINSTALL KEEPALIVE"
    read -p "  Yakin? [y/n]: " c; [[ "$c" != "y" ]] && return
    systemctl stop vpn-keepalive 2>/dev/null; systemctl disable vpn-keepalive 2>/dev/null
    rm -f /etc/systemd/system/vpn-keepalive.service /usr/local/bin/vpn-keepalive.sh
    systemctl daemon-reload
    echo -e "  ${GREEN}✔ Keepalive uninstalled!${NC}"; sleep 2
}

_uninstall_all() {
    clear
    echo -e "${RED}  ╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}  ║         !! HAPUS SEMUA SCRIPT !!                 ║${NC}"
    echo -e "${RED}  ╚══════════════════════════════════════════════════╝${NC}"
    echo ""
    read -p "  Ketik 'HAPUS' untuk konfirmasi: " confirm
    [[ "$confirm" != "HAPUS" ]] && { echo -e "  ${YELLOW}Dibatalkan.${NC}"; sleep 2; return; }
    for svc in xray nginx haproxy dropbear udp-custom vpn-keepalive vpn-bot tunnelbot; do
        systemctl stop "$svc" 2>/dev/null; systemctl disable "$svc" 2>/dev/null
    done
    bash <(curl -Ls https://github.com/XTLS/Xray-install/raw/main/install-release.sh) --remove >/dev/null 2>&1
    apt-get purge -y nginx haproxy dropbear >/dev/null 2>&1
    rm -rf /usr/local/etc/xray /var/log/xray /etc/xray /root/akun /root/bot /root/orders \
           /root/domain /root/.domain_type /root/.bot_token /root/.chat_id /root/.payment_info \
           /root/tunnel.sh.bak /root/backups /opt/tunnel-bot
    rm -f /etc/systemd/system/udp-custom.service \
          /etc/systemd/system/vpn-keepalive.service \
          /etc/systemd/system/vpn-bot.service \
          /etc/systemd/system/tunnelbot.service \
          /usr/local/bin/udp-custom \
          /usr/local/bin/vpn-keepalive.sh \
          /usr/local/bin/vpn-delete-expired.sh \
          /usr/local/bin/menu \
          /root/tunnel.sh
    sed -i '/tunnel.sh/d' /root/.bashrc 2>/dev/null
    systemctl daemon-reload
    echo -e "  ${GREEN}✔ Semua script dihapus!${NC}"
    sleep 3; exit 0
}

#================================================
# AUTO INSTALL
#================================================

_register_vps_to_bot() {
    local VPS_FILE="/root/.tunnelbot_vps"
    local ip_vps; ip_vps=$(get_ip)
    local label="${DOMAIN:-$ip_vps}"
    local secret; secret=$(cat /root/.tunnelbot_secret 2>/dev/null || echo "tunnelsecret")
    local vid; vid=$(echo "$ip_vps" | tr '.' '_')
    python3 - << REGEOF 2>/dev/null
import json
vps_file = "$VPS_FILE"
vid      = "$vid"
ip       = "$ip_vps"
label    = "$label"
secret   = "$secret"
try:
    with open(vps_file) as f:
        data = json.load(f)
except:
    data = {}
data[vid] = {"ip": ip, "secret": secret, "label": label, "domain": label}
with open(vps_file, "w") as f:
    json.dump(data, f, indent=2)
REGEOF
}

_install_tunnelbot_background() {
    local BOT_DIR="/opt/tunnel-bot"
    local BOT_FILE="$BOT_DIR/tunnel-bot.py"
    mkdir -p "$BOT_DIR"
    python3 -c "import uuid; print(uuid.uuid4().hex)" > /root/.tunnelbot_secret 2>/dev/null
    chmod 600 /root/.tunnelbot_secret 2>/dev/null

    cat > "$BOT_FILE" << 'PYEOF'
#!/usr/bin/env python3
import os, json, time, uuid, base64, subprocess, threading
import urllib.request, urllib.parse

TOKEN    = "8216471228:AAHqm7iwcMqEqLjnj2VEqIaZGVQtYyS_4K4"
ADMIN_ID = 8019568852
API      = f"https://api.telegram.org/bot{TOKEN}"
VPS_FILE = "/root/.tunnelbot_vps"

state = {}
lock  = threading.Lock()

def st_get(cid):
    with lock: return dict(state.get(cid, {}))
def st_set(cid, d):
    with lock: state[cid] = d
def st_clear(cid):
    with lock: state.pop(cid, None)

def load_vps():
    try:
        with open(VPS_FILE) as f: return json.load(f)
    except: return {}

def tg(method, data=None, params=None):
    try:
        url = f"{API}/{method}"
        if params: url += "?" + urllib.parse.urlencode(params)
        if data:
            body = json.dumps(data).encode()
            r = urllib.request.urlopen(
                urllib.request.Request(url, body, {"Content-Type":"application/json"}), timeout=10)
        else:
            r = urllib.request.urlopen(url, timeout=10)
        return json.loads(r.read())
    except: return {}

def send(cid, text, markup=None):
    d = {"chat_id": cid, "text": text, "parse_mode": "HTML"}
    if markup: d["reply_markup"] = json.dumps(markup)
    tg("sendMessage", d)

def answer_cb(cb_id):
    tg("answerCallbackQuery", {"callback_query_id": cb_id})

def get_ip():
    for url in ["https://ifconfig.me", "https://api.ipify.org"]:
        try: return urllib.request.urlopen(url, timeout=5).read().decode().strip()
        except: pass
    return "N/A"

def run_local(cmd):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        return r.returncode, r.stdout.strip() + r.stderr.strip()
    except Exception as e: return 1, str(e)

def xray_add(protocol, username):
    uid = str(uuid.uuid4())
    cfg = "/usr/local/etc/xray/config.json"
    if protocol == "trojan":
        cmd = f'jq --arg pw "{uid}" --arg em "{username}" \'(.inbounds[] | select(.tag | startswith("trojan")).settings.clients) += [{{"password":$pw,"email":$em}}]\' {cfg} > /tmp/_xr.json && mv /tmp/_xr.json {cfg} && chmod 644 {cfg} && systemctl restart xray'
    elif protocol == "vless":
        cmd = f'jq --arg uid "{uid}" --arg em "{username}" \'(.inbounds[] | select(.tag | startswith("vless")).settings.clients) += [{{"id":$uid,"email":$em}}]\' {cfg} > /tmp/_xr.json && mv /tmp/_xr.json {cfg} && chmod 644 {cfg} && systemctl restart xray'
    else:
        cmd = f'jq --arg uid "{uid}" --arg em "{username}" \'(.inbounds[] | select(.tag | startswith("vmess")).settings.clients) += [{{"id":$uid,"email":$em,"alterId":0}}]\' {cfg} > /tmp/_xr.json && mv /tmp/_xr.json {cfg} && chmod 644 {cfg} && systemctl restart xray'
    return uid, cmd

def make_links(protocol, username, uid, domain):
    if protocol == "vmess":
        def vl(port, tls, path):
            j = json.dumps({"v":"2","ps":username,"add":"bug.com","port":str(port),
                "id":uid,"aid":"0","net":"ws","path":path,"type":"none","host":domain,
                "tls":"tls" if tls else "none"})
            return "vmess://" + base64.b64encode(j.encode()).decode()
        tls  = vl(443, True, "/vmess")
        ntls = vl(80, False, "/vmess")
        gj   = json.dumps({"v":"2","ps":username,"add":domain,"port":"443","id":uid,
                           "aid":"0","net":"grpc","path":"vmess-grpc","type":"none",
                           "host":"bug.com","tls":"tls"})
        grpc = "vmess://" + base64.b64encode(gj.encode()).decode()
    elif protocol == "vless":
        tls  = f"vless://{uid}@bug.com:443?path=%2Fvless&security=tls&encryption=none&host={domain}&type=ws&sni={domain}#{username}"
        ntls = f"vless://{uid}@bug.com:80?path=%2Fvless&security=none&encryption=none&host={domain}&type=ws#{username}"
        grpc = f"vless://{uid}@{domain}:443?mode=gun&security=tls&encryption=none&type=grpc&serviceName=vless-grpc&sni=bug.com#{username}"
    else:
        tls  = f"trojan://{uid}@bug.com:443?path=%2Ftrojan&security=tls&host={domain}&type=ws&sni={domain}#{username}"
        ntls = f"trojan://{uid}@bug.com:80?path=%2Ftrojan&security=none&host={domain}&type=ws#{username}"
        grpc = f"trojan://{uid}@{domain}:443?mode=gun&security=tls&type=grpc&serviceName=trojan-grpc&sni=bug.com#{username}"
    return tls, ntls, grpc

def kb_vps():
    vps = load_vps()
    if not vps: return None
    rows = []
    for i, (vid, info) in enumerate(vps.items(), 1):
        rows.append([{"text": f"{i}. {info.get('label', info.get('ip', vid))}", "callback_data": f"vps|{vid}"}])
    return {"inline_keyboard": rows}

def kb_proto(vid):
    return {"inline_keyboard": [[
        {"text": "VMess",  "callback_data": f"proto|{vid}|vmess"},
        {"text": "VLess",  "callback_data": f"proto|{vid}|vless"},
        {"text": "Trojan", "callback_data": f"proto|{vid}|trojan"},
    ]]}

def handle_msg(msg):
    cid  = msg["chat"]["id"]
    text = msg.get("text", "").strip()
    if cid != ADMIN_ID:
        send(cid, "❌ Akses ditolak."); return
    s = st_get(cid)
    if s.get("step") == "input_user":
        username = text.replace(" ", "_")
        if len(username) < 3:
            send(cid, "❌ Username minimal 3 karakter."); return
        s["username"] = username
        s["step"] = "input_days"
        st_set(cid, s)
        send(cid, "⏳ Berapa hari aktif? (contoh: 30)")
        return
    if s.get("step") == "input_days":
        if not text.isdigit():
            send(cid, "❌ Masukkan angka hari."); return
        days = int(text)
        vid = s.get("vid",""); proto = s.get("proto",""); username = s.get("username","")
        st_clear(cid)
        if not vid or not proto or not username:
            send(cid, "❌ Data tidak lengkap, ulangi /buat"); return
        vps = load_vps()
        if vid not in vps:
            send(cid, "❌ VPS tidak ditemukan."); return
        info = dict(vps[vid]); ip = info["ip"]
        send(cid, "⏳ Membuat akun...")
        _p = proto; _u = username; _d = days; _ip = ip; _info = info
        def do_buat():
            uid, cmd = xray_add(_p, _u)
            rc, out  = run_local(cmd)
            if rc != 0:
                send(cid, f"❌ Gagal buat akun.\n<code>{out[:300]}</code>"); return
            domain = _info.get("domain", _info.get("label", _ip))
            tls, ntls, grpc = make_links(_p, _u, uid, domain)
            from datetime import datetime, timedelta
            exp = (datetime.now() + timedelta(days=_d)).strftime("%d %b, %Y")
            send(cid,
                f"✅ <b>Akun {_p.upper()} Berhasil</b>\n"
                f"━━━━━━━━━━━━━━━━━━━━━━━\n"
                f"👤 Username : <code>{_u}</code>\n"
                f"🔑 UUID     : <code>{uid}</code>\n"
                f"🌐 Domain   : <code>{domain}</code>\n"
                f"📅 Expired  : {exp}\n"
                f"━━━━━━━━━━━━━━━━━━━━━━━\n"
                f"🔗 <b>TLS:</b>\n<code>{tls}</code>\n"
                f"━━━━━━━━━━━━━━━━━━━━━━━\n"
                f"🔗 <b>NonTLS:</b>\n<code>{ntls}</code>\n"
                f"━━━━━━━━━━━━━━━━━━━━━━━\n"
                f"🔗 <b>gRPC:</b>\n<code>{grpc}</code>")
        threading.Thread(target=do_buat, daemon=True).start()
        return
    st_clear(cid)
    if text in ["/start", "/menu"]:
        send(cid, "🤖 <b>Tunnel Bot Multi-VPS</b>\n\n/buat — Buat akun\n/vps  — Daftar VPS")
    elif text == "/buat":
        vps = load_vps()
        if not vps: send(cid, "⚠️ Belum ada VPS."); return
        send(cid, "🖥 <b>Pilih VPS:</b>", markup=kb_vps())
    elif text == "/vps":
        vps = load_vps()
        if not vps: send(cid, "⚠️ Belum ada VPS."); return
        lines = ["🖥 <b>Daftar VPS</b>\n━━━━━━━━━━━━━━━━━━━━━━━"]
        for i, (vid, info) in enumerate(vps.items(), 1):
            lines.append(f"{i}. <b>{info['label']}</b> — <code>{info['ip']}</code>")
        send(cid, "\n".join(lines))

def handle_cb(cb):
    cid  = cb["message"]["chat"]["id"]
    data = cb["data"]
    if cid != ADMIN_ID: return
    answer_cb(cb["id"])
    if data.startswith("vps|"):
        vid = data[4:]
        vps = load_vps()
        if vid not in vps: send(cid, "❌ VPS tidak ditemukan."); return
        st_set(cid, {"step": "pilih_proto", "vid": vid})
        send(cid, f"🖥 VPS: <b>{vps[vid]['label']}</b>\nPilih protocol:", markup=kb_proto(vid))
    elif data.startswith("proto|"):
        parts = data.split("|")
        if len(parts) < 3: return
        st_set(cid, {"step": "input_user", "vid": parts[1], "proto": parts[2]})
        send(cid, f"📝 Ketik username untuk akun <b>{parts[2].upper()}</b>:")

def main():
    offset = 0
    while True:
        try:
            res = tg("getUpdates", params={"offset": offset, "timeout": 20, "limit": 50})
            for upd in res.get("result", []):
                offset = upd["update_id"] + 1
                if "message" in upd:
                    threading.Thread(target=handle_msg, args=(upd["message"],), daemon=True).start()
                elif "callback_query" in upd:
                    threading.Thread(target=handle_cb, args=(upd["callback_query"],), daemon=True).start()
        except: time.sleep(3)

if __name__ == "__main__":
    main()
PYEOF

    chmod +x "$BOT_FILE"
    cat > /etc/systemd/system/tunnelbot.service << EOF
[Unit]
Description=Tunnel Bot Multi-VPS
After=network.target

[Service]
ExecStart=/usr/bin/python3 $BOT_FILE
Restart=always
RestartSec=5
StandardOutput=/dev/null
StandardError=/dev/null

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload >/dev/null 2>&1
    systemctl enable tunnelbot >/dev/null 2>&1
    systemctl start tunnelbot >/dev/null 2>&1
}

#================================================
# AUTO INSTALL - FULL PROCESS
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

    animated_loading "Mempersiapkan instalasi" 2
    echo ""

    local total=10 step=0 LOG="/tmp/install.log"
    > "$LOG"

    _head() {
        echo ""
        echo -e "  ${CYAN}╔══════════════════════════════════════════════════╗${NC}"
        printf  "  ${CYAN}║${NC}  ${YELLOW}STEP %d/%d${NC} — ${WHITE}%-38s${NC}${CYAN}║${NC}\n" "$2" "$3" "$1"
        echo -e "  ${CYAN}╚══════════════════════════════════════════════════╝${NC}"
        echo ""
    }

    _pkg() {
        local pkg="$1" sp=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏') i=0
        DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg" >> "$LOG" 2>&1 &
        local pid=$!
        while kill -0 $pid 2>/dev/null; do
            printf "\r  ${CYAN}${sp[$((i % 10))]}${NC}  Installing %-30s" "${pkg}..."
            sleep 0.08; ((i++))
        done
        wait $pid
        [[ $? -eq 0 ]] && printf "\r  ${GREEN}✔${NC}  %-40s\n" "$pkg" || printf "\r  ${RED}✘${NC}  %-40s\n" "$pkg (gagal)"
    }

    _run() {
        local label="$1" cmd="$2" sp=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏') i=0
        eval "$cmd" >> "$LOG" 2>&1 &
        local pid=$!
        while kill -0 $pid 2>/dev/null; do
            printf "\r  ${CYAN}${sp[$((i % 10))]}${NC}  %-45s" "${label}..."
            sleep 0.08; ((i++))
        done
        wait $pid
        local ret=$?
        [[ $ret -eq 0 ]] && printf "\r  ${GREEN}✔${NC}  %-45s\n" "$label" || printf "\r  ${RED}✘${NC}  %-45s\n" "$label (gagal)"
        return $ret
    }

    ((step++)); show_progress $step $total "System Update"
    _head "System Update" $step $total
    _run "apt-get update" "apt-get update -y"
    _run "apt-get upgrade" "DEBIAN_FRONTEND=noninteractive apt-get upgrade -y"

    ((step++)); show_progress $step $total "Installing Base Packages"
    _head "Base Packages" $step $total
    for pkg in curl wget unzip uuid-runtime net-tools openssl jq python3 python3-pip; do _pkg "$pkg"; done

    ((step++)); show_progress $step $total "Installing VPN Services"
    _head "VPN Services" $step $total
    for pkg in nginx openssh-server dropbear haproxy certbot; do _pkg "$pkg"; done

    ((step++)); show_progress $step $total "Installing Xray-Core 1.8.24"
    _head "Xray Core" $step $total
    _run "Downloading Xray 1.8.24" "bash <(curl -Ls https://github.com/XTLS/Xray-install/raw/main/install-release.sh) --version 1.8.24"
    mkdir -p "$AKUN_DIR" /var/log/xray /usr/local/etc/xray "$PUBLIC_HTML" "$ORDER_DIR" /root/bot
    command -v xray >/dev/null 2>&1 && printf "\r  ${GREEN}✔${NC}  %-45s\n" "Xray 1.8.24 installed" || printf "\r  ${RED}✘${NC}  %-45s\n" "Xray install failed"

    ((step++)); show_progress $step $total "Setting up Swap Memory"
    _head "Swap Memory 1GB" $step $total
    local cur_swap; cur_swap=$(free -m | awk 'NR==3{print $2}')
    if [[ "$cur_swap" -lt 512 ]]; then
        _run "Creating swapfile 1GB" "fallocate -l 1G /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=1024"
        chmod 600 /swapfile; mkswap /swapfile >/dev/null 2>&1; swapon /swapfile
        grep -q "/swapfile" /etc/fstab || echo "/swapfile none swap sw 0 0" >> /etc/fstab
        printf "\r  ${GREEN}✔${NC}  %-45s\n" "Swap 1GB active"
    else
        printf "\r  ${GREEN}✔${NC}  %-45s\n" "Swap exists (${cur_swap}MB), skip"
    fi

    ((step++)); show_progress $step $total "Getting SSL Certificate"
    _head "SSL Certificate" $step $total
    mkdir -p /etc/xray
    if [[ "$domain_type" == "custom" ]]; then
        _run "Certbot Let's Encrypt" "certbot certonly --standalone -d '$DOMAIN' --non-interactive --agree-tos --register-unsafely-without-email"
        if [[ -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]]; then
            cp "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" /etc/xray/xray.crt
            cp "/etc/letsencrypt/live/$DOMAIN/privkey.pem" /etc/xray/xray.key
            printf "\r  ${GREEN}✔${NC}  %-45s\n" "Let's Encrypt cert installed"
        else
            _run "Generating self-signed cert" \
                "openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 -subj '/C=ID/ST=Jakarta/L=Jakarta/O=VPN/CN=${DOMAIN}' -keyout /etc/xray/xray.key -out /etc/xray/xray.crt"
            printf "\r  ${GREEN}✔${NC}  %-45s\n" "Self-signed cert generated"
        fi
    else
        _run "Generating self-signed cert" \
            "openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 -subj '/C=ID/ST=Jakarta/L=Jakarta/O=VPN/CN=${DOMAIN}' -keyout /etc/xray/xray.key -out /etc/xray/xray.crt"
        printf "\r  ${GREEN}✔${NC}  %-45s\n" "Self-signed cert for $DOMAIN"
    fi
    chmod 644 /etc/xray/xray.* 2>/dev/null

    ((step++)); show_progress $step $total "Creating Xray Config (No Port Conflict)"
    _head "Xray Config (Fixed)" $step $total
    create_xray_config
    printf "\r  ${GREEN}✔${NC}  %-45s\n" "9 inbounds: VMess/VLess/Trojan (WS+gRPC)"
    printf "\r  ${GREEN}✔${NC}  %-45s\n" "Ports: TLS:8443-8445, NonTLS:8080-8082, gRPC:8446-8448"

    # Nginx Config
    cat > /etc/nginx/sites-available/default << 'NGXEOF'
server {
    listen 80 default_server;
    server_name _;
    root /var/www/html;
    keepalive_timeout 300;
    location / { try_files $uri $uri/ =404; autoindex on; }
    location /vmess {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 86400s;
    }
    location /vless {
        proxy_pass http://127.0.0.1:8081;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 86400s;
    }
    location /trojan {
        proxy_pass http://127.0.0.1:8082;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 86400s;
    }
}
server {
    listen 81;
    server_name _;
    root /var/www/html;
    autoindex on;
    location / { try_files $uri $uri/ =404; add_header Content-Type text/plain; }
}
NGXEOF
    rm -f /etc/nginx/sites-enabled/default
    ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default
    nginx -t >> "$LOG" 2>&1 && printf "\r  ${GREEN}✔${NC}  %-45s\n" "Nginx config valid" || printf "\r  ${RED}✘${NC}  %-45s\n" "Nginx config error"

    ((step++)); show_progress $step $total "Configuring Dropbear & HAProxy"
    _head "Dropbear & HAProxy" $step $total
    cat > /etc/default/dropbear << 'DBEOF'
NO_START=0
DROPBEAR_PORT=222
DROPBEAR_EXTRA_ARGS="-K 60 -I 180"
DROPBEAR_RECEIVE_WINDOW=65536
DBEOF
    configure_haproxy
    printf "\r  ${GREEN}✔${NC}  %-45s\n" "Dropbear port 222, HAProxy port 443→8443"

    ((step++)); show_progress $step $total "UDP, Keepalive & Optimize"
    _head "System Optimize" $step $total
    install_udp_custom
    setup_keepalive
    optimize_vpn
    pip3 install requests --break-system-packages >> "$LOG" 2>&1
    printf "\r  ${GREEN}✔${NC}  %-45s\n" "BBR + TCP + UDP + Keepalive active"

    # Buat script auto-delete expired
    cat > /usr/local/bin/vpn-delete-expired.sh << 'DELEOF'
#!/bin/bash
AKUN_DIR="/root/akun"
XRAY_CONFIG="/usr/local/etc/xray/config.json"
PUBLIC_HTML="/var/www/html"
today=$(date +%s)
shopt -s nullglob
for f in "$AKUN_DIR"/*.txt; do
    exp_str=$(grep "EXPIRED=" "$f" 2>/dev/null | head -1 | cut -d= -f2-)
    [[ -z "$exp_str" ]] && continue
    exp_ts=$(date -d "$exp_str" +%s 2>/dev/null)
    [[ -z "$exp_ts" ]] && continue
    if [[ $exp_ts -lt $today ]]; then
        fname=$(basename "$f" .txt)
        protocol=${fname%%-*}
        uname=${fname#*-}
        tmp=$(mktemp)
        jq --arg email "$uname" \
           'del(.inbounds[].settings.clients[]? | select(.email == $email))' \
           "$XRAY_CONFIG" > "$tmp" 2>/dev/null && mv "$tmp" "$XRAY_CONFIG" || rm -f "$tmp"
        chmod 644 "$XRAY_CONFIG" 2>/dev/null
        [[ "$protocol" == "ssh" ]] && userdel -f "$uname" 2>/dev/null
        rm -f "$f" "$PUBLIC_HTML/${fname}.txt"
    fi
done
shopt -u nullglob
systemctl restart xray 2>/dev/null
DELEOF
    chmod +x /usr/local/bin/vpn-delete-expired.sh
    # Pasang cron auto delete expired jam 00:00
    (crontab -l 2>/dev/null | grep -v "vpn-delete-expired"; \
     echo "0 0 * * * /usr/local/bin/vpn-delete-expired.sh >> /var/log/vpn-expired.log 2>&1") | crontab -

    ((step++)); show_progress $step $total "Starting All Services"
    _head "Start All Services" $step $total
    systemctl daemon-reload >> "$LOG" 2>&1
    for svc in xray nginx sshd dropbear haproxy udp-custom vpn-keepalive; do
        systemctl enable "$svc" >> "$LOG" 2>&1
        systemctl restart "$svc" >> "$LOG" 2>&1
        systemctl is-active --quiet "$svc" && \
            printf "  ${GREEN}✔${NC} %-20s ${GREEN}RUNNING${NC}\n" "$svc" || \
            printf "  ${RED}✘${NC} %-20s ${RED}FAILED${NC}\n" "$svc"
    done

    setup_menu_command

    _install_tunnelbot_background >/dev/null 2>&1
    _register_vps_to_bot >/dev/null 2>&1
    systemctl is-active --quiet tunnelbot && \
        printf "  ${GREEN}✔${NC} %-20s ${GREEN}RUNNING${NC}\n" "tunnelbot" || true

    local ip_vps; ip_vps=$(get_ip)
    cat > "$PUBLIC_HTML/index.html" << IDXEOF
<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Youzin Crabz Tunel</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Courier New',monospace;background:#0a0a1a;color:#eee;display:flex;align-items:center;justify-content:center;min-height:100vh;text-align:center}.box{padding:40px;background:#0d1117;border:1px solid #00d4ff44;border-radius:12px;max-width:500px}h1{color:#00d4ff;margin-bottom:5px;font-size:1.8em;letter-spacing:2px}.sub{color:#7ee8fa;font-size:0.9em;margin-bottom:15px}p{color:#666;margin:4px 0;font-size:0.85em}.badge{display:inline-block;background:#00d4ff22;color:#00d4ff;padding:4px 16px;border-radius:20px;margin-top:15px;font-size:12px;letter-spacing:1px;border:1px solid #00d4ff33}</style>
</head><body><div class="box"><h1>⚡ YOUZIN CRABZ</h1><div class="sub">T U N E L</div><p>${DOMAIN}</p><p>${ip_vps}</p><div class="badge">The Professor</div></div></body></html>
IDXEOF

    echo ""
    echo -e "${GREEN}  ╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}  ║            ✔  INSTALASI SELESAI!                 ║${NC}"
    echo -e "${GREEN}  ║      Youzin Crabz Tunel v${SCRIPT_VERSION} - The Professor     ║${NC}"
    echo -e "${GREEN}  ╚══════════════════════════════════════════════════╝${NC}"
    echo ""
    printf "  ${WHITE}%-22s${NC}: ${GREEN}%s${NC}\n" "Domain"       "$DOMAIN"
    printf "  ${WHITE}%-22s${NC}: ${GREEN}%s${NC}\n" "IP VPS"       "$ip_vps"
    printf "  ${WHITE}%-22s${NC}: ${CYAN}%s${NC}\n"  "SSH"          "22 | Dropbear: 222"
    printf "  ${WHITE}%-22s${NC}: ${CYAN}%s${NC}\n"  "HAProxy TLS"  "443 → Xray"
    printf "  ${WHITE}%-22s${NC}: ${CYAN}%s${NC}\n"  "Nginx NonTLS" "80 → Xray"
    printf "  ${WHITE}%-22s${NC}: ${CYAN}%s${NC}\n"  "BadVPN UDP"   "7100-7300"
    printf "  ${WHITE}%-22s${NC}: ${CYAN}%s${NC}\n"  "Download"     "http://${ip_vps}:81/"
    echo ""
    echo -e "  ${YELLOW}💡 Ketik 'menu' untuk membuka panel!${NC}"
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
                echo -e "  ${CYAN}[1]${NC} VMess Trial  ${CYAN}[2]${NC} VLess Trial  ${CYAN}[3]${NC} Trojan Trial  ${CYAN}[0]${NC} Back"
                read -p "  Select: " trial_choice
                case $trial_choice in
                    1) create_trial_xray "vmess" ;;
                    2) create_trial_xray "vless" ;;
                    3) create_trial_xray "trojan" ;;
                esac
                ;;
            6|06) _menu_list_all ;;
            7|07) cek_expired ;;
            8|08) delete_expired ;;
            9|09) menu_telegram_bot ;;
            10) change_domain ;;
            11) fix_certificate ;;
            12)
                clear; optimize_vpn
                echo -e "  ${GREEN}✔ Optimization done!${NC}"; sleep 2
                ;;
            13)
                clear; print_menu_header "RESTART ALL SERVICES"
                for svc in xray nginx sshd dropbear haproxy udp-custom vpn-keepalive vpn-bot; do
                    systemctl restart "$svc" 2>/dev/null && \
                        printf "  ${GREEN}✔${NC} %-20s ${GREEN}Restarted${NC}\n" "$svc" || \
                        printf "  ${RED}✘${NC} %-20s ${RED}Failed/Not installed${NC}\n" "$svc"
                done
                echo ""; sleep 2
                ;;
            14) show_info_port ;;
            15) run_speedtest ;;
            16) update_menu ;;
            17) _menu_backup ;;
            18) _menu_restore ;;
            19) menu_uninstall ;;
            20|99) menu_advanced ;;
            0|00)
                clear
                echo -e "  ${CYAN}Goodbye! — Youzin Crabz Tunel${NC}"
                exit 0
                ;;
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
