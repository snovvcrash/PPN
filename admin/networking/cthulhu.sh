#!/usr/bin/env bash

# Automatic VPS (Cthulhu) environment configuration
# Tested on Ubuntu 20.04
# Run as root: 

USERNAME="$1"
PASSWORD="$2"

GREEN="\033[1;32m"
NOCOLOR="\033[0m"

colorecho() {
	echo -e "${GREEN}[*] ${1}${NOCOLOR}"
}

# -- general ---------------------------------------------------------

colorecho "general"

timedatectl set-timezone Europe/Moscow
apt update && apt upgrade -y
apt install sudo -y

# -- useradd ---------------------------------------------------------

colorecho "useradd"

useradd -ms /bin/bash $USERNAME
echo "$USERNAME:$PASSWORD" | chpasswd
usermod -aG sudo $USERNAME
echo "Defaults secure_path=\"/home/$USERNAME/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"" > /etc/sudoers.d/$USERNAME
echo "$USERNAME ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/$USERNAME
rm -f /home/$USERNAME/.hushlogin

# -- ssh -------------------------------------------------------------

colorecho "ssh"

mkdir /home/$USERNAME/.ssh
chown $USERNAME:$USERNAME /home/$USERNAME/.ssh
sudo -u $USERNAME ssh-keygen -o -a 100 -t ed25519 -f /home/$USERNAME/.ssh/id_cthulhu -C "Cthulhu VPS" && cat /home/$USERNAME/.ssh/id_cthulhu
sudo -u $USERNAME cat /home/$USERNAME/.ssh/id_cthulhu.pub >> /home/$USERNAME/.ssh/authorized_keys
chown $USERNAME:$USERNAME /home/$USERNAME/.ssh/authorized_keys
chmod og-wx /home/$USERNAME/.ssh/authorized_keys
read -rsp $'Copy the private key (press any key to continue)...\n' -n1 key
mv /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

cat << EOT > /etc/ssh/sshd_config
Port 302

# Supported HostKey algorithms by order of preference
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key

# Authentication
PermitRootLogin no
AllowUsers $USERNAME
AuthenticationMethods publickey
PubkeyAuthentication yes
HostbasedAuthentication no
IgnoreRhosts yes
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no

UsePAM yes
UseDNS no

X11Forwarding yes
PrintMotd no

# Allow client to pass locale environment variables
AcceptEnv LANG LC_*

# Override default of no subsystems
Subsystem	sftp	/usr/lib/openssh/sftp-server
EOT

sshd -t
service sshd restart
service sshd status
sudo -u $USERNAME rm /home/$USERNAME/.ssh/id_cthulhu*

# -- fail2ban --------------------------------------------------------

colorecho "fail2ban"

apt install fail2ban -y
cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local

cat << EOT > /tmp/jail.local
enabled  = true
filter   = sshd
action   = iptables[name=SSH, port=302, protocol=tcp]
port     = 302
findtime = 600
maxretry = 3
bantime  = 43200
logpath  = %(sshd_log)s
backend  = %(sshd_backend)s
EOT

perl -i -p0e 's/port    = ssh\nlogpath = %\(sshd_log\)s\nbackend = %\(sshd_backend\)s\n/`cat \/tmp\/jail.local`/se' /etc/fail2ban/jail.local
service fail2ban restart
service fail2ban status
systemctl enable fail2ban.service --now
fail2ban-client status
fail2ban-client status sshd

# -- GUI + X2Go ------------------------------------------------------

apt install xfce4 xfce4-goodies xorg dbus-x11 x11-xserver-utils -y
apt install x2goserver x2goserver-xsession -y
service x2goserver status
systemctl enable x2goserver.service --now

# -- tools -----------------------------------------------------------

colorecho "tools"

apt install build-essential locales ca-certificates cmake curl dnsutils htop mlocate netcat rlwrap git sqlite3 dos2unix -y

# -- locales ---------------------------------------------------------

colorecho "locales"

apt install locales -y
sed -i -e 's/# en_US ISO-8859-1/en_US ISO-8859-1/' /etc/locale.gen
sed -i -e 's/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen
sed -i -e 's/# ru_RU.UTF-8 UTF-8/ru_RU.UTF-8 UTF-8/' /etc/locale.gen
locale-gen

# -- motd ------------------------------------------------------------

colorecho "motd"

rm /etc/update-motd.d/*

cat << EOT > /etc/update-motd.d/01-motd
#!/bin/sh

# uname -snrvm

clear
echo ""
echo "\033[38;5;248m ▄████████     ███        ▄█    █▄    ███    █▄   ▄█          ▄█    █▄    ███    █▄ "
echo "\033[38;5;247m███    ███ ▀█████████▄   ███    ███   ███    ███ ███         ███    ███   ███    ███"
echo "\033[38;5;245m███    █▀     ▀███▀▀██   ███    ███   ███    ███ ███         ███    ███   ███    ███"
echo "\033[38;5;243m███            ███   ▀  ▄███▄▄▄▄███▄▄ ███    ███ ███        ▄███▄▄▄▄███▄▄ ███    ███"
echo "\033[38;5;241m███            ███     ▀▀███▀▀▀▀███▀  ███    ███ ███       ▀▀███▀▀▀▀███▀  ███    ███"
echo "\033[38;5;239m███    █▄      ███       ███    ███   ███    ███ ███         ███    ███   ███    ███"
echo "\033[38;5;237m███    ███     ███       ███    ███   ███    ███ ███▌    ▄   ███    ███   ███    ███"
echo "\033[38;5;235m████████▀     ▄████▀     ███    █▀    ████████▀  █████▄▄██   ███    █▀    ████████▀ "
echo "\033[38;5;160m                Now I am become Death, the destroyer of the worlds. \033[0m         "
echo ""
EOT

chmod +x /etc/update-motd.d/01-motd

# -- dotfiles --------------------------------------------------------

colorecho "dotfiles"

sudo -u $USERNAME git clone https://github.com/snovvcrash/dotfiles-linux /home/$USERNAME/.dotfiles
pushd "/home/$USERNAME/.dotfiles"

# tmux

colorecho "tmux"

pushd "tmux"
sudo -u $USERNAME ./tmux-upd.sh "3.1c"
popd

pushd "00-autoconfig"
sudo -u $USERNAME ./tmux.sh
# prefix + I
popd

# zsh

colorecho "zsh"

pushd "00-autoconfig"
sudo -u $USERNAME ./zsh.sh
sudo -u $USERNAME chsh -s `which zsh`
sudo -u $USERNAME sed -i 's/ZSH_THEME="fino"/#ZSH_THEME="fino"/g' /home/$USERNAME/.zshrc
sudo -u $USERNAME sed -i 's/#ZSH_THEME="gianu"/ZSH_THEME="gianu"/g' /home/$USERNAME/.zshrc
popd

# python

colorecho "python"

pushd "00-autoconfig"
sudo -u $USERNAME ./python.sh
popd

# fzf

colorecho "fzf"

pushd "00-autoconfig"
sudo -u $USERNAME ./fzf.sh
popd

# tilix

colorecho "tilix"
pushd "00-autoconfig"
sudo -u $USERNAME ./tilix.sh
popd

popd
