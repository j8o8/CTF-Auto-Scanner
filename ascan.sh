#!/bin/bash

VERSION="v1.0.3"

############### PARAMETER HANDLING ###############
helpFunction()
{
   echo ""
   echo "Usage: $0 -t ip-address [-d target.thm] [-f scriptfolder] [-o]"
   echo -e "\t-t Target IP address"
   echo -e "\t-d Target domain"
   echo -e "\t-f Subfolder for logs"
   exit 1
}

while getopts "t:d:f:" opt
do
   case "$opt" in
      t ) target_ip="$OPTARG" ;;
      d ) target_domain="$OPTARG" ;;
      f ) subfolder="$OPTARG" ;;
      ? ) helpFunction ;;
   esac
done

if [ -z "$target_ip" ]; then
   echo "Target IP address is required.";
   helpFunction
fi

if [ -z "$target_domain" ]; then
   target_domain="target.thm"
fi

############### VARIABLES ###############
ESC=$(printf '\033')
R="${ESC}[1;31m"
G="${ESC}[1;32m"
Y="${ESC}[1;33m"
B="${ESC}[1;34m"
MAGENTA="${ESC}[1;35m"
CYAN="${ESC}[1;36m"
NC="${ESC}[0m"
PREFIX="${Y}### "
INFO="${Y}[i] "
runtime=$(date +%Y%m%d%H%M%S)
port_range="65536" # Port numbert to scan + 1

############### FUNCTIONS ###############
check_prerequisite() {
    prereq=$1
    if [ "$(dpkg -l | awk '/'$prereq'/ {print }'|wc -l)" -ge 1 ]; then
        echo $INFO$NC"$prereq is installed"
    else
        echo $INFO$Y"$prereq is required but not installed"$NC
        read -p "Try installing $prereq? [y/n]" -n 1 -r
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            sudo apt-get -y install $prereq
        else
            exit 1
        fi
    fi
}

check_service() {
   service_name=$1
   xml_out=$(xmllint --xpath "//port[descendant::service[@name='$service_name']]" $nmap_tmp_xml 2>/dev/null)
   if [ -z "${xml_out}" ]; then
      echo $Y"$service_name not found -> Skipping"$NC
   else
      port=$(echo $xml_out | perl -p -e 's/^.*?portid="//' | awk '{sub(/">.*/,""); print}' | sed -n '1p')
      echo $G"$service_name found on port $port -> Scanning"$NC
      if [[ $service_name == "http" ]]; then
         scan_http=true;
         http_port=$port
      elif [[ $service_name == "ssh" ]]; then
         scan_ssh=true;
         ssh_port=$port
      elif [[ $service_name == "netbios-ssn" ]]; then
         scan_smb=true;
         smb_port=$port
      fi
   fi
}

scan_http_service() {
   echo $PREFIX$B"Starting HTTP Scan on $target:$http_port"$NC
   echo ""

   echo $PREFIX$B"Trying to download robots.txt"$NC
   robots_log="$log_path/robots.txt"
   robots_uri="http://$target/robots.txt"
   if wget -q --method=HEAD $robots_uri; then
      echo $INFO$NC"Downloading"
      curl $robots_uri > $robots_log
      echo ""
      cat $robots_log
      echo $G"Robots.txt download finished"$NC
      echo $INFO$NC"Robots file saved to $robots_log"
   else
      echo $INFO$Y"robots.txt does not exist"$NC
   fi
   echo ""
   echo $PREFIX$B"Starting Gobuster Scan"$NC
   gobuster_log="$log_path/gobuster.log"
   gobuster_wordlist="/usr/share/dirb/wordlists/common.txt"
   echo $INFO$NC"Using wordlist $gobuster_wordlist"
   gobuster dir -u http://$target:$http_port -w $gobuster_wordlist -o $gobuster_log -t 200
   echo $INFO$G"Gobuster Scan finished"$NC
   echo $INFO$NC"Log file saved to $gobuster_log"
   echo ""

   echo $PREFIX$B"Starting Nikto Scan"$NC
   nikto_log="$log_path/nikto.log"
   nikto -h $target -p $http_port -Format txt -o $nikto_log
   echo $INFO$G"Nikto Scan finished"$NC
   echo $INFO$NC"Log file saved to $nikto_log"
   echo ""
}

scan_smb_service() {
   echo $PREFIX$B"Starting SMB Scan on $target:$smb_port"$NC
   echo ""
   echo $PREFIX$B"Starting Smbmap Scan"$NC
   smbmap_log="$log_path/smbmap.log"
   smbmap -H $target -P $smb_port -u guest > $smbmap_log
   cat $smbmap_log
   echo $INFO$G"Smbmap Scan finished"$NC
   echo $INFO$NC"Log file saved to $smbmap_log"
   echo ""
   echo $INFO$G"SMB Scan finished"$NC
}

scan_ssh_service() {
   echo $PREFIX$B"Starting SSH Scan on $target:$ssh_port"$NC
   echo ""
   ssh_log="$log_path/ssh.log"
   echo $INFO$Y"Doing nothing yet"$NC
   echo $INFO$NC"Log file saved to $ssh_log"
   echo ""
   echo $INFO$G"SSH Scan finished"$NC
}

############### SCRIPT START ###############
echo $MAGENTA"Commencing CTF Mission, now."$NC
echo ""

############### PREREQUISITES CHECK ###############
echo $PREFIX$B"Checking prerequisites"$NC
check_prerequisite "libxml2-utils"
check_prerequisite "perl"
echo ""

############### SUBFOLDER CHECK ###############
if [ -z "$subfolder" ]; then
   log_path=$(pwd)
else
   if [ ! -d "$subfolder" ]; then
      echo $INFO$B"Creating folder $subfolder"$NC
      mkdir $subfolder
   fi
   current_path=$(pwd)
   log_path="$current_path/$subfolder"
fi
echo ""

############### SETTINGS ###############
echo $PREFIX$B"Settings"$NC
echo $INFO$NC"Using IP Address: $target_ip"
echo $INFO$NC"Using Domain:     $target_domain"
echo $INFO$NC"Using Folder:     $log_path"
echo ""

############### HOSTS ENTRY ###############
echo $PREFIX$B"Adding hosts entry"$NC
echo $INFO$NC'Writing "'$target_ip' '$target_domain'" to /etc/hosts'
echo "$target_ip $target_domain" >> /etc/hosts
if grep -wq "$target_domain" /etc/hosts; then
   target=$target_domain
   echo $INFO$G"Host entry successfully added"
else
   target=$target_ip
   echo $INFO$R"Host entry addition failed"
fi
echo ""

############### PING TEST ###############
echo $PREFIX$B"Testing Ping"$NC
echo $INFO$NC"Pinging $target"
if ping -c 1 $target_domain &> /dev/null; then
   ping=true
   echo $INFO$G"Ping test successful"$NC
else
   ping=false
   echo $INFO$R"Ping failed. Firewall might be active"$NC
fi
echo ""

############### OPEN PORT SCAN ###############
echo $PREFIX$B"Starting Open Port Scan"$NC
open_ports=""
for port in $(seq 1 $port_range); do
   if [ "$port" -lt "$port_range" ]; then
      echo -ne $INFO$NC"Scanning Port: $port\r"
      ( echo > /dev/tcp/$target/$port) > /dev/null 2>&1 && echo "Open Port found on "$target": "$port && open_ports="${open_ports}$port,";
   else
      echo -ne $INFO$G"Open Port Scan successfully finished\r"$NC
   fi
done
open_ports=${open_ports%,*}
echo ""
echo ""

############### NMAP SCAN ###############
echo $PREFIX$B"Starting NMAP Scans"$NC
echo $INFO$NC"Using ports $open_ports"
nmap_tmp_xml="/tmp/nmap-$target-$runtime.xml"
nmap_log="$log_path/nmap.log"
if $ping; then
   nmap -v -n -T4 -sV -sC --min-rate 2000 --max-retries 3 -p$open_ports -oX $nmap_tmp_xml -oN $nmap_log $target
else
   echo $INFO$NC"Ping deactivated"
   nmap -Pn -v -n -T4 -sV -sC --min-rate 2000 --max-retries 3 -p$open_ports -oN $nmap_log $target
fi
echo $INFO$G"NMAP Scan finished"$NC
echo $INFO$NC"Log file saved to $nmap_log"
echo ""

############### FURTHER SCANS ###############
echo $PREFIX$B"Checking for services to scan"$NC
services=( http ssh netbios-ssn )
scan_http=false
http_port="80"
scan_ssh=false
ssh_port="22"
scan_smb=false
smb_port="445"
for service in ${services[@]}
do
   check_service $service
done
echo ""

if $scan_http; then
   scan_http_service
   echo $G"HTTP Scan finished"$NC
   echo ""
fi

if $scan_smb; then
   scan_smb_service
   echo ""
fi

if $scan_ssh; then
   scan_ssh_service
   echo ""
fi

############### EOF ###############
echo $PREFIX$B"Exiting"$NC
exit 0
