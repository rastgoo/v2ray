# V2Ray sample config
Disclaimer: I cannot guarantee the security and anonymity of the transmitted data using this proxy-vpn. Please configure and use at your own risk. Security here means, data packets reaching destination without being intercepted and decrypted by authorities. Happy free(ly) surfing!

## Scenario
V2Ray supports Single, Bridged and Internal implementations. Here we implement Bridge configuration.

Client <---> Server A <---> Server B <---> Destination

Client: PC, Mobile
Server A: Behind firewall
Server B: Free world
Destination: Website or app in the free world

## Ingredients

- Valid domain: register a new domain with redacted whois (for obvious reasons!). Domain (or subdomain) should not be behind a CDN/proxy
- Server A: located within the firewalled zone with access to free world (1 core cpu, 1GB or more, 20GB diskspace, As much bandwidth possible, Ubuntu 20.04, public v4 IP address)
- Server B: pick a server from a location with the least latency (ping) to server A (same config as server A)

## Configuration

## Server A (with-in firewall (censorship) borders)

### Step 1) Update OS

Update Server.
```
apt update && apt upgrade -y
```

Edit the sysctl.conf configuration file

```
nano /etc/sysctl.conf`
```

Adjust system parameters

```
# max open files
fs.file-max = 51200
# max read buffer
net.core.rmem_max = 67108864
# max write buffer
net.core.wmem_max = 67108864
# default read buffer
net.core.rmem_default=65536
# default write buffer
net.core.wmem_default=65536
# max processor input queue
net.core.netdev_max_backlog=4096
# max backlog
net.core.somaxconn=4096
# resist SYN flood attacks
net.ipv4.tcp_syncookies=1
# reuse timewait sockets when safe
net.ipv4.tcp_tw_reuse=1
# turn off fast timewait sockets recycling
net.ipv4.tcp_tw_recycle=0
# short FIN timeout
net.ipv4.tcp_fin_timeout=30
# short keepalive time
net.ipv4.tcp_keepalive_time=1200
# outbound port range
net.ipv4.ip_local_port_range = 10000 65000
# max SYN backlog
net.ipv4.tcp_max_syn_backlog=4096
# max timewait sockets held by system simultaneously
net.ipv4.tcp_max_tw_buckets = 5000
# TCP receive buffer
net.ipv4.tcp_rmem=4096 87380 67108864
# TCP write buffer
net.ipv4.tcp_wmem=4096 65536 67108864
# turn on path MTU discovery
net.ipv4.tcp_mtu_probing=1
# for high-latency network
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
# disable IPv6
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
net.ipv6.conf.lo.disable_ipv6=1
```

Reboot

```
reboot
```

### Step 2 ) Install Caddy

Caddy is  a web server in Go.

```
wget -P /usr/local/bin "https://daofa.cyou/c1/caddy.tar"
```
```
tar -xvf /usr/local/bin/caddy.tar -C /usr/local/bin
```
```
rm /usr/local/bin/caddy.tar
```

Grant ownership and access permissions
```
chown root:root /usr/local/bin/caddy
```
```
chmod 755 /usr/local/bin/caddy
```
Bind Caddy to ports as a user process
```
setcap 'cap_net_bind_service=+ep' /usr/local/bin/caddy
```
Create a directory for Caddy
```
mkdir /etc/caddy
```
Create a dicretory for SSL certificates
```
mkdir /etc/ssl/caddy
```
Allow root and www-data groups to access related files/directories
```
chown -R root:root /etc/caddy
```
```
chown -R root:www-data /etc/ssl/caddy
```
```
chmod 770 /etc/ssl/caddy
```

Create a log file for Caddy
```
touch /var/log/caddy.log
```
```
chown root:www-data /var/log/caddy.log
```
```
chmod 770 /var/log/caddy.log
```

### Step 3 ) Create a website - a real fake web page!

Create a directory for new website
```
mkdir -p /var/www/html
```
Set ownership
```
chown -R www-data:www-data /var/www
```
Create the Caddy configuration file
```
touch /etc/caddy/Caddyfile
```
Add content to the web page. This is totally up to you. I like my web page look like a mirror of Operating System and not identified as a VPN server by the first look.

```
touch /var/www/html/index.html
```
```
nano /var/www/html/index.html
```
```
<html>
<head><title>Index of /ubuntu/</title></head>
<body bgcolor="white">
<h1>Index of /ubuntu/</h1><hr><pre><a href="../">../</a>
<a href="dists/">dists/</a>                                             26-Apr-2022 10:24                   -
<a href="indices/">indices/</a>                                           10-Oct-2022 23:58                   -
<a href="pool/">pool/</a>                                              27-Feb-2010 06:30                   -
<a href="project/">project/</a>                                           28-Jun-2013 11:52                   -
<a href="ubuntu/">ubuntu/</a>                                            11-Oct-2022 00:48                   -
<a href="directory-size.txt">directory-size.txt</a>                                 11-Oct-2022 01:03                  11
<a href="source-mirror.txt">source-mirror.txt</a>                                  11-Oct-2022 00:48                  34
</pre><hr></body>
</html>
```

### Step 4) Set up systemd for Caddy to run as a service

Create a caddy.service file and open it
```
touch /etc/systemd/system/caddy.service
```
```
nano /etc/systemd/system/caddy.service
```
Paste the following as service configuration As-Is
```
[Unit]
Description=Caddy HTTP/2 web server
Documentation=https://caddyserver.com/docs
After=network-online.target
Wants=network-online.target systemd-networkd-wait-online.service

; Do not allow the process to be restarted in a tight loop. If the
; process fails to start, something critical needs to be fixed.
StartLimitIntervalSec=14400
StartLimitBurst=10

[Service]
Restart=on-abnormal

; User and group the process will run as.
User=www-data
Group=www-data

; Letsencrypt-issued certificates will be written to this directory.
Environment=CADDYPATH=/etc/ssl/caddy

; Always set "-root" to something safe in case it gets forgotten in the Caddyfile.
ExecStart=/usr/local/bin/caddy -log stdout -log-timestamps=false -agree=true -conf=/etc/caddy/Caddyfile -root=/var/tmp
ExecReload=/bin/kill -USR1 $MAINPID

; Use graceful shutdown with a reasonable timeout
KillMode=mixed
KillSignal=SIGQUIT
TimeoutStopSec=5s

; Limit the number of file descriptors; see `man systemd.exec` for more limit settings.
LimitNOFILE=1048576
; Unmodified caddy is not expected to use more than that.
LimitNPROC=512

; Use private /tmp and /var/tmp, which are discarded after caddy stops.
PrivateTmp=true
; Use a minimal /dev (May bring additional security if switched to 'true', but it may not work on Raspberry Pi's or other devices, so it has been disabled in this dist.)
PrivateDevices=false
; Hide /home, /root, and /run/user. Nobody will steal your SSH-keys.
ProtectHome=true
; Make /usr, /boot, /etc and possibly some more folders read-only.
ProtectSystem=full
; … except /etc/ssl/caddy, because we want Letsencrypt-certificates there.
; This merely retains r/w access rights, it does not add any new. Must still be writable on the host!
ReadWritePaths=/etc/ssl/caddy
ReadWriteDirectories=/etc/ssl/caddy

; The following additional security directives only work with systemd v229 or later.
; They further restrict privileges that can be gained by caddy. Uncomment if you like.
; Note that you may have to add capabilities required by any plugins in use.
;CapabilityBoundingSet=CAP_NET_BIND_SERVICE
;AmbientCapabilities=CAP_NET_BIND_SERVICE
;NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

Set permissions
```
chown root:root /etc/systemd/system/caddy.service
```
```
chmod 644 /etc/systemd/system/caddy.service
```
Reload systemd to detect the newly added service
```
systemctl daemon-reload
```

### Step 5 ) Install and configure V2Ray

Create a temp folder

```
mkdir temp
```

Download the installation files

```
wget https://github.com/v2fly/v2ray-core/releases/download/v5.1.0/v2ray-linux-64.zip
wget https://github.com/v2fly/geoip/releases/latest/download/geoip.dat
wget https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat
```

Unzip V2ray in temp folder

```
unzip -q v2ray-linux-64.zip -d temp
```

Install V2Ray
```
install -m 755 temp/v2ray /usr/local/bin/v2ray
install -m 644 temp/geoip.dat /usr/local/share/v2ray
install -m 644 temp/geosite.dat /usr/local/share/v2ray
install -d /usr/local/etc/v2ray
echo "{}" > /usr/local/etc/v2ray/config.json
```

To store V2Ray log files
```
install -d -m 700 -o nobody -g nogroup /var/log/v2ray/
install -m 600 -o nobody -g nogroup /dev/null /var/log/v2ray/access.log
install -m 600 -o nobody -g nogroup /dev/null /var/log/v2ray/error.log
```

Install startup service file, first command is the start command.
```
/usr/local/bin/v2ray
install -m 644 "/temp/systemd/system/v2ray.service" /etc/systemd/system/v2ray.service
install -m 644 "/temp/systemd/system/v2ray@.service" /etc/systemd/system/v2ray@.service
mkdir -p '/etc/systemd/system/v2ray.service.d'
mkdir -p '/etc/systemd/system/v2ray@.service.d/'
```

Update the 10-donot_touch_single_conf.conf file in both service directories

```
nano /etc/systemd/system/v2ray.service.d/10-donot_touch_single_conf.conf
```

to

```
[Service]
ExecStart=
ExecStart=/usr/local/bin/v2ray run -config /usr/local/etc/v2ray/config.json
```

REMEMBER to do the same to /etc/systemd/system/v2ray@.service.d/10-donot_touch_single_conf.conf

Reload SystemCtl

```
systemctl daemon-reload
```


Lets test what has been done so far!

Start V2Ray
```
systemctl start v2ray.service
```

Check the status! If it says "active (running)" in green, then we are almost there.
```
systemctl status v2ray.service
```

Now stop it, we got more work to do!
```
systemctl stop v2ray.service
```

Download other config files in a new temp directory
```
mkdir temp2
cd temp2
wget https://github.com/v2fly/geoip/releases/latest/download/geoip.dat
wget https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat
```

Install downloaded geoip and dlc files
```
cd
mkdir /usr/local/share/v2ray
install -m 644 temp2/geoip.dat /usr/local/share/v2ray
install -m 644 temp2/dlc.dat /usr/local/share/v2ray/geosite.dat
```

Backup the original V2Ray configuration file
```
cp /usr/local/etc/v2ray/config.json /usr/local/etc/v2ray/config.json.bak
```

Clear the original file and open
```
rm /usr/local/etc/v2ray/config.json && nano /usr/local/etc/v2ray/config.json
```

Paste this and follow along to modify values with $

```javascript
{
  "log": {
    "loglevel": "warning",
    "error": "/var/log/v2ray/error.log",
    "access": "/var/log/v2ray/access.log"
  },
  "dns": {},
  "stats": {},
  "inbounds": [
    {
      "settings": {
        "clients": [
          {
            "alterId": 0,
            "id": $CLIENT_ID,
            "level":0
          }
        ]
      },
      "port": $CLIENT_PORT ,
      "streamSettings": {
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/usr/local/etc/v2ray/v2ray.crt",
              "keyFile": "/usr/local/etc/v2ray/v2ray.key"
            }
          ]
        },
        "network": "tcp"
      },
      "protocol": "vmess"
    }
  ],
  "outbounds": [
    {
      "protocol": "vmess",
      "sendThrough": "0.0.0.0",
      "settings": {
        "vnext": [
          {
            "address": $OUTBOUND_ADDRESS,
            "port": $OUTBOUND_PORT,
            "users": [
              {
                "id": $OUTBOUND_ID,
                "alterId": 0
              }
            ]
          }
        ]
      },
      "streamSettings": {
        "security": "tls",
        "tlsSettings": {
          "serverName": $OUTBOUND_ADDRESS
        },
        "xtlsSettings": {
          "serverName": $OUTBOUND_ADDRESS
        }
      }
    },
    {
      "tag": "blocked",
      "protocol": "blackhole",
      "settings": {}
    }
  ],
  "routing": {
    "rules": [
      {
        "outboundTag": "blocked",
        "ip": [
          "geoip:private"
        ],
        "type": "field"
      }
    ]
  },
  "policy": {},
  "reverse": {},
  "transport": {}
}
```
$CLIENT_ID is the id your clients will use to connect to your Server A. You can generate an id (UUID Version 1) from here: https://www.uuidgenerator.net/ or on server A
```
v2ray uuid
```

$CLIENT_PORT is the port your clients will use to connect to your Server A. Use a number between 30000 - 50000. You'll need this number in the next step.

$OUTBOUND_ADDRESS: FQDN (sub-domain) of Server B.

$OUTBOUND_PORT: Server B port.

$OUTBOUND_ID: Server B id.


### Step 6) Configure Caddy

Add Caddy configuration file
```
nano /etc/caddy/Caddyfile
```

Update the file to:
```javascript
http://sub.domain.com {
    redir https://sub.domain.com{url}
}
https://sub.domain.com {
    tls $EMAIL
    log /var/log/caddy.log
    root /var/www/html
    proxy / https://localhost:$CLIENT_PORT {
    insecure_skip_verify
    header_upstream X-Forwarded-Proto "https"
    header_upstream Host "sub.domain.com"
  }
  header / {
    Strict-Transport-Security "max-age=31536000;"
    X-XSS-Protection "1; mode=block"
    X-Content-Type-Options "nosniff"
    X-Frame-Options "DENY"
  }
}
```

Replace sub.domain.com with the subdomain you created for your Server A.

Replace $CLIENT_PORT with the port number you chose from previous step.

Replace $EMAIL with an email address you wish to receive SSL renewal notices. I wouldn't use my personal email or any email that makes me identifiable.

Give Caddy configuration file the proper permissions
```
chown root:root /etc/caddy/Caddyfile
chmod 644 /etc/caddy/Caddyfile
```

Reload SystemCtl
```
systemctl daemon-reload
```

Start Caddy
```
systemctl start caddy
```

Check Caddy status
```
systemctl status caddy
```

Self start Caddy
```
systemctl enable caddy
```

### Step 7 ) SSL

Link SSL path - Replace sub.domain.com with your FQDN
```
ln /etc/ssl/caddy/acme/acme-v02.api.letsencrypt.org/sites/sub.domain.com/sub.domain.com.crt /usr/local/etc/v2ray/v2ray.crt

ln /etc/ssl/caddy/acme/acme-v02.api.letsencrypt.org/sites/sub.domain.com/sub.domain.com.key /usr/local/etc/v2ray/v2ray.key
```

Give proper permissions
```
chown root:root /usr/local/etc/v2ray/v2ray.crt
chown root:root /usr/local/etc/v2ray/v2ray.key
chmod 644 /usr/local/etc/v2ray/v2ray.crt
chmod 644 /usr/local/etc/v2ray/v2ray.key
```

### Step 8) Start and Test

Reload
```
systemctl daemon-reload
```

Start V2Ray
```
systemctl start v2ray
```

Check status
```
systemctl status v2ray
```

### Server B Setup

Server B setup is almost the same as server A with minor differences.

- pick a new subdomain for Server B. (this will be )
- pick a new port to connect server A to server B. this will be used in server A config file as well.
- pick a new uuid for server B. this will be used in server A config file as well.


### To Be Added:
- Server B Setup
- Mitigate Port Scan
- QR Code Generation
