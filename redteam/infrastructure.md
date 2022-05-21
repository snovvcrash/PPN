# Infrastructure

- [https://ditrizna.medium.com/design-and-setup-of-c2-traffic-redirectors-ec3c11bd227d](https://ditrizna.medium.com/design-and-setup-of-c2-traffic-redirectors-ec3c11bd227d)
- [https://byt3bl33d3r.substack.com/p/taking-the-pain-out-of-c2-infrastructure-3c4](https://byt3bl33d3r.substack.com/p/taking-the-pain-out-of-c2-infrastructure-3c4)




## Nebula

- [https://notes.huskyhacks.dev/blog/red-team-infrastructure-done-right](https://notes.huskyhacks.dev/blog/red-team-infrastructure-done-right)
- [https://github.com/slackhq/nebula/releases](https://github.com/slackhq/nebula/releases)

Install:

```
$ sudo mkdir -p /opt/nebula/certs
$ sudo eget -s linux/amd64 --download-only slackhq/nebula --to /opt/nebula && cd /opt/nebula
$ sudo tar -xzvf nebula-linux-amd64.tar.gz && sudo rm nebula-linux-amd64.tar.gz
$ sudo mv nebula-cert certs
```

Make certs for the **lighthouse**, **teamserver** and **proxy** (redirector):

```
$ sudo ./nebula-cert ca -name 'hax0r1337, Inc.'
$ sudo ./nebula-cert sign -name lighthouse -ip "10.10.13.1/24"
$ sudo ./nebula-cert sign -name teamserver -ip "10.10.13.2/24" -groups "teamservers"
$ sudo ./nebula-cert sign -name proxy1 -ip "10.10.13.37/24" -groups "proxies"
```

Configs:

{% tabs %}
{% tab title="Lighthouse" %}
{% code title="lighthouse.yml" %}
```yml
pki:
  ca: /opt/nebula/certs/ca.crt
  cert: /opt/nebula/certs/lighthouse.crt
  key: /opt/nebula/certs/lighthouse.key

static_host_map:
  "10.10.13.1": ["<LIGHTHOUSE_IP>:4242"]

lighthouse:
  am_lighthouse: true

listen:
  host: 0.0.0.0
  port: 4242

punchy:
  punch: true

tun:
  disabled: false
  dev: nebula1
  drop_local_broadcast: false
  drop_multicast: false
  tx_queue: 500
  mtu: 1300
  routes:
  unsafe_routes:

logging:
  level: info
  format: text

firewall:
  conntrack:
    tcp_timeout: 12m
    udp_timeout: 3m
    default_timeout: 10m
    max_connections: 100000

  outbound:
    - port: any
      proto: any
      host: any

  inbound:
    - port: any
      proto: icmp
      host: any
    
    - port: 4789
      proto: any
      host: any

    - port: 22
      proto: any
      cidr: 10.10.13.0/24
```
{% endcode %}
{% endtab %}
{% tab title="Teamserver" %}
{% code title="teamserver.yml" %}
```yml
pki:
  ca: /opt/nebula/certs/ca.crt
  cert: /opt/nebula/certs/teamserver.crt
  key: /opt/nebula/certs/teamserver.key

static_host_map:
  "10.10.13.1": ["<LIGHTHOUSE_IP>:4242"]

lighthouse:
  am_lighthouse: false
  interval: 60
  hosts:
    - "192.168.100.1"

listen:
  host: 0.0.0.0
  port: 4242

punchy:
  punch: true

tun:
  disabled: false
  dev: nebula1
  drop_local_broadcast: false
  drop_multicast: false
  tx_queue: 500
  mtu: 1300
  routes:
  unsafe_routes:

logging:
  level: info
  format: text

firewall:
  conntrack:
    tcp_timeout: 12m
    udp_timeout: 3m
    default_timeout: 10m
    max_connections: 100000

  outbound:
    - port: any
      proto: any
      host: any

  inbound:
    - port: any
      proto: icmp
      host: any

    - port: 80
      proto: any
      host: any

    - port: 443
      proto: any
      host: any

    - port: 4789
      proto: any
      host: any

    - port: 22
      proto: any
      cidr: 10.10.13.0/24
```
{% endcode %}
{% endtab %}
{% tab title="Proxy" %}
{% code title="proxy1.yml" %}
```yml
pki:
  ca: /opt/nebula/certs/ca.crt
  cert: /opt/nebula/certs/proxy1.crt
  key: /opt/nebula/certs/proxy1.key

static_host_map:
  "10.10.13.1": ["<LIGHTHOUSE_IP>:4242"]

lighthouse:
  am_lighthouse: false
  interval: 60
  hosts:
    - "192.168.100.1"

listen:
  host: 0.0.0.0
  port: 4242

punchy:
  punch: true

tun:
  disabled: false
  dev: nebula1
  drop_local_broadcast: false
  drop_multicast: false
  tx_queue: 500
  mtu: 1300
  routes:
  unsafe_routes:

logging:
  level: info
  format: text

firewall:
  conntrack:
    tcp_timeout: 12m
    udp_timeout: 3m
    default_timeout: 10m
    max_connections: 100000

  outbound:
    - port: any
      proto: any
      host: any

  inbound:
    - port: any
      proto: icmp
      host: any

    - port: 80
      proto: any
      host: any

    - port: 443
      proto: any
      host: any

    - port: 4789
      proto: any
      host: any

    - port: 22
      proto: any
      cidr: 10.10.13.0/24
```
{% endcode %}
{% endtab %}
{% endtabs %}

Systemd [unit](https://github.com/slackhq/nebula/blob/master/examples/quickstart-vagrant/ansible/roles/nebula/files/systemd.nebula.service):

```
[Unit]
Description=nebula
Wants=basic.target
After=basic.target network.target

[Service]
SyslogIdentifier=nebula
ExecReload=/bin/kill -HUP $MAINPID
ExecStart=/opt/nebula/nebula -config /opt/nebula/<CONFIG>.yml
Restart=always

[Install]
WantedBy=multi-user.target
```




## Caddy

- [https://byt3bl33d3r.substack.com/p/taking-the-pain-out-of-c2-infrastructure](https://byt3bl33d3r.substack.com/p/taking-the-pain-out-of-c2-infrastructure)
- [https://caddyserver.com/docs/install](https://caddyserver.com/docs/install)
- [https://github.com/caddyserver/caddy/releases](https://github.com/caddyserver/caddy/releases)
- [https://improsec.com/tech-blog/staging-cobalt-strike-with-mtls-using-caddy](https://improsec.com/tech-blog/staging-cobalt-strike-with-mtls-using-caddy)
- [https://github.com/improsec/CaddyStager](https://github.com/improsec/CaddyStager)

Install:

```
$ sudo apt install debian-keyring debian-archive-keyring apt-transport-https -y
$ curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo tee /etc/apt/trusted.gpg.d/caddy-stable.asc
$ curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
$ sudo apt update
$ sudo apt install caddy -y
$ sudo rm /etc/caddy/Caddyfile && sudo vi /etc/caddy/Caddyfile
$ sudo systemctl restart caddy
$ sudo systemctl status caddy
```

Manually requesting Let's Encrypt certificate:

```
$ sudo apt install certbot -y
$ sudo certbot certonly --standalone -d example.com --register-unsafely-without-email --agree-tos
$ sudo mkdir -p /opt/caddy/ssl
$ sudo cp /etc/letsencrypt/live/example.com/{fullchain.pem,privkey.pem} /opt/caddy/ssl
$ sudo chown -R caddy:caddy /opt/caddy
```

Config sample to act as a reverse proxy:

{% code title="/etc/caddy/Caddyfile" %}
```
{
    log
    #debug
    admin off
    #auto_https disable_redirects
}

(logging) {
    log {
        output file /var/log/caddy-{args.0}-access.log {
            roll true
            roll_size 1Mib
            roll_local_time true
            roll_keep 24
            roll_keep_for 7d
        }
    }
}

(proxy-upstream) {
    @ua_denylist {
        header User-Agent curl*
    }
        
    @ip_denylist {
        remote_ip 8.8.8.8/32
    }
        
    header {
        -Server
        +X-Robots-Tag "noindex, nofollow, nosnippet, noarchive"
        +X-Content-Type-Options "nosniff"
    }
        
    respond @ua_denylist "Forbidden" 403 {
        close
    }
        
    respond @ip_denylist "Forbidden" 403 {
        close
    }
        
    reverse_proxy https://10.10.13.37:31337 {
        header_up Host {upstream_hostport}
        header_up X-Forwarded-Host {host}
        header_up X-Forwarded-Port {port}
        transport http {
            tls_insecure_skip_verify
        }
    }
}

https://example.com {
    import logging all
    #tls /opt/caddy/ssl/fullchain.pem /opt/caddy/ssl/privkey.pem

    handle /files/* {
        file_server {
            # there should be this "files" directory in root
            root /home/snovvcrash/www
            #browse
        }
    }

    handle {
        import proxy-upstream
    }
}
```
{% endcode %}
