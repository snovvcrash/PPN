# Infrastructure

- [https://ditrizna.medium.com/design-and-setup-of-c2-traffic-redirectors-ec3c11bd227d](https://ditrizna.medium.com/design-and-setup-of-c2-traffic-redirectors-ec3c11bd227d)
- [https://byt3bl33d3r.substack.com/p/taking-the-pain-out-of-c2-infrastructure-3c4](https://byt3bl33d3r.substack.com/p/taking-the-pain-out-of-c2-infrastructure-3c4)




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
$ sudo apt install caddy certbot
```

Config sample to act as a reverse proxy:

```
{
    log
	#debug
    admin off
    auto_https disable_redirects
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
    import proxy-upstream
    tls /etc/letsencrypt/live/example.com/fullchain.pem /etc/letsencrypt/live/example.com/privkey.pem
}
```
