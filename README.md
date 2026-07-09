# DNS Server

A compact Linux-only DNS proxy and local-record resolver written in strict C++11.

The server listens on IPv4:

- UDP DNS on port `53`
- TCP DNS-over-TLS on port `853`

Local records are answered directly from the configured RFC-style zone file. When the configured file exists, local authoritative mode is enabled: every valid query is answered exclusively from that file and there is no fallback to the upstream resolver. If the selected config file does not exist, the server runs as a DNS forwarder. Upstream forwarding attempts DNS-over-TLS first and falls back to plain DNS UDP/TCP if the upstream TLS path is unavailable.

## Dependencies

### Debian / Ubuntu

```bash
apt update
apt install -y build-essential libssl-dev pkg-config libcap2-bin
```

### Arch Linux

```bash
pacman -S --needed base-devel openssl pkgconf libcap
```

## Build

```bash
make
```

The compiled binary is created in the project directory:

```bash
./dns_server
```

The Makefile builds with:

```text
g++ -std=c++11 -O3 -flto -DNDEBUG -pipe -pthread -Wall -Wextra
```

and links against OpenSSL.

## Run

Run with the default config path:

```bash
./dns_server
```

Run with an explicit local-record config file:

```bash
./dns_server -c /path/to/config
```

or:

```bash
./dns_server --config /path/to/config
```

If the selected config file does not exist, the process logs the missing file and continues as a raw DNS forwarder. If the selected config file exists, the process enables local authoritative mode and will not forward unanswered names or types upstream.

## Local-record config format

The config file accepts standard zone-file style records, including `$ORIGIN`, `$TTL`, comments beginning with `;` outside quoted strings, relative owner names, `@`, omitted per-record TTLs, `IN`, quoted text fields, and parenthesized multiline records:

```zone
$ORIGIN example.com.
$TTL 3600

@ IN SOA ns1.example.com. admin.example.com. (
    2025070801
    3600
    1800
    604800
    3600
)

4.3.2.0.in-addr.arpa. IN PTR www.example.com.

_443._tcp.www  IN TLSA   3 1 1 1234567890abcdef1234567890abcdef
afsdb          IN AFSDB  1 afsdb.example.com.
alias          IN CNAME  www.example.com.
apl            IN APL    1:192.0.2.0/24 !1:192.0.2.128/25 2:2001:db8::/32
cert           IN CERT   PKIX 0 0 AQIDBAUGBwg=
hinfo          IN HINFO  "x86_64" "Linux"
@              IN CAA    0 iodef "mailto:security@example.com"
@              IN CAA    0 issue "letsencrypt.org"
@              IN CAA    0 issuewild ";"
@              IN CDNSKEY 257 3 13 AQIDBAUGBwgJCgsM
@              IN CDS    12345 13 2 1234567890abcdef1234567890abcdef
@              IN DNSKEY 257 3 13 AQIDBAUGBwgJCgsM
@              IN DS     12345 13 2 1234567890abcdef1234567890abcdef
@              IN MX     10 mail.example.com.
@              IN NS     ns1.example.com.
@              IN TXT    "google-site-verification=1234567890abcdef"
@              IN TXT    "v=spf1 include:_spf.example.com mx -all"
loc            IN LOC    37 46 9.123 N 122 25 8.456 W 100m 20m 100m 20m
naptr          IN NAPTR  100 50 "s" "SIP+D2U" "" _sip._udp.example.com.
ns1            IN A      192.0.2.53
_sip._tcp      IN SRV    10 60 5060 sip.example.com.
sshfp          IN SSHFP  4 2 1234567890abcdef1234567890abcdef
subzone        IN DNAME  example.net.
www            IN A      192.0.2.1
www            IN NSEC   alias.example.com. A RRSIG NSEC
www            IN RRSIG  A 13 2 3600 20250709000000 20250708000000 12345 example.com. AQIDBAUGBwgJCgsM
```

## Binary and text field notes:

- CERT, DNSKEY, CDNSKEY, and RRSIG use base64 data. Parentheses may be used to split long base64 data across lines.
- DS, CDS, SSHFP, and TLSA use hexadecimal data. Whitespace inside parenthesized multiline hexadecimal data is ignored.
- TXT, HINFO, NAPTR, and CAA text-like fields should be quoted when they contain spaces, semicolons, or other punctuation.
- Name-bearing fields are expanded relative to $ORIGIN unless they end in a trailing dot.
- Class must be IN when a class is specified.

Rules:

- Class must be `IN` when a class is specified.
- `$TTL` supplies the default TTL for subsequent records; per-record numeric TTLs and `s`, `m`, `h`, `d`, `w` suffixes are accepted.
- `$ORIGIN` controls relative owner names and relative target names.
- A trailing dot marks an absolute DNS name.
- When the file exists, unanswered names return authoritative `NXDOMAIN`; existing names without the requested type return authoritative empty `NOERROR`.
- DNSSEC and certificate-style binary fields use standard base64 or hexadecimal presentation data, depending on the RR type.

## Optional tuning environment variables

These variables tune performance, cache behavior, timeouts, and logging. They do not replace source-level DNS endpoint values and do not replace `-c` config loading.

```text
DNS_VERBOSE=1
DNS_WORKERS=<1-128>
DNS_UDP_MSG_MAX=<512-65535>
DNS_CACHE_KEY_MAX=<64-65533>
DNS_CACHE_RESP_MAX=<512-65535>
DNS_CACHE_STRIPES=<1-4096>
DNS_CACHE_WAYS=<1-64>
DNS_DOT_POOL_SIZE=<1-128>
DNS_MAX_WORK_QUEUE=<64-262144>
DNS_SOCKET_BUFFER_BYTES=<65536-4194304>
DNS_UPSTREAM_CONNECT_TIMEOUT_SECONDS=<1-30>
DNS_UPSTREAM_IO_TIMEOUT_SECONDS=<1-60>
```

Example:

```bash
DNS_WORKERS=8 DNS_VERBOSE=1 ./dns_server -c /etc/dns_server/config
```

## Install and systemd service

Build, install to `/usr/bin/dns_server`, create `/etc/dns_server`, install the systemd unit, and start the service:

```bash
sudo make deploy
```

The service unit is installed at:

```text
/usr/lib/systemd/system/dns-server.service
```

Useful service commands:

```bash
systemctl status dns-server.service
systemctl restart dns-server.service
journalctl -u dns-server.service -f
```

Uninstall the binary and service:

```bash
sudo make uninstall
```

## Clean

```bash
make clean
```
