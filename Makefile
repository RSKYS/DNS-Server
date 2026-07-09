.ONESHELL:
SHELL          := /bin/bash

CXX            ?= g++
PKG_CONFIG     ?= pkg-config

TARGET         := dns_server
SRC            := dns-server.cpp

BINDIR         := /usr/bin
BIN_PATH       := $(BINDIR)/$(TARGET)

SYSTEMD_DIR    := /usr/lib/systemd/system
SERVICE_NAME   := dns-server.service
SERVICE_PATH   := $(SYSTEMD_DIR)/$(SERVICE_NAME)

OPENSSL_CFLAGS := $(shell $(PKG_CONFIG) --cflags openssl 2>/dev/null)
OPENSSL_LIBS   := $(shell $(PKG_CONFIG) --libs openssl 2>/dev/null || printf '%s\n' '-lssl -lcrypto')

CXXFLAGS       := -std=c++11 -O3 -DNDEBUG -pipe -pthread -Wall -Wextra \
                  -fstack-protector-strong -fomit-frame-pointer \
                  -ffunction-sections -fdata-sections $(OPENSSL_CFLAGS)

LDFLAGS        := -Wl,-O1 -Wl,--as-needed -Wl,--gc-sections
LDLIBS         := $(OPENSSL_LIBS) -pthread

.PHONY: all preflight build install service-deploy service-install load clean uninstall
.NOTPARALLEL: all install service-install load clean uninstall

all:
	set -e
	$(MAKE) clean
	$(MAKE) build
	$(MAKE) service-install
	$(MAKE) load
	$(MAKE) clean

preflight:
	@command -v $(CXX) >/dev/null 2>&1 || { \
		echo 'error: g++ was not found. Install build-essential/base-devel first.' >&2; \
		exit 1; \
	}
	@printf '%s\n' '#include <openssl/bn.h>' 'int main() { return 0; }' | \
		$(CXX) -std=c++11 -x c++ -fsyntax-only - $(OPENSSL_CFLAGS) >/dev/null 2>&1 || { \
		echo 'error: OpenSSL development headers were not found: missing <openssl/bn.h>' >&2; \
		echo 'Debian/Ubuntu: apt update && apt install -y build-essential libssl-dev pkg-config libcap2-bin' >&2; \
		echo 'Arch Linux:    pacman -S --needed base-devel openssl pkgconf libcap' >&2; \
		exit 1; \
	}

build: preflight $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS) $(LDLIBS)

install: build
	install -Dm755 $(TARGET) $(BIN_PATH)
	install -d -m 755 /etc/dns_server
	touch /etc/dns_server/config
	setcap 'cap_net_bind_service=+ep' $(BIN_PATH) || true

service-deploy:
	cat > $(SERVICE_NAME) <<-SERVICE_EOF
	[Unit]
	Description=DNS Server
	After=network-online.target
	Wants=network-online.target

	[Service]
	Type=simple
	ExecStart=$(BIN_PATH)
	Restart=always
	RestartSec=1
	LimitNOFILE=1048576

	AmbientCapabilities=CAP_NET_BIND_SERVICE
	CapabilityBoundingSet=CAP_NET_BIND_SERVICE
	NoNewPrivileges=true

	ProtectSystem=strict
	ProtectHome=true
	ProtectKernelTunables=true
	ProtectKernelModules=true
	ProtectControlGroups=true
	LockPersonality=true
	RestrictRealtime=true
	RestrictSUIDSGID=true
	PrivateTmp=true

	[Install]
	WantedBy=multi-user.target
	SERVICE_EOF

service-install: install service-deploy
	install -Dm644 $(SERVICE_NAME) $(SERVICE_PATH)
	rm -f $(SERVICE_NAME)
	systemctl daemon-reload

load:
	systemctl enable $(SERVICE_NAME)
	systemctl restart $(SERVICE_NAME)

clean:
	rm -f $(TARGET) $(SERVICE_NAME)

uninstall:
	if command -v systemctl >/dev/null 2>&1; then \
		systemctl disable --now $(SERVICE_NAME) >/dev/null 2>&1 || true; \
	fi
	rm -f $(BIN_PATH) $(SERVICE_PATH) $(TARGET) $(SERVICE_NAME) || true
	if command -v systemctl >/dev/null 2>&1; then \
		systemctl daemon-reload >/dev/null 2>&1 || true; \
	fi
