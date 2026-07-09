#include <errno.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>
#include <arpa/inet.h>
typedef short int intS;

#ifndef DNS_HOST
#define DNS_HOST "0.0.0.0"
#endif

static const char* const DNS_VERBOSE_ENV = "DNS_VERBOSE";
static const char* const UPSTREAM_DNS = "1.1.1.1";
static const uint32_t RELOAD_INTERVAL_SECONDS = 90;
static const uint16_t DNS_PORT = 53;
static const uint16_t DOT_PORT = 853;
static const size_t WIRE_MAX = 65535;
static const size_t INLINE_REQ = 512;
static volatile sig_atomic_t g_running = 1;

static void on_signal(int) {
	g_running = 0;
}

static void install_signal_handlers() {
	struct sigaction sa;
	std::memset(&sa, 0, sizeof(sa));	
	sa.sa_handler = on_signal;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	signal(SIGPIPE, SIG_IGN);
}

static uint32_t monotonic_seconds() {
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
		return static_cast<uint32_t>(std::time(NULL));
	}
	return static_cast<uint32_t>(ts.tv_sec);
}

static size_t clamp_size(size_t value, size_t low, size_t high) {
	return std::max(low, std::min(value, high));
}

static int clamp_int(int value, int low, int high) {
	return std::max(low, std::min(value, high));
}

static bool parse_size_env(const char* name, size_t& out) {
	const char* s = std::getenv(name);
	if (s == NULL || *s == '\0') {
		return false;
	}
	char* end = NULL;
	errno = 0;
	unsigned long long v = std::strtoull(s, &end, 10);
	if (errno != 0 || end == s) {
		return false;
	}
	while (*end != '\0' && std::isspace(static_cast<unsigned char>(*end))) {
		++end;
	}
	if (*end != '\0') {
		return false;
	}
	out = static_cast<size_t>(v);
	return true;
}

static bool parse_int_env(const char* name, int& out) {
	size_t v = 0;
	if (!parse_size_env(name, v)) {
		return false;
	}
	if (v > static_cast<size_t>(std::numeric_limits<int>::max())) {
		return false;
	}
	out = static_cast<int>(v);
	return true;
}

static size_t next_power_of_two(size_t v) {
	if (v <= 1) {
		return 1;
	}
	--v;
	for (size_t shift = 1; shift < sizeof(size_t) * 8; shift <<= 1) {
		v |= v >> shift;
	}
	return v + 1;
}

static size_t online_cpu_count() {
	long n = sysconf(_SC_NPROCESSORS_ONLN);
	if (n > 0) {
		return static_cast<size_t>(n);
	}
	unsigned int hc = std::thread::hardware_concurrency();
	return hc == 0 ? 1 : static_cast<size_t>(hc);
}

static uint64_t physical_ram_bytes() {
	long pages = sysconf(_SC_PHYS_PAGES);
	long page_size = sysconf(_SC_PAGESIZE);
	if (pages <= 0 || page_size <= 0) {
		return 0;
	}
	return static_cast<uint64_t>(pages) * static_cast<uint64_t>(page_size);
}

struct RuntimeConfig {
	std::string listen_ip;
	std::string upstream_dns;
	uint16_t dns_port;
	uint16_t dot_port;
	bool upstream_dot;
	bool listen_dot;
	size_t workers;
	size_t udp_msg_max;
	size_t cache_key_max;
	size_t cache_resp_max;
	size_t cache_stripes;
	size_t cache_ways;
	size_t dot_pool_size;
	size_t max_work_queue;
	int socket_buffer_bytes;
	intS upstream_connect_timeout_seconds;
	intS upstream_io_timeout_seconds;
	std::string config_path;

	static RuntimeConfig load(int argc, char** argv) {
		RuntimeConfig cfg;
		const size_t cpus = online_cpu_count();
		const uint64_t ram = physical_ram_bytes();
		const bool low_end = (cpus <= 1) || (ram != 0 && ram <= 1536ULL * 1024ULL * 1024ULL);

		cfg.listen_ip = DNS_HOST;

		cfg.upstream_dns = UPSTREAM_DNS;

		cfg.config_path = "/etc/dns_server/config";
		for (int i = 1; i < argc; ++i) {
			std::string arg = argv[i] == NULL ? std::string() : std::string(argv[i]);
			if (arg == "-c" || arg == "--config") {
				if (i + 1 >= argc || argv[i + 1] == NULL || argv[i + 1][0] == '\0') {
					throw std::runtime_error("missing config path after " + arg);
				}
				cfg.config_path = argv[++i];
			} else {
				throw std::runtime_error("unknown argument: " + arg);
			}
		}

		cfg.dns_port = DNS_PORT;
		cfg.dot_port = DOT_PORT;

		cfg.upstream_dot = false;
		cfg.listen_dot = true;

		cfg.workers = low_end ? 4 : std::min<size_t>(32, std::max<size_t>(4, cpus * 2));
		cfg.udp_msg_max = low_end ? 4096 : 8192;
		cfg.cache_key_max = low_end ? 512 : 1024;
		cfg.cache_resp_max = low_end ? 4096 : 8192;
		cfg.cache_stripes = low_end ? 64 : 256;
		cfg.cache_ways = low_end ? 8 : 16;
		cfg.dot_pool_size = low_end ? 2 : std::min<size_t>(16, cfg.workers);
		cfg.max_work_queue = low_end ? 2048 : 16384;
		cfg.socket_buffer_bytes = low_end ? 256 * 1024 : 1024 * 1024;
		cfg.upstream_connect_timeout_seconds = low_end ? 2 : 4;
		cfg.upstream_io_timeout_seconds = low_end ? 4 : 5;

		size_t v = 0;
		if (parse_size_env("DNS_WORKERS", v)) {
			cfg.workers = clamp_size(v, 1, 128);
		}
		if (parse_size_env("DNS_UDP_MSG_MAX", v)) {
			cfg.udp_msg_max = clamp_size(v, 512, WIRE_MAX);
		}
		if (parse_size_env("DNS_CACHE_KEY_MAX", v)) {
			cfg.cache_key_max = clamp_size(v, 64, WIRE_MAX - 2);
		}
		if (parse_size_env("DNS_CACHE_RESP_MAX", v)) {
			cfg.cache_resp_max = clamp_size(v, 512, WIRE_MAX);
		}
		if (parse_size_env("DNS_CACHE_STRIPES", v)) {
			cfg.cache_stripes = clamp_size(v, 1, 4096);
		}
		if (parse_size_env("DNS_CACHE_WAYS", v)) {
			cfg.cache_ways = clamp_size(v, 1, 64);
		}
		if (parse_size_env("DNS_DOT_POOL_SIZE", v)) {
			cfg.dot_pool_size = clamp_size(v, 1, 128);
		}
		if (parse_size_env("DNS_MAX_WORK_QUEUE", v)) {
			cfg.max_work_queue = clamp_size(v, 64, 262144);
		}
		int iv = 0;
		if (parse_int_env("DNS_UPSTREAM_DOT", iv)) {
			cfg.upstream_dot = iv != 0;
		}
		if (parse_int_env("DNS_LISTEN_DOT", iv)) {
			cfg.listen_dot = iv != 0;
		}
		if (parse_int_env("DNS_SOCKET_BUFFER_BYTES", iv)) {
			cfg.socket_buffer_bytes = clamp_int(iv, 64 * 1024, 4 * 1024 * 1024);
		}
		if (parse_int_env("DNS_UPSTREAM_CONNECT_TIMEOUT_SECONDS", iv)) {
			cfg.upstream_connect_timeout_seconds = static_cast<intS>(clamp_int(iv, 1, 30));
		}
		if (parse_int_env("DNS_UPSTREAM_IO_TIMEOUT_SECONDS", iv)) {
			cfg.upstream_io_timeout_seconds = static_cast<intS>(clamp_int(iv, 1, 60));
		}

		cfg.cache_stripes = next_power_of_two(cfg.cache_stripes);
		cfg.dot_pool_size = cfg.upstream_dot ? std::max<size_t>(1, cfg.dot_pool_size) : 0;
		return cfg;
	}
};

class UniqueFd {
	int fd_;

	UniqueFd(const UniqueFd&);
	UniqueFd& operator=(const UniqueFd&);

public:
	UniqueFd() : fd_(-1) {}
	explicit UniqueFd(int fd) : fd_(fd) {}

	UniqueFd(UniqueFd&& other) : fd_(other.fd_) {
		other.fd_ = -1;
	}

	UniqueFd& operator=(UniqueFd&& other) {
		if (this != &other) {
			reset(other.fd_);
			other.fd_ = -1;
		}
		return *this;
	}

	~UniqueFd() {
		reset();
	}

	int get() const {
		return fd_;
	}

	bool valid() const {
		return fd_ >= 0;
	}

	int release() {
		int fd = fd_;
		fd_ = -1;
		return fd;
	}

	void reset(int fd = -1) {
		if (fd_ >= 0) {
			::close(fd_);
		}
		fd_ = fd;
	}
};

struct OpenSslDeleter {
	void operator()(SSL_CTX* p) const { if (p) SSL_CTX_free(p); }
	void operator()(SSL* p) const { if (p) SSL_free(p); }
	void operator()(X509* p) const { if (p) X509_free(p); }
	void operator()(EVP_PKEY* p) const { if (p) EVP_PKEY_free(p); }
	void operator()(EVP_PKEY_CTX* p) const { if (p) EVP_PKEY_CTX_free(p); }
};

template <typename T>
using SslPtr = std::unique_ptr<T, OpenSslDeleter>;

class Logger {
public:
	enum Level {
		INFO,
		REQ,
		RES,
		CACHE,
		WARN,
		ERROR
	};

private:
	static std::mutex mtx_;

	static bool verbose_cached() {
		static intS enabled = []() -> intS {
			const char* v = std::getenv(DNS_VERBOSE_ENV);
			return (v != NULL && v[0] != '\0' && std::strcmp(v, "0") != 0) ? 1 : 0;
		}();
		return enabled != 0;
	}

	static bool should_log(Level level) {
		return level == INFO || level == WARN || level == ERROR || verbose_cached();
	}

	static const char* level_name(Level level) {
		switch (level) {
			case INFO:  return "[INFO]";
			case REQ:   return "[REQ]";
			case RES:   return "[RES]";
			case CACHE: return "[CACHE]";
			case WARN:  return "[WARN]";
			case ERROR: return "[ERROR]";
		}
		return "[INFO]";
	}

public:
	static bool verbose() {
		return verbose_cached();
	}

	static bool enabled(Level level) {
		return should_log(level);
	}

	static void log(Level level, const std::string& message) {
		if (!should_log(level)) {
			return;
		}

		std::lock_guard<std::mutex> lock(mtx_);
		char timestamp[32];
		std::time_t now = std::time(NULL);
		struct tm local_tm;
		if (localtime_r(&now, &local_tm) == NULL) {
			std::strncpy(timestamp, "0000-00-00 00:00:00", sizeof(timestamp));
			timestamp[sizeof(timestamp) - 1] = '\0';
		} else {
			std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &local_tm);
		}
		std::cout << "[" << timestamp << "] " << level_name(level) << " " << message << std::endl;
	}
};

std::mutex Logger::mtx_;

static bool set_nonblocking(int fd) {
	int flags = fcntl(fd, F_GETFL, 0);
	return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

static void set_cloexec(int fd) {
	int flags = fcntl(fd, F_GETFD, 0);
	if (flags >= 0) {
		fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
	}
}

static void set_socket_buffers(int fd, int bytes) {
	setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bytes, sizeof(bytes));
	setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bytes, sizeof(bytes));
}

static bool connect_with_timeout(int fd, const struct sockaddr* addr, socklen_t addrlen, intS seconds) {
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0) {
		return false;
	}
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
		return false;
	}

	int rc = connect(fd, addr, addrlen);
	if (rc == 0) {
		return fcntl(fd, F_SETFL, flags) == 0;
	}
	if (errno != EINPROGRESS) {
		fcntl(fd, F_SETFL, flags);
		return false;
	}

	fd_set wfds;
	FD_ZERO(&wfds);
	FD_SET(fd, &wfds);
	struct timeval tv;
	std::memset(&tv, 0, sizeof(tv));
	tv.tv_sec = seconds;

	rc = select(fd + 1, NULL, &wfds, NULL, &tv);
	if (rc <= 0) {
		fcntl(fd, F_SETFL, flags);
		if (rc == 0) {
			errno = ETIMEDOUT;
		}
		return false;
	}

	int err = 0;
	socklen_t errlen = sizeof(err);
	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen) < 0 || err != 0) {
		fcntl(fd, F_SETFL, flags);
		if (err != 0) {
			errno = err;
		}
		return false;
	}
	return fcntl(fd, F_SETFL, flags) == 0;
}

static bool set_reuse(int fd) {
	int opt = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
		return false;
	}
#ifdef SO_REUSEPORT
	setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#endif
	return true;
}

static void set_common_socket_opts(int fd, const RuntimeConfig& cfg) {
	int opt = 1;
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
	set_socket_buffers(fd, cfg.socket_buffer_bytes);
}

static void set_timeouts(int fd, intS seconds) {
	struct timeval tv;
	std::memset(&tv, 0, sizeof(tv));
	tv.tv_sec = seconds;
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

static inline uint16_t be16(const uint8_t* p) {
	return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | static_cast<uint16_t>(p[1]));
}

static inline uint32_t be32(const uint8_t* p) {
	return (static_cast<uint32_t>(p[0]) << 24) |
		   (static_cast<uint32_t>(p[1]) << 16) |
		   (static_cast<uint32_t>(p[2]) << 8) |
			static_cast<uint32_t>(p[3]);
}

static inline void put_be16(uint8_t* p, uint16_t value) {
	p[0] = static_cast<uint8_t>((value >> 8) & 0xff);
	p[1] = static_cast<uint8_t>(value & 0xff);
}

static inline void put_be32(uint8_t* p, uint32_t value) {
	p[0] = static_cast<uint8_t>((value >> 24) & 0xff);
	p[1] = static_cast<uint8_t>((value >> 16) & 0xff);
	p[2] = static_cast<uint8_t>((value >> 8) & 0xff);
	p[3] = static_cast<uint8_t>(value & 0xff);
}

static bool skip_dns_name(const uint8_t* msg, size_t len, size_t& off) {
	if (msg == NULL) {
		return false;
	}
	size_t pos = off;
	bool jumped = false;
	size_t jumps = 0;

	while (pos < len) {
		uint8_t c = msg[pos];
		if (c == 0) {
			if (!jumped) {
				off = pos + 1;
			}
			return true;
		}
		if ((c & 0xc0) == 0xc0) {
			if (pos + 1 >= len || ++jumps > 32) {
				return false;
			}
			uint16_t ptr = static_cast<uint16_t>(((c & 0x3f) << 8) | msg[pos + 1]);
			if (ptr >= len) {
				return false;
			}
			if (!jumped) {
				off = pos + 2;
				jumped = true;
			}
			pos = ptr;
			continue;
		}
		if ((c & 0xc0) != 0 || pos + 1 + c > len) {
			return false;
		}
		pos += 1 + c;
		if (!jumped) {
			off = pos;
		}
	}
	return false;
}

static std::string decode_dns_name(const uint8_t* msg, size_t len, size_t& off) {
	std::string name;
	name.reserve(64);
	size_t pos = off;
	size_t next_off = off;
	bool jumped = false;
	size_t jumps = 0;

	while (pos < len) {
		uint8_t c = msg[pos];
		if (c == 0) {
			if (!jumped) {
				next_off = pos + 1;
			}
			off = next_off;
			return name.empty() ? "." : name;
		}
		if ((c & 0xc0) == 0xc0) {
			if (pos + 1 >= len || ++jumps > 32) {
				return "";
			}
			uint16_t ptr = static_cast<uint16_t>(((c & 0x3f) << 8) | msg[pos + 1]);
			if (ptr >= len) {
				return "";
			}
			if (!jumped) {
				next_off = pos + 2;
				jumped = true;
			}
			pos = ptr;
			continue;
		}
		if ((c & 0xc0) != 0 || pos + 1 + c > len) {
			return "";
		}
		if (!name.empty()) {
			name += ".";
		}
		name.append(reinterpret_cast<const char*>(msg + pos + 1), c);
		pos += 1 + c;
		if (!jumped) {
			next_off = pos;
		}
	}
	return "";
}

static std::string dns_type_name(uint16_t type) {
	switch (type) {
		case 1: return "A";
		case 2: return "NS";
		case 5: return "CNAME";
		case 6: return "SOA";
		case 12: return "PTR";
		case 13: return "HINFO";
		case 15: return "MX";
		case 16: return "TXT";
		case 18: return "AFSDB";
		case 28: return "AAAA";
		case 29: return "LOC";
		case 33: return "SRV";
		case 35: return "NAPTR";
		case 37: return "CERT";
		case 39: return "DNAME";
		case 42: return "APL";
		case 43: return "DS";
		case 44: return "SSHFP";
		case 46: return "RRSIG";
		case 47: return "NSEC";
		case 48: return "DNSKEY";
		case 52: return "TLSA";
		case 59: return "CDS";
		case 60: return "CDNSKEY";
		case 255: return "ANY";
		case 257: return "CAA";
	}
	return "TYPE-" + std::to_string(type);
}
static std::string parse_query_info(const uint8_t* msg, size_t len) {
	if (msg == NULL || len < 12) {
		return "[Malformed Msg]";
	}
	uint16_t qd = be16(msg + 4);
	if (qd == 0) {
		return "[No Query]";
	}
	size_t off = 12;
	std::string name = decode_dns_name(msg, len, off);
	if (name.empty()) {
		name = "[Malformed Name]";
	}
	if (off + 4 > len) {
		return name + " [Malformed Struct]";
	}
	return name + " (" + dns_type_name(be16(msg + off)) + ")";
}

static uint32_t extract_min_ttl(const uint8_t* msg, size_t len) {
	if (msg == NULL || len < 12) {
		return 0;
	}
	uint16_t qd = be16(msg + 4);
	uint32_t rr_count = static_cast<uint32_t>(be16(msg + 6)) +
						static_cast<uint32_t>(be16(msg + 8)) +
						static_cast<uint32_t>(be16(msg + 10));
	size_t off = 12;
	for (uint16_t i = 0; i < qd; ++i) {
		if (!skip_dns_name(msg, len, off) || off + 4 > len) {
			return 0;
		}
		off += 4;
	}

	uint32_t min_ttl = 0xffffffffu;
	bool found = false;
	for (uint32_t i = 0; i < rr_count; ++i) {
		if (!skip_dns_name(msg, len, off) || off + 10 > len) {
			return found ? min_ttl : 0;
		}
		uint16_t type = be16(msg + off);
		uint32_t ttl = be32(msg + off + 4);
		uint16_t rdlen = be16(msg + off + 8);
		off += 10;
		if (off + rdlen > len) {
			return found ? min_ttl : 0;
		}
		if (type != 41) {
			min_ttl = std::min(min_ttl, ttl);
			found = true;
		}
		off += rdlen;
	}
	return found ? min_ttl : 0;
}

static bool adjust_ttls(uint8_t* msg, size_t len, uint32_t age) {
	if (msg == NULL || len < 12) {
		return false;
	}
	uint16_t qd = be16(msg + 4);
	uint32_t rr_count = static_cast<uint32_t>(be16(msg + 6)) +
						static_cast<uint32_t>(be16(msg + 8)) +
						static_cast<uint32_t>(be16(msg + 10));
	size_t off = 12;
	for (uint16_t i = 0; i < qd; ++i) {
		if (!skip_dns_name(msg, len, off) || off + 4 > len) {
			return false;
		}
		off += 4;
	}
	for (uint32_t i = 0; i < rr_count; ++i) {
		if (!skip_dns_name(msg, len, off) || off + 10 > len) {
			return false;
		}
		uint16_t type = be16(msg + off);
		if (type != 41) {
			uint32_t ttl = be32(msg + off + 4);
			put_be32(msg + off + 4, ttl > age ? ttl - age : 0);
		}
		uint16_t rdlen = be16(msg + off + 8);
		off += 10;
		if (off + rdlen > len) {
			return false;
		}
		off += rdlen;
	}
	return true;
}

static bool build_servfail(const uint8_t* req, size_t rlen, std::vector<uint8_t>& resp) {
	if (req == NULL || rlen < 12) {
		return false;
	}
	resp.assign(req, req + rlen);
	resp[2] |= 0x80;
	resp[3] = static_cast<uint8_t>((resp[3] & 0xf0) | 0x02);
	std::memset(&resp[6], 0, 6);
	return true;
}

static std::string trim_copy(const std::string& s) {
	size_t first = 0;
	while (first < s.size() && std::isspace(static_cast<unsigned char>(s[first]))) {
		++first;
	}
	size_t last = s.size();
	while (last > first && std::isspace(static_cast<unsigned char>(s[last - 1]))) {
		--last;
	}
	return s.substr(first, last - first);
}

static std::string lower_copy(std::string s) {
	std::transform(s.begin(), s.end(), s.begin(), [](char c) {
		return static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
	});
	return s;
}

static bool parse_u16_token(const std::string& s, uint16_t& out) {
	if (s.empty()) {
		return false;
	}
	char* end = NULL;
	errno = 0;
	unsigned long v = std::strtoul(s.c_str(), &end, 10);
	if (errno != 0 || end == s.c_str() || *end != '\0' || v > 65535UL) {
		return false;
	}
	out = static_cast<uint16_t>(v);
	return true;
}

static bool parse_u32_token(const std::string& s, uint32_t& out) {
	if (s.empty()) {
		return false;
	}
	char* end = NULL;
	errno = 0;
	unsigned long v = std::strtoul(s.c_str(), &end, 10);
	if (errno != 0 || end == s.c_str() || *end != '\0' || v > 0xffffffffUL) {
		return false;
	}
	out = static_cast<uint32_t>(v);
	return true;
}

static std::string normalize_dns_name_token(const std::string& raw) {
	std::string name = lower_copy(trim_copy(raw));
	while (name.size() > 1 && name[name.size() - 1] == '.') {
		name.resize(name.size() - 1);
	}
	return name.empty() ? std::string() : name;
}

static bool valid_normalized_dns_name(const std::string& name) {
	if (name.empty()) {
		return false;
	}
	if (name == ".") {
		return true;
	}
	if (name.size() > 253) {
		return false;
	}
	size_t label_start = 0;
	while (label_start < name.size()) {
		size_t dot = name.find('.', label_start);
		size_t label_len = (dot == std::string::npos) ? (name.size() - label_start) : (dot - label_start);
		if (label_len == 0 || label_len > 63) {
			return false;
		}
		if (dot == std::string::npos) {
			break;
		}
		label_start = dot + 1;
	}
	return true;
}

static bool append_dns_name_wire(const std::string& normalized_name, std::vector<uint8_t>& out) {
	if (!valid_normalized_dns_name(normalized_name)) {
		return false;
	}
	if (normalized_name == ".") {
		out.push_back(0);
		return true;
	}
	size_t pos = 0;
	while (pos < normalized_name.size()) {
		size_t dot = normalized_name.find('.', pos);
		size_t len = (dot == std::string::npos) ? (normalized_name.size() - pos) : (dot - pos);
		if (len == 0 || len > 63) {
			return false;
		}
		out.push_back(static_cast<uint8_t>(len));
		out.insert(out.end(), normalized_name.begin() + static_cast<std::string::difference_type>(pos),
				   normalized_name.begin() + static_cast<std::string::difference_type>(pos + len));
		if (dot == std::string::npos) {
			break;
		}
		pos = dot + 1;
	}
	out.push_back(0);
	return true;
}

static void append_u16(std::vector<uint8_t>& out, uint16_t v) {
	out.push_back(static_cast<uint8_t>((v >> 8) & 0xff));
	out.push_back(static_cast<uint8_t>(v & 0xff));
}

static void append_u32(std::vector<uint8_t>& out, uint32_t v) {
	out.push_back(static_cast<uint8_t>((v >> 24) & 0xff));
	out.push_back(static_cast<uint8_t>((v >> 16) & 0xff));
	out.push_back(static_cast<uint8_t>((v >> 8) & 0xff));
	out.push_back(static_cast<uint8_t>(v & 0xff));
}

class LocalRecords {
	struct Question {
		std::string name;
		uint16_t qtype;
		uint16_t qclass;
		size_t question_end;

		Question() : name(), qtype(0), qclass(0), question_end(0) {}
	};

public:
	struct Record {
		std::string owner;
		uint16_t type;
		uint32_t ttl;
		std::vector<uint8_t> rdata;

		Record() : owner(), type(0), ttl(1), rdata() {}
	};

private:
	std::unordered_map<std::string, std::vector<Record> > records_;
	size_t count_;
	bool active_;
	mutable std::mutex mtx_;

	LocalRecords(const LocalRecords&);
	LocalRecords& operator=(const LocalRecords&);

	static std::string strip_comment_outside_quotes(const std::string& line) {
		std::string out;
		out.reserve(line.size());
		bool in_quote = false;
		bool escaped = false;
		for (size_t i = 0; i < line.size(); ++i) {
			char c = line[i];
			if (escaped) {
				out.push_back(c);
				escaped = false;
				continue;
			}
			if (c == '\\' && in_quote) {
				out.push_back(c);
				escaped = true;
				continue;
			}
			if (c == '"') {
				in_quote = !in_quote;
				out.push_back(c);
				continue;
			}
			if (c == ';' && !in_quote) {
				break;
			}
			out.push_back(c);
		}
		return out;
	}

	static bool strip_parentheses_outside_quotes(const std::string& line, std::string& out, int& depth, std::string& error) {
		out.clear();
		out.reserve(line.size());
		bool in_quote = false;
		bool escaped = false;
		for (size_t i = 0; i < line.size(); ++i) {
			char c = line[i];
			if (escaped) {
				out.push_back(c);
				escaped = false;
				continue;
			}
			if (c == '\\' && in_quote) {
				out.push_back(c);
				escaped = true;
				continue;
			}
			if (c == '"') {
				in_quote = !in_quote;
				out.push_back(c);
				continue;
			}
			if (!in_quote && c == '(') {
				++depth;
				out.push_back(' ');
				continue;
			}
			if (!in_quote && c == ')') {
				if (depth <= 0) {
					error = "unmatched closing parenthesis";
					return false;
				}
				--depth;
				out.push_back(' ');
				continue;
			}
			out.push_back(c);
		}
		if (in_quote) {
			error = "unterminated quoted string";
			return false;
		}
		return true;
	}

	static bool tokenize_zone_line(const std::string& line, std::vector<std::string>& tokens, std::string& error) {
		tokens.clear();
		std::string clean = strip_comment_outside_quotes(line);
		size_t i = 0;
		while (i < clean.size()) {
			while (i < clean.size() && std::isspace(static_cast<unsigned char>(clean[i]))) {
				++i;
			}
			if (i >= clean.size()) {
				break;
			}

			std::string tok;
			bool quoted = false;
			if (clean[i] == '"') {
				quoted = true;
				++i;
				bool closed = false;
				while (i < clean.size()) {
					char c = clean[i++];
					if (c == '\\' && i < clean.size()) {
						tok.push_back(clean[i++]);
						continue;
					}
					if (c == '"') {
						closed = true;
						break;
					}
					tok.push_back(c);
				}
				if (!closed) {
					error = "unterminated quoted string";
					return false;
				}
			} else {
				while (i < clean.size() && !std::isspace(static_cast<unsigned char>(clean[i]))) {
					tok.push_back(clean[i++]);
				}
			}
			if (quoted || !tok.empty()) {
				tokens.push_back(tok);
			}
		}
		return true;
	}

	static bool parse_type(const std::string& s, uint16_t& type) {
		std::string t = lower_copy(s);
		if (t.size() > 4 && t.substr(0, 4) == "type") {
			uint16_t v = 0;
			if (parse_u16_token(t.substr(4), v)) {
				type = v;
				return true;
			}
		}
		if (t == "a") type = 1;
		else if (t == "aaaa") type = 28;
		else if (t == "ns") type = 2;
		else if (t == "cname") type = 5;
		else if (t == "soa") type = 6;
		else if (t == "ptr") type = 12;
		else if (t == "hinfo") type = 13;
		else if (t == "mx") type = 15;
		else if (t == "txt") type = 16;
		else if (t == "afsdb") type = 18;
		else if (t == "loc") type = 29;
		else if (t == "srv") type = 33;
		else if (t == "naptr") type = 35;
		else if (t == "cert") type = 37;
		else if (t == "dname") type = 39;
		else if (t == "apl") type = 42;
		else if (t == "ds") type = 43;
		else if (t == "sshfp") type = 44;
		else if (t == "rrsig") type = 46;
		else if (t == "nsec") type = 47;
		else if (t == "dnskey") type = 48;
		else if (t == "tlsa") type = 52;
		else if (t == "cds") type = 59;
		else if (t == "cdnskey") type = 60;
		else if (t == "caa") type = 257;
		else return false;
		return true;
	}

	static bool parse_u8_token(const std::string& s, uint8_t& out) {
		uint16_t v = 0;
		if (!parse_u16_token(s, v) || v > 255) {
			return false;
		}
		out = static_cast<uint8_t>(v);
		return true;
	}

	static bool parse_ttl_token(const std::string& s, uint32_t& out) {
		if (s.empty()) {
			return false;
		}
		uint64_t total = 0;
		size_t i = 0;
		bool saw = false;
		while (i < s.size()) {
			if (!std::isdigit(static_cast<unsigned char>(s[i]))) {
				return false;
			}
			uint64_t n = 0;
			while (i < s.size() && std::isdigit(static_cast<unsigned char>(s[i]))) {
				n = n * 10 + static_cast<unsigned int>(s[i] - '0');
				if (n > 0xffffffffULL) {
					return false;
				}
				++i;
			}
			uint64_t mult = 1;
			if (i < s.size()) {
				char u = static_cast<char>(std::tolower(static_cast<unsigned char>(s[i])));
				if (u == 's') mult = 1;
				else if (u == 'm') mult = 60;
				else if (u == 'h') mult = 3600;
				else if (u == 'd') mult = 86400;
				else if (u == 'w') mult = 604800;
				else return false;
				++i;
			}
			if (n > 0xffffffffULL / mult || total > 0xffffffffULL - n * mult) {
				return false;
			}
			total += n * mult;
			saw = true;
		}
		if (!saw) {
			return false;
		}
		out = static_cast<uint32_t>(total);
		return true;
	}

	static bool parse_hex_data(const std::string& text, std::vector<uint8_t>& out) {
		out.clear();
		std::string hex;
		hex.reserve(text.size());
		for (size_t i = 0; i < text.size(); ++i) {
			if (!std::isspace(static_cast<unsigned char>(text[i]))) {
				hex.push_back(text[i]);
			}
		}
		if ((hex.size() % 2) != 0) {
			return false;
		}
		for (size_t i = 0; i < hex.size(); i += 2) {
			int v = 0;
			for (size_t j = 0; j < 2; ++j) {
				char c = hex[i + j];
				v <<= 4;
				if (c >= '0' && c <= '9') v |= c - '0';
				else if (c >= 'a' && c <= 'f') v |= c - 'a' + 10;
				else if (c >= 'A' && c <= 'F') v |= c - 'A' + 10;
				else return false;
			}
			out.push_back(static_cast<uint8_t>(v));
		}
		return true;
	}

	static int base64_value(char c) {
		if (c >= 'A' && c <= 'Z') return c - 'A';
		if (c >= 'a' && c <= 'z') return c - 'a' + 26;
		if (c >= '0' && c <= '9') return c - '0' + 52;
		if (c == '+') return 62;
		if (c == '/') return 63;
		return -1;
	}

	static bool parse_base64_data(const std::string& text, std::vector<uint8_t>& out) {
		out.clear();
		uint32_t buf = 0;
		int bits = 0;
		bool padded = false;
		for (size_t i = 0; i < text.size(); ++i) {
			char c = text[i];
			if (std::isspace(static_cast<unsigned char>(c))) {
				continue;
			}
			if (c == '=') {
				padded = true;
				continue;
			}
			if (padded) {
				return false;
			}
			int v = base64_value(c);
			if (v < 0) {
				return false;
			}
			buf = (buf << 6) | static_cast<uint32_t>(v);
			bits += 6;
			while (bits >= 8) {
				bits -= 8;
				out.push_back(static_cast<uint8_t>((buf >> bits) & 0xff));
			}
		}
		return true;
	}

	static std::string join_tokens(const std::vector<std::string>& tokens, size_t pos, const std::string& sep) {
		std::string out;
		for (size_t i = pos; i < tokens.size(); ++i) {
			if (i != pos) {
				out += sep;
			}
			out += tokens[i];
		}
		return out;
	}

	static std::string resolve_dns_name_token(const std::string& raw, const std::string& origin) {
		std::string t = trim_copy(raw);
		if (t.empty()) {
			return std::string();
		}
		if (t == "@") {
			return origin.empty() ? std::string(".") : origin;
		}
		if (t == ".") {
			return std::string(".");
		}
		if (!t.empty() && t[t.size() - 1] == '.') {
			return normalize_dns_name_token(t);
		}
		if (!origin.empty() && origin != ".") {
			t += "." + origin;
		}
		return normalize_dns_name_token(t);
	}

	static bool append_name_rdata(std::vector<uint8_t>& out, const std::string& raw, const std::string& origin,
								  const char* what, std::string& error) {
		std::string name = resolve_dns_name_token(raw, origin);
		if (!append_dns_name_wire(name, out)) {
			error = std::string("invalid ") + what + " name";
			return false;
		}
		return true;
	}

	static bool append_char_string(std::vector<uint8_t>& out, const std::string& text, const char* what, std::string& error) {
		if (text.size() > 480) {
			error = std::string(what) + " exceeds 480 octets";
			return false;
		}
		out.push_back(static_cast<uint8_t>(text.size()));
		out.insert(out.end(), text.begin(), text.end());
		return true;
	}

	static bool parse_cert_type_token(const std::string& s, uint16_t& out) {
		if (parse_u16_token(s, out)) {
			return true;
		}
		std::string t = lower_copy(s);
		if (t == "pkix") out = 1;
		else if (t == "spki") out = 2;
		else if (t == "pgp") out = 3;
		else if (t == "ipkix") out = 4;
		else if (t == "ispki") out = 5;
		else if (t == "ipgp") out = 6;
		else if (t == "acpkix") out = 7;
		else if (t == "iacpkix") out = 8;
		else if (t == "uri") out = 253;
		else if (t == "oid") out = 254;
		else return false;
		return true;
	}

	static bool parse_dns_time_token(const std::string& s, uint32_t& out) {
		if (s.size() != 14) {
			return false;
		}
		for (size_t i = 0; i < s.size(); ++i) {
			if (!std::isdigit(static_cast<unsigned char>(s[i]))) {
				return false;
			}
		}
		int year = std::atoi(s.substr(0, 4).c_str());
		int mon = std::atoi(s.substr(4, 2).c_str());
		int day = std::atoi(s.substr(6, 2).c_str());
		int hour = std::atoi(s.substr(8, 2).c_str());
		int min = std::atoi(s.substr(10, 2).c_str());
		int sec = std::atoi(s.substr(12, 2).c_str());
		if (mon < 1 || mon > 12 || day < 1 || day > 31 || hour > 23 || min > 59 || sec > 59) {
			return false;
		}
		int y = year;
		int m = mon;
		y -= m <= 2;
		const int era = (y >= 0 ? y : y - 399) / 400;
		const unsigned yoe = static_cast<unsigned>(y - era * 400);
		const unsigned doy = (153U * static_cast<unsigned>(m + (m > 2 ? -3 : 9)) + 2U) / 5U + static_cast<unsigned>(day) - 1U;
		const unsigned doe = yoe * 365U + yoe / 4U - yoe / 100U + doy;
		int64_t days = static_cast<int64_t>(era) * 146097LL + static_cast<int64_t>(doe) - 719468LL;
		int64_t total = days * 86400LL + static_cast<int64_t>(hour) * 3600LL + static_cast<int64_t>(min) * 60LL + sec;
		if (total < 0 || total > 0xffffffffLL) {
			return false;
		}
		out = static_cast<uint32_t>(total);
		return true;
	}

	static bool parse_decimal_millis(const std::string& s, int64_t& out) {
		if (s.empty()) {
			return false;
		}
		size_t i = 0;
		int64_t whole = 0;
		while (i < s.size() && std::isdigit(static_cast<unsigned char>(s[i]))) {
			whole = whole * 10 + static_cast<int64_t>(s[i] - '0');
			++i;
		}
		int64_t frac = 0;
		int digits = 0;
		if (i < s.size() && s[i] == '.') {
			++i;
			while (i < s.size() && std::isdigit(static_cast<unsigned char>(s[i])) && digits < 3) {
				frac = frac * 10 + static_cast<int64_t>(s[i] - '0');
				++i;
				++digits;
			}
			while (digits < 3) {
				frac *= 10;
				++digits;
			}
		}
		if (i != s.size()) {
			return false;
		}
		out = whole * 1000 + frac;
		return true;
	}

	static bool parse_loc_coord(const std::vector<std::string>& tokens, size_t& pos, bool latitude, uint32_t& out) {
		if (pos >= tokens.size()) {
			return false;
		}
		int deg = -1;
		int min = 0;
		int64_t sec_millis = 0;
		std::string hemi;
		if (!parse_int_text(tokens[pos++], deg)) {
			return false;
		}
		if (pos < tokens.size() && !is_loc_hemi(tokens[pos], latitude)) {
			if (!parse_int_text(tokens[pos++], min)) {
				return false;
			}
		}
		if (pos < tokens.size() && !is_loc_hemi(tokens[pos], latitude)) {
			if (!parse_decimal_millis(tokens[pos++], sec_millis)) {
				return false;
			}
		}
		if (pos >= tokens.size() || !is_loc_hemi(tokens[pos], latitude)) {
			return false;
		}
		hemi = lower_copy(tokens[pos++]);
		if (deg < 0 || min < 0 || min > 59 || sec_millis < 0 || sec_millis >= 60000) {
			return false;
		}
		if ((latitude && deg > 90) || (!latitude && deg > 180)) {
			return false;
		}
		int64_t millis = (static_cast<int64_t>(deg) * 3600LL + static_cast<int64_t>(min) * 60LL) * 1000LL + sec_millis;
		if (hemi == "s" || hemi == "w") {
			millis = -millis;
		}
		int64_t wire = 2147483648LL + millis;
		if (wire < 0 || wire > 0xffffffffLL) {
			return false;
		}
		out = static_cast<uint32_t>(wire);
		return true;
	}

	static bool parse_int_text(const std::string& s, int& out) {
		if (s.empty()) {
			return false;
		}
		char* end = NULL;
		errno = 0;
		long v = std::strtol(s.c_str(), &end, 10);
		if (errno != 0 || end == s.c_str() || *end != '\0' || v < std::numeric_limits<int>::min() || v > std::numeric_limits<int>::max()) {
			return false;
		}
		out = static_cast<int>(v);
		return true;
	}

	static bool is_loc_hemi(const std::string& s, bool latitude) {
		std::string t = lower_copy(s);
		return latitude ? (t == "n" || t == "s") : (t == "e" || t == "w");
	}

	static bool parse_meter_cm(const std::string& raw, int64_t& out, bool allow_negative) {
		std::string s = raw;
		if (!s.empty() && (s[s.size() - 1] == 'm' || s[s.size() - 1] == 'M')) {
			s.resize(s.size() - 1);
		}
		if (s.empty()) {
			return false;
		}
		bool neg = false;
		if (s[0] == '-') {
			if (!allow_negative) {
				return false;
			}
			neg = true;
			s.erase(s.begin());
		}
		int64_t millis = 0;
		if (!parse_decimal_millis(s, millis)) {
			return false;
		}
		int64_t cm = millis / 10;
		out = neg ? -cm : cm;
		return true;
	}

	static uint8_t loc_precision_byte(int64_t cm) {
		if (cm <= 0) {
			return 0;
		}
		uint8_t exp = 0;
		while (cm > 9 && exp < 9) {
			cm = (cm + 5) / 10;
			++exp;
		}
		if (cm > 9) {
			cm = 9;
		}
		return static_cast<uint8_t>((static_cast<uint8_t>(cm) << 4) | exp);
	}

	static bool parse_rdata_loc(const std::vector<std::string>& tokens, size_t pos, Record& rec, std::string& error) {
		size_t p = pos;
		uint32_t lat = 0;
		uint32_t lon = 0;
		if (!parse_loc_coord(tokens, p, true, lat) || !parse_loc_coord(tokens, p, false, lon)) {
			error = "LOC requires latitude, longitude, altitude, and optional size/precision values";
			return false;
		}
		if (p >= tokens.size()) {
			error = "LOC missing altitude";
			return false;
		}
		int64_t alt_cm = 0;
		if (!parse_meter_cm(tokens[p++], alt_cm, true)) {
			error = "invalid LOC altitude";
			return false;
		}
		int64_t size_cm = 100;
		int64_t hp_cm = 1000000;
		int64_t vp_cm = 1000;
		if (p < tokens.size() && !parse_meter_cm(tokens[p++], size_cm, false)) {
			error = "invalid LOC size";
			return false;
		}
		if (p < tokens.size() && !parse_meter_cm(tokens[p++], hp_cm, false)) {
			error = "invalid LOC horizontal precision";
			return false;
		}
		if (p < tokens.size() && !parse_meter_cm(tokens[p++], vp_cm, false)) {
			error = "invalid LOC vertical precision";
			return false;
		}
		if (p != tokens.size()) {
			error = "too many LOC fields";
			return false;
		}
		int64_t wire_alt = alt_cm + 10000000LL;
		if (wire_alt < 0 || wire_alt > 0xffffffffLL) {
			error = "LOC altitude out of range";
			return false;
		}
		rec.rdata.push_back(0);
		rec.rdata.push_back(loc_precision_byte(size_cm));
		rec.rdata.push_back(loc_precision_byte(hp_cm));
		rec.rdata.push_back(loc_precision_byte(vp_cm));
		append_u32(rec.rdata, lat);
		append_u32(rec.rdata, lon);
		append_u32(rec.rdata, static_cast<uint32_t>(wire_alt));
		return true;
	}

	static bool parse_rdata_apl(const std::vector<std::string>& tokens, size_t pos, Record& rec, std::string& error) {
		if (pos >= tokens.size()) {
			error = "APL requires one or more address prefix items";
			return false;
		}
		for (size_t i = pos; i < tokens.size(); ++i) {
			std::string item = tokens[i];
			bool neg = false;
			if (!item.empty() && item[0] == '!') {
				neg = true;
				item.erase(item.begin());
			}
			size_t colon = item.find(':');
			size_t slash = item.rfind('/');
			if (colon == std::string::npos || slash == std::string::npos || slash <= colon + 1) {
				error = "invalid APL item";
				return false;
			}
			uint16_t afi = 0;
			uint16_t prefix = 0;
			if (!parse_u16_token(item.substr(0, colon), afi) || !parse_u16_token(item.substr(slash + 1), prefix)) {
				error = "invalid APL address family or prefix";
				return false;
			}
			std::string addr_text = item.substr(colon + 1, slash - colon - 1);
			uint8_t bytes[16];
			std::memset(bytes, 0, sizeof(bytes));
			size_t maxbits = 0;
			int family = 0;
			if (afi == 1) {
				family = AF_INET;
				maxbits = 32;
			} else if (afi == 2) {
				family = AF_INET6;
				maxbits = 128;
			} else {
				error = "unsupported APL address family";
				return false;
			}
			if (prefix > maxbits || inet_pton(family, addr_text.c_str(), bytes) != 1) {
				error = "invalid APL address or prefix";
				return false;
			}
			for (size_t bit = prefix; bit < maxbits; ++bit) {
				bytes[bit / 8] &= static_cast<uint8_t>(~(1U << (7 - (bit % 8))));
			}
			size_t len = (static_cast<size_t>(prefix) + 7) / 8;
			while (len > 0 && bytes[len - 1] == 0) {
				--len;
			}
			append_u16(rec.rdata, afi);
			rec.rdata.push_back(static_cast<uint8_t>(prefix));
			rec.rdata.push_back(static_cast<uint8_t>((neg ? 0x80 : 0) | static_cast<uint8_t>(len)));
			rec.rdata.insert(rec.rdata.end(), bytes, bytes + len);
		}
		return true;
	}

	static bool parse_rdata_nsec(const std::vector<std::string>& tokens, size_t pos, const std::string& origin,
								 Record& rec, std::string& error) {
		if (pos + 2 > tokens.size()) {
			error = "NSEC requires next domain name and at least one type";
			return false;
		}
		if (!append_name_rdata(rec.rdata, tokens[pos], origin, "NSEC next domain", error)) {
			return false;
		}
		std::vector<std::vector<uint8_t> > windows(256);
		for (size_t i = pos + 1; i < tokens.size(); ++i) {
			uint16_t type = 0;
			if (!parse_type(tokens[i], type)) {
				error = "invalid NSEC type bitmap mnemonic";
				return false;
			}
			uint8_t window = static_cast<uint8_t>(type / 256);
			uint8_t bit = static_cast<uint8_t>(type % 256);
			size_t octet = bit / 8;
			uint8_t mask = static_cast<uint8_t>(1U << (7 - (bit % 8)));
			if (windows[window].size() <= octet) {
				windows[window].resize(octet + 1, 0);
			}
			windows[window][octet] |= mask;
		}
		for (size_t w = 0; w < windows.size(); ++w) {
			std::vector<uint8_t>& b = windows[w];
			while (!b.empty() && b[b.size() - 1] == 0) {
				b.pop_back();
			}
			if (!b.empty()) {
				rec.rdata.push_back(static_cast<uint8_t>(w));
				rec.rdata.push_back(static_cast<uint8_t>(b.size()));
				rec.rdata.insert(rec.rdata.end(), b.begin(), b.end());
			}
		}
		return true;
	}

	static bool parse_rdata(uint16_t type, const std::vector<std::string>& tokens, size_t pos,
						  const std::string& origin, Record& rec, std::string& error) {
		if (type == 1) {
			if (pos + 1 != tokens.size()) {
				error = "A requires exactly one IPv4 address";
				return false;
			}
			uint8_t addr[4];
			if (inet_pton(AF_INET, tokens[pos].c_str(), addr) != 1) {
				error = "invalid IPv4 address";
				return false;
			}
			rec.rdata.assign(addr, addr + 4);
			return true;
		}

		if (type == 28) {
			if (pos + 1 != tokens.size()) {
				error = "AAAA requires exactly one IPv6 address";
				return false;
			}
			uint8_t addr[16];
			if (inet_pton(AF_INET6, tokens[pos].c_str(), addr) != 1) {
				error = "invalid IPv6 address";
				return false;
			}
			rec.rdata.assign(addr, addr + 16);
			return true;
		}

		if (type == 2 || type == 5 || type == 12 || type == 39) {
			if (pos + 1 != tokens.size()) {
				error = "name-based record requires exactly one target name";
				return false;
			}
			return append_name_rdata(rec.rdata, tokens[pos], origin, "target", error);
		}

		if (type == 6) {
			if (pos + 7 != tokens.size()) {
				error = "SOA requires mname, rname, serial, refresh, retry, expire, minimum";
				return false;
			}
			uint32_t serial = 0, refresh = 0, retry = 0, expire = 0, minimum = 0;
			if (!append_name_rdata(rec.rdata, tokens[pos], origin, "SOA mname", error) ||
				!append_name_rdata(rec.rdata, tokens[pos + 1], origin, "SOA rname", error) ||
				!parse_u32_token(tokens[pos + 2], serial) || !parse_ttl_token(tokens[pos + 3], refresh) ||
				!parse_ttl_token(tokens[pos + 4], retry) || !parse_ttl_token(tokens[pos + 5], expire) ||
				!parse_ttl_token(tokens[pos + 6], minimum)) {
				error = "invalid SOA data";
				return false;
			}
			append_u32(rec.rdata, serial);
			append_u32(rec.rdata, refresh);
			append_u32(rec.rdata, retry);
			append_u32(rec.rdata, expire);
			append_u32(rec.rdata, minimum);
			return true;
		}

		if (type == 13) {
			if (pos + 2 != tokens.size()) {
				error = "HINFO requires CPU and OS strings";
				return false;
			}
			return append_char_string(rec.rdata, tokens[pos], "HINFO CPU", error) &&
				   append_char_string(rec.rdata, tokens[pos + 1], "HINFO OS", error);
		}

		if (type == 15 || type == 18) {
			if (pos + 2 != tokens.size()) {
				error = (type == 15) ? "MX requires preference and exchange" : "AFSDB requires subtype and hostname";
				return false;
			}
			uint16_t pref = 0;
			if (!parse_u16_token(tokens[pos], pref)) {
				error = (type == 15) ? "invalid MX preference" : "invalid AFSDB subtype";
				return false;
			}
			append_u16(rec.rdata, pref);
			return append_name_rdata(rec.rdata, tokens[pos + 1], origin, type == 15 ? "MX exchange" : "AFSDB hostname", error);
		}

		if (type == 16) {
			if (pos >= tokens.size()) {
				error = "TXT requires text data";
				return false;
			}
			for (size_t i = pos; i < tokens.size(); ++i) {
				if (!append_char_string(rec.rdata, tokens[i], "TXT string", error)) {
					return false;
				}
			}
			return true;
		}

		if (type == 29) {
			return parse_rdata_loc(tokens, pos, rec, error);
		}

		if (type == 33) {
			if (pos + 4 != tokens.size()) {
				error = "SRV requires priority, weight, port, and target";
				return false;
			}
			uint16_t priority = 0, weight = 0, port = 0;
			if (!parse_u16_token(tokens[pos], priority) || !parse_u16_token(tokens[pos + 1], weight) ||
				!parse_u16_token(tokens[pos + 2], port)) {
				error = "invalid SRV priority/weight/port";
				return false;
			}
			append_u16(rec.rdata, priority);
			append_u16(rec.rdata, weight);
			append_u16(rec.rdata, port);
			return append_name_rdata(rec.rdata, tokens[pos + 3], origin, "SRV target", error);
		}

		if (type == 35) {
			if (pos + 6 != tokens.size()) {
				error = "NAPTR requires order, preference, flags, services, regexp, replacement";
				return false;
			}
			uint16_t order = 0, pref = 0;
			if (!parse_u16_token(tokens[pos], order) || !parse_u16_token(tokens[pos + 1], pref)) {
				error = "invalid NAPTR order/preference";
				return false;
			}
			append_u16(rec.rdata, order);
			append_u16(rec.rdata, pref);
			return append_char_string(rec.rdata, tokens[pos + 2], "NAPTR flags", error) &&
				   append_char_string(rec.rdata, tokens[pos + 3], "NAPTR services", error) &&
				   append_char_string(rec.rdata, tokens[pos + 4], "NAPTR regexp", error) &&
				   append_name_rdata(rec.rdata, tokens[pos + 5], origin, "NAPTR replacement", error);
		}

		if (type == 37) {
			if (pos + 4 > tokens.size()) {
				error = "CERT requires type, key tag, algorithm, and certificate";
				return false;
			}
			uint16_t cert_type = 0, key_tag = 0;
			uint8_t alg = 0;
			std::vector<uint8_t> cert;
			if (!parse_cert_type_token(tokens[pos], cert_type) || !parse_u16_token(tokens[pos + 1], key_tag) ||
				!parse_u8_token(tokens[pos + 2], alg) || !parse_base64_data(join_tokens(tokens, pos + 3, ""), cert)) {
				error = "invalid CERT data";
				return false;
			}
			append_u16(rec.rdata, cert_type);
			append_u16(rec.rdata, key_tag);
			rec.rdata.push_back(alg);
			rec.rdata.insert(rec.rdata.end(), cert.begin(), cert.end());
			return true;
		}

		if (type == 42) {
			return parse_rdata_apl(tokens, pos, rec, error);
		}

		if (type == 43 || type == 59) {
			if (pos + 4 > tokens.size()) {
				error = (type == 43) ? "DS requires key tag, algorithm, digest type, and digest" : "CDS requires key tag, algorithm, digest type, and digest";
				return false;
			}
			uint16_t key_tag = 0;
			uint8_t alg = 0, digest_type = 0;
			std::vector<uint8_t> digest;
			if (!parse_u16_token(tokens[pos], key_tag) || !parse_u8_token(tokens[pos + 1], alg) ||
				!parse_u8_token(tokens[pos + 2], digest_type) || !parse_hex_data(join_tokens(tokens, pos + 3, ""), digest)) {
				error = "invalid DS/CDS data";
				return false;
			}
			append_u16(rec.rdata, key_tag);
			rec.rdata.push_back(alg);
			rec.rdata.push_back(digest_type);
			rec.rdata.insert(rec.rdata.end(), digest.begin(), digest.end());
			return true;
		}

		if (type == 44) {
			if (pos + 3 > tokens.size()) {
				error = "SSHFP requires algorithm, fingerprint type, and fingerprint";
				return false;
			}
			uint8_t alg = 0, fp_type = 0;
			std::vector<uint8_t> fp;
			if (!parse_u8_token(tokens[pos], alg) || !parse_u8_token(tokens[pos + 1], fp_type) ||
				!parse_hex_data(join_tokens(tokens, pos + 2, ""), fp)) {
				error = "invalid SSHFP data";
				return false;
			}
			rec.rdata.push_back(alg);
			rec.rdata.push_back(fp_type);
			rec.rdata.insert(rec.rdata.end(), fp.begin(), fp.end());
			return true;
		}

		if (type == 46) {
			if (pos + 9 > tokens.size()) {
				error = "RRSIG requires type-covered, algorithm, labels, original TTL, expiration, inception, key tag, signer, signature";
				return false;
			}
			uint16_t covered = 0, key_tag = 0;
			uint8_t alg = 0, labels = 0;
			uint32_t original_ttl = 0, expiration = 0, inception = 0;
			std::vector<uint8_t> sig;
			if (!parse_type(tokens[pos], covered) || !parse_u8_token(tokens[pos + 1], alg) ||
				!parse_u8_token(tokens[pos + 2], labels) || !parse_ttl_token(tokens[pos + 3], original_ttl) ||
				!parse_dns_time_token(tokens[pos + 4], expiration) || !parse_dns_time_token(tokens[pos + 5], inception) ||
				!parse_u16_token(tokens[pos + 6], key_tag) || !parse_base64_data(join_tokens(tokens, pos + 8, ""), sig)) {
				error = "invalid RRSIG data";
				return false;
			}
			append_u16(rec.rdata, covered);
			rec.rdata.push_back(alg);
			rec.rdata.push_back(labels);
			append_u32(rec.rdata, original_ttl);
			append_u32(rec.rdata, expiration);
			append_u32(rec.rdata, inception);
			append_u16(rec.rdata, key_tag);
			if (!append_name_rdata(rec.rdata, tokens[pos + 7], origin, "RRSIG signer", error)) {
				return false;
			}
			rec.rdata.insert(rec.rdata.end(), sig.begin(), sig.end());
			return true;
		}

		if (type == 47) {
			return parse_rdata_nsec(tokens, pos, origin, rec, error);
		}

		if (type == 48 || type == 60) {
			if (pos + 4 > tokens.size()) {
				error = (type == 48) ? "DNSKEY requires flags, protocol, algorithm, and key" : "CDNSKEY requires flags, protocol, algorithm, and key";
				return false;
			}
			uint16_t flags = 0;
			uint8_t proto = 0, alg = 0;
			std::vector<uint8_t> key;
			if (!parse_u16_token(tokens[pos], flags) || !parse_u8_token(tokens[pos + 1], proto) ||
				!parse_u8_token(tokens[pos + 2], alg) || !parse_base64_data(join_tokens(tokens, pos + 3, ""), key)) {
				error = "invalid DNSKEY/CDNSKEY data";
				return false;
			}
			append_u16(rec.rdata, flags);
			rec.rdata.push_back(proto);
			rec.rdata.push_back(alg);
			rec.rdata.insert(rec.rdata.end(), key.begin(), key.end());
			return true;
		}

		if (type == 52) {
			if (pos + 4 > tokens.size()) {
				error = "TLSA requires usage, selector, matching type, and certificate association data";
				return false;
			}
			uint8_t usage = 0, selector = 0, matching = 0;
			std::vector<uint8_t> assoc;
			if (!parse_u8_token(tokens[pos], usage) || !parse_u8_token(tokens[pos + 1], selector) ||
				!parse_u8_token(tokens[pos + 2], matching) || !parse_hex_data(join_tokens(tokens, pos + 3, ""), assoc)) {
				error = "invalid TLSA data";
				return false;
			}
			rec.rdata.push_back(usage);
			rec.rdata.push_back(selector);
			rec.rdata.push_back(matching);
			rec.rdata.insert(rec.rdata.end(), assoc.begin(), assoc.end());
			return true;
		}

		if (type == 257) {
			if (pos + 3 != tokens.size()) {
				error = "CAA requires flags, tag, and value";
				return false;
			}
			uint8_t flags = 0;
			if (!parse_u8_token(tokens[pos], flags) || tokens[pos + 1].empty() || tokens[pos + 1].size() > 255) {
				error = "invalid CAA flags or tag";
				return false;
			}
			rec.rdata.push_back(flags);
			rec.rdata.push_back(static_cast<uint8_t>(tokens[pos + 1].size()));
			rec.rdata.insert(rec.rdata.end(), tokens[pos + 1].begin(), tokens[pos + 1].end());
			rec.rdata.insert(rec.rdata.end(), tokens[pos + 2].begin(), tokens[pos + 2].end());
			return true;
		}

		error = "unsupported record type";
		return false;
	}

	static bool parse_question(const uint8_t* req, size_t rlen, Question& q) {
		if (req == NULL || rlen < 16) {
			return false;
		}
		uint16_t qd = be16(req + 4);
		if (qd != 1) {
			return false;
		}
		size_t off = 12;
		std::string name = decode_dns_name(req, rlen, off);
		if (name.empty() || off + 4 > rlen) {
			return false;
		}
		q.name = normalize_dns_name_token(name);
		q.qtype = be16(req + off);
		q.qclass = be16(req + off + 2);
		q.question_end = off + 4;
		return valid_normalized_dns_name(q.name);
	}

	static void add_record_to(std::unordered_map<std::string, std::vector<Record> >& records,
							  size_t& count, Record& rec) {
		records[rec.owner].push_back(std::move(rec));
		++count;
	}

	bool find_type_position(const std::vector<std::string>& tokens, bool owner_omitted, size_t& type_pos, uint16_t& type,
						  uint32_t& ttl, const std::string& last_owner, const std::string& origin,
						  Record& rec, std::string& error) const {
		for (size_t i = 0; i < tokens.size(); ++i) {
			uint16_t t = 0;
			if (!parse_type(tokens[i], t)) {
				continue;
			}
			if (owner_omitted) {
				bool seen_ttl = false;
				bool seen_class = false;
				uint32_t local_ttl = ttl;
				bool ok = true;
				for (size_t j = 0; j < i; ++j) {
					if (lower_copy(tokens[j]) == "in" && !seen_class) {
						seen_class = true;
					} else if (parse_ttl_token(tokens[j], local_ttl) && !seen_ttl) {
						seen_ttl = true;
					} else {
						ok = false;
						break;
					}
				}
				if (!ok) {
					continue;
				}
				if (last_owner.empty()) {
					error = "owner omitted before any previous owner";
					return false;
				}
				rec.owner = last_owner;
				ttl = local_ttl;
				type_pos = i;
				type = t;
				return true;
			}

			if (i == 0) {
				continue;
			}
			bool seen_ttl = false;
			bool seen_class = false;
			uint32_t local_ttl = ttl;
			bool ok = true;
			for (size_t j = 1; j < i; ++j) {
				if (lower_copy(tokens[j]) == "in" && !seen_class) {
					seen_class = true;
				} else if (parse_ttl_token(tokens[j], local_ttl) && !seen_ttl) {
					seen_ttl = true;
				} else {
					ok = false;
					break;
				}
			}
			if (!ok) {
				continue;
			}
			rec.owner = resolve_dns_name_token(tokens[0], origin);
			if (!valid_normalized_dns_name(rec.owner)) {
				error = "invalid owner name";
				return false;
			}
			ttl = local_ttl;
			type_pos = i;
			type = t;
			return true;
		}
		error = "unsupported DNS record type";
		return false;
	}

	bool parse_record_line(const std::vector<std::string>& tokens, bool owner_omitted, const std::string& origin,
					   uint32_t default_ttl, const std::string& last_owner, Record& rec, std::string& error) const {
		if (tokens.empty()) {
			error = "empty record";
			return false;
		}
		size_t type_pos = 0;
		uint16_t type = 0;
		uint32_t ttl = default_ttl;
		if (!find_type_position(tokens, owner_omitted, type_pos, type, ttl, last_owner, origin, rec, error)) {
			return false;
		}
		rec.type = type;
		rec.ttl = ttl;
		if (!parse_rdata(rec.type, tokens, type_pos + 1, origin, rec, error)) {
			return false;
		}
		if (rec.rdata.size() > 65535) {
			error = "RDATA exceeds DNS wire limit";
			return false;
		}
		return true;
	}

	static void append_answer_record(std::vector<uint8_t>& resp, const Record& rec, bool owner_is_question) {
		if (owner_is_question) {
			append_u16(resp, 0xc00c);
		} else {
			append_dns_name_wire(rec.owner, resp);
		}
		append_u16(resp, rec.type);
		append_u16(resp, 1);
		append_u32(resp, rec.ttl);
		append_u16(resp, static_cast<uint16_t>(rec.rdata.size()));
		if (!rec.rdata.empty()) {
			resp.insert(resp.end(), rec.rdata.begin(), rec.rdata.end());
		}
	}

	void collect_matching_records(const std::string& name, uint16_t qtype, std::vector<const Record*>& out) const {
		auto it = records_.find(name);
		if (it == records_.end()) {
			return;
		}
		for (size_t i = 0; i < it->second.size(); ++i) {
			const Record& rec = it->second[i];
			if (qtype == 255 || rec.type == qtype) {
				out.push_back(&rec);
			}
		}
	}

	bool owner_exists(const std::string& name) const {
		return records_.find(name) != records_.end();
	}

	static void build_header_and_question(const uint8_t* req, const Question& q, uint8_t rcode,
								  uint16_t answer_count, std::vector<uint8_t>& resp) {
		resp.clear();
		resp.reserve(12 + (q.question_end - 12) + static_cast<size_t>(answer_count) * 32);
		resp.insert(resp.end(), req, req + 12);
		resp[2] = static_cast<uint8_t>(0x80 | (req[2] & 0x78) | 0x04 | (req[2] & 0x01));
		resp[3] = static_cast<uint8_t>(0x80 | (req[3] & 0x10) | (rcode & 0x0f));
		put_be16(&resp[4], 1);
		put_be16(&resp[6], answer_count);
		put_be16(&resp[8], 0);
		put_be16(&resp[10], 0);
		resp.insert(resp.end(), req + 12, req + q.question_end);
	}

public:
	LocalRecords() : records_(), count_(0), active_(false), mtx_() {}

	size_t count() const {
		std::lock_guard<std::mutex> lock(mtx_);
		return count_;
	}

	bool enabled() const {
		std::lock_guard<std::mutex> lock(mtx_);
		return active_;
	}

	bool load_from_file(const std::string& path) {
		std::unordered_map<std::string, std::vector<Record> > new_records;
		size_t new_count = 0;

		if (path.empty() || access(path.c_str(), F_OK) != 0) {
			{
				std::lock_guard<std::mutex> lock(mtx_);
				records_.clear();
				count_ = 0;
				active_ = false;
			}
			Logger::log(Logger::INFO, "Local DNS config not found: " + path + " (custom overrides disabled; using upstream resolver)");
			return false;
		}

		std::ifstream in(path.c_str());
		if (!in) {
			{
				std::lock_guard<std::mutex> lock(mtx_);
				records_.clear();
				count_ = 0;
				active_ = false;
			}
			Logger::log(Logger::WARN, "Local DNS config exists but cannot be opened: " + path + ": " + std::strerror(errno) + " (custom overrides disabled; using upstream resolver)");
			return false;
		}

		std::string origin;
		uint32_t default_ttl = 1;
		std::string last_owner;
		std::string line;
		std::string logical;
		bool logical_owner_omitted = false;
		int paren_depth = 0;
		size_t line_no = 0;
		size_t logical_line_no = 0;
		size_t bad = 0;
		while (std::getline(in, line)) {
			++line_no;
			std::string clean = strip_comment_outside_quotes(line);
			std::string stripped;
			std::string error;
			if (!strip_parentheses_outside_quotes(clean, stripped, paren_depth, error)) {
				++bad;
				Logger::log(Logger::WARN, path + ":" + std::to_string(line_no) + ": " + error);
				logical.clear();
				paren_depth = 0;
				continue;
			}
			if (!trim_copy(stripped).empty()) {
				if (logical.empty()) {
					logical_owner_omitted = std::isspace(static_cast<unsigned char>(stripped[0])) != 0;
					logical_line_no = line_no;
					logical = stripped;
				} else {
					logical += " ";
					logical += stripped;
				}
			}
			if (paren_depth > 0 || logical.empty()) {
				continue;
			}

			std::vector<std::string> tokens;
			if (!tokenize_zone_line(logical, tokens, error)) {
				++bad;
				Logger::log(Logger::WARN, path + ":" + std::to_string(logical_line_no) + ": " + error);
				logical.clear();
				continue;
			}
			logical.clear();
			if (tokens.empty()) {
				continue;
			}

			std::string directive = lower_copy(tokens[0]);
			if (directive == "$origin") {
				if (tokens.size() != 2) {
					++bad;
					Logger::log(Logger::WARN, path + ":" + std::to_string(logical_line_no) + ": malformed $ORIGIN directive ignored");
					continue;
				}
				origin = resolve_dns_name_token(tokens[1], origin);
				if (!valid_normalized_dns_name(origin)) {
					++bad;
					origin.clear();
					Logger::log(Logger::WARN, path + ":" + std::to_string(logical_line_no) + ": invalid $ORIGIN directive ignored");
				}
				continue;
			}
			if (directive == "$ttl") {
				if (tokens.size() != 2 || !parse_ttl_token(tokens[1], default_ttl)) {
					++bad;
					Logger::log(Logger::WARN, path + ":" + std::to_string(logical_line_no) + ": malformed $TTL directive ignored");
				}
				continue;
			}
			if (!directive.empty() && directive[0] == '$') {
				++bad;
				Logger::log(Logger::WARN, path + ":" + std::to_string(logical_line_no) + ": unsupported directive ignored: " + tokens[0]);
				continue;
			}

			Record rec;
			if (!parse_record_line(tokens, logical_owner_omitted, origin, default_ttl, last_owner, rec, error)) {
				++bad;
				Logger::log(Logger::WARN, path + ":" + std::to_string(logical_line_no) + ": malformed record ignored: " + error);
				continue;
			}
			last_owner = rec.owner;
			add_record_to(new_records, new_count, rec);
		}
		if (paren_depth > 0) {
			++bad;
			Logger::log(Logger::WARN, path + ": unterminated parenthesized record at end of file");
		}

		{
			std::lock_guard<std::mutex> lock(mtx_);
			records_.swap(new_records);
			count_ = new_count;
			active_ = new_count > 0;
		}

		Logger::log(Logger::INFO, "Loaded " + std::to_string(new_count) + " local DNS override record(s) from " + path +
					(new_count == 0 ? std::string("; override mode is disabled") : std::string("; override mode is enabled")) +
					(bad == 0 ? std::string() : ("; ignored " + std::to_string(bad) + " malformed line(s)")));
		return new_count > 0;
	}

	bool answer(const uint8_t* req, size_t rlen, std::vector<uint8_t>& resp) const {
		Question q;
		std::lock_guard<std::mutex> lock(mtx_);
		if (!active_ || !parse_question(req, rlen, q)) {
			return false;
		}
		if (q.qclass != 1) {
			return false;
		}

		std::vector<const Record*> answers;
		collect_matching_records(q.name, q.qtype, answers);

		if (answers.empty() && q.qtype != 5 && q.qtype != 255) {
			std::vector<const Record*> cname_answers;
			collect_matching_records(q.name, 5, cname_answers);
			for (size_t i = 0; i < cname_answers.size(); ++i) {
				answers.push_back(cname_answers[i]);
			}
			for (size_t i = 0; i < cname_answers.size(); ++i) {
				size_t off = 0;
				std::string target = cname_answers[i]->rdata.empty() ? std::string() :
					decode_dns_name(&cname_answers[i]->rdata[0], cname_answers[i]->rdata.size(), off);
				if (!target.empty()) {
					std::vector<const Record*> target_records;
					collect_matching_records(normalize_dns_name_token(target), q.qtype, target_records);
					for (size_t j = 0; j < target_records.size(); ++j) {
						answers.push_back(target_records[j]);
					}
				}
			}
		}

		if (answers.size() > 65535) {
			return false;
		}
		if (answers.empty()) {
			if (!owner_exists(q.name)) {
				return false;
			}
			build_header_and_question(req, q, 0, 0, resp);
			return true;
		}

		build_header_and_question(req, q, 0, static_cast<uint16_t>(answers.size()), resp);
		for (size_t i = 0; i < answers.size(); ++i) {
			append_answer_record(resp, *answers[i], answers[i]->owner == q.name);
			if (resp.size() > WIRE_MAX) {
				return false;
			}
		}
		return true;
	}
};

static bool fd_write_all(int fd, const uint8_t* data, size_t len) {
	size_t off = 0;
	while (off < len) {
		ssize_t n = ::send(fd, data + off, len - off, MSG_NOSIGNAL);
		if (n > 0) {
			off += static_cast<size_t>(n);
			continue;
		}
		if (n < 0 && errno == EINTR) {
			continue;
		}
		return false;
	}
	return true;
}

static bool fd_read_all(int fd, uint8_t* data, size_t len) {
	size_t off = 0;
	while (off < len) {
		ssize_t n = ::recv(fd, data + off, len - off, 0);
		if (n > 0) {
			off += static_cast<size_t>(n);
			continue;
		}
		if (n < 0 && errno == EINTR) {
			continue;
		}
		return false;
	}
	return true;
}

static bool ssl_write_all(SSL* ssl, const uint8_t* data, size_t len) {
	size_t off = 0;
	while (off < len) {
		int n = SSL_write(ssl, data + off, static_cast<int>(len - off));
		if (n > 0) {
			off += static_cast<size_t>(n);
			continue;
		}
		int err = SSL_get_error(ssl, n);
		if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE ||
			(err == SSL_ERROR_SYSCALL && errno == EINTR)) {
			continue;
		}
		return false;
	}
	return true;
}

static bool ssl_read_all(SSL* ssl, uint8_t* data, size_t len) {
	size_t off = 0;
	while (off < len) {
		int n = SSL_read(ssl, data + off, static_cast<int>(len - off));
		if (n > 0) {
			off += static_cast<size_t>(n);
			continue;
		}
		int err = SSL_get_error(ssl, n);
		if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE ||
			(err == SSL_ERROR_SYSCALL && errno == EINTR)) {
			continue;
		}
		return false;
	}
	return true;
}

class DnsCache {
	struct Entry {
		uint64_t hash;
		uint32_t stored;
		uint32_t ttl;
		std::vector<uint8_t> key;
		std::vector<uint8_t> resp;

		Entry() : hash(0), stored(0), ttl(0), key(), resp() {}
	};

	struct Stripe {
		std::mutex mtx;
		std::vector<Entry> entries;
		size_t clock_hand;

		explicit Stripe(size_t ways) : entries(ways), clock_hand(0) {}
	};

	std::vector<std::unique_ptr<Stripe> > stripes_;
	size_t stripe_mask_;
	size_t ways_;
	size_t key_max_;
	size_t resp_max_;

	DnsCache(const DnsCache&);
	DnsCache& operator=(const DnsCache&);

	static inline uint64_t fnv1a(const uint8_t* data, size_t len) {
		uint64_t h = 14695981039346656037ULL;
		for (size_t i = 0; i < len; ++i) {
			h ^= data[i];
			h *= 1099511628211ULL;
		}
		return h;
	}

public:
	DnsCache(size_t stripes, size_t ways, size_t key_max, size_t resp_max)
		: stripes_(), stripe_mask_(0), ways_(ways), key_max_(key_max), resp_max_(resp_max) {
		size_t count = next_power_of_two(clamp_size(stripes, 1, 4096));
		ways_ = clamp_size(ways_, 1, 64);
		stripe_mask_ = count - 1;
		stripes_.reserve(count);
		for (size_t i = 0; i < count; ++i) {
			stripes_.push_back(std::unique_ptr<Stripe>(new Stripe(ways_)));
		}
	}

	bool lookup(const uint8_t* req, size_t rlen, std::vector<uint8_t>& resp) {
		if (req == NULL || rlen < 2) {
			return false;
		}
		uint64_t h = fnv1a(req + 2, rlen - 2);
		uint32_t now = monotonic_seconds();
		Stripe& stripe = *stripes_[static_cast<size_t>(h) & stripe_mask_];

		std::lock_guard<std::mutex> lock(stripe.mtx);
		for (size_t i = 0; i < ways_; ++i) {
			Entry& e = stripe.entries[i];
			if (e.ttl == 0 || e.stored == 0) {
				continue;
			}
			if (now - e.stored >= e.ttl) {
				continue;
			}
			if (e.hash != h || e.key.size() != rlen - 2) {
				continue;
			}
			if (!e.key.empty() && std::memcmp(&e.key[0], req + 2, e.key.size()) != 0) {
				continue;
			}

			resp = e.resp;
			uint32_t age = now - e.stored;
			if (!resp.empty() && !adjust_ttls(&resp[0], resp.size(), age)) {
				return false;
			}
			if (resp.size() >= 2) {
				resp[0] = req[0];
				resp[1] = req[1];
			}
			return true;
		}
		return false;
	}

	void store(const uint8_t* req, size_t rlen, const uint8_t* resp_data, size_t resp_len) {
		if (req == NULL || resp_data == NULL || rlen < 2 || rlen - 2 > key_max_ || resp_len > resp_max_) {
			return;
		}
		if (resp_len < 12 || (resp_data[2] & 0x02) != 0) {
			return;
		}
		uint32_t ttl = extract_min_ttl(resp_data, resp_len);
		if (ttl == 0) {
			return;
		}

		uint64_t h = fnv1a(req + 2, rlen - 2);
		Stripe& stripe = *stripes_[static_cast<size_t>(h) & stripe_mask_];
		uint32_t now = monotonic_seconds();
		std::vector<uint8_t> key_copy(req + 2, req + rlen);
		std::vector<uint8_t> resp_copy(resp_data, resp_data + resp_len);

		std::lock_guard<std::mutex> lock(stripe.mtx);
		size_t target = stripe.clock_hand;
		uint32_t best_life_left = 0xffffffffu;
		bool selected = false;

		for (size_t i = 0; i < ways_; ++i) {
			Entry& e = stripe.entries[i];
			if (e.ttl == 0 || e.stored == 0 || now - e.stored >= e.ttl) {
				target = i;
				selected = true;
				break;
			}
			uint32_t life_left = e.ttl - (now - e.stored);
			if (life_left < best_life_left) {
				best_life_left = life_left;
				target = i;
			}
		}
		if (!selected) {
			stripe.clock_hand = (target + 1) % ways_;
		}

		Entry& e = stripe.entries[target];
		e.key.swap(key_copy);
		e.resp.swap(resp_copy);
		e.hash = h;
		e.stored = now;
		e.ttl = ttl;
	}
};

class Proxy;

struct Job {
	enum Type { JOB_NONE, JOB_UDP, JOB_TCP } type;
	int fd;
	bool tls;
	struct sockaddr_in peer;
	socklen_t peer_len;
	size_t req_len;
	uint8_t* req_heap;
	uint8_t req_inline[INLINE_REQ];

	Job() : type(JOB_NONE), fd(-1), tls(false), peer(), peer_len(0), req_len(0), req_heap(NULL), req_inline() {}
	~Job() {
		if (req_heap) {
			delete[] req_heap;
		}
	}
	Job(const Job&) = delete;
	Job& operator=(const Job&) = delete;
	Job(Job&& other) noexcept 
		: type(other.type), fd(other.fd), tls(other.tls), peer(other.peer), peer_len(other.peer_len), req_len(other.req_len), req_heap(other.req_heap) {
		std::memcpy(req_inline, other.req_inline, INLINE_REQ);
		other.req_heap = NULL;
		other.fd = -1;
		other.type = JOB_NONE;
	}
	Job& operator=(Job&& other) noexcept {
		if (this != &other) {
			if (req_heap) { delete[] req_heap; req_heap = NULL; }
			type = other.type;
			fd = other.fd;
			tls = other.tls;
			peer = other.peer;
			peer_len = other.peer_len;
			req_len = other.req_len;
			req_heap = other.req_heap;
			std::memcpy(req_inline, other.req_inline, INLINE_REQ);
			other.req_heap = NULL;
			other.fd = -1;
			other.type = JOB_NONE;
		}
		return *this;
	}
};

class WorkerPool {
	std::mutex mtx_;
	std::condition_variable cv_;
	std::vector<Job> queue_;
	size_t head_;
	size_t tail_;
	size_t size_;
	size_t max_queue_;
	size_t thread_count_;
	std::vector<std::thread> threads_;
	bool stopping_;

	WorkerPool(const WorkerPool&);
	WorkerPool& operator=(const WorkerPool&);

	void thread_main(Proxy* proxy);

public:
	WorkerPool(size_t n, size_t max_queue)
		: queue_(), head_(0), tail_(0), size_(0), max_queue_(max_queue),
		  thread_count_(n), threads_(), stopping_(false) {
		max_queue_ = clamp_size(max_queue_, 64, 262144);
		thread_count_ = clamp_size(thread_count_, 1, 128);
		queue_.resize(max_queue_);
		threads_.reserve(thread_count_);
	}

	void start(Proxy* proxy) {
		for (size_t i = 0; i < thread_count_; ++i) {
			threads_.push_back(std::thread(&WorkerPool::thread_main, this, proxy));
		}
	}

	~WorkerPool() {
		{
			std::unique_lock<std::mutex> lock(mtx_);
			stopping_ = true;
		}
		cv_.notify_all();
		for (size_t i = 0; i < threads_.size(); ++i) {
			if (threads_[i].joinable()) {
				threads_[i].join();
			}
		}
		while (size_ > 0) {
			Job& job = queue_[head_];
			if (job.type == Job::JOB_TCP && job.fd >= 0) {
				::close(job.fd);
			}
			head_ = (head_ + 1) % queue_.size();
			--size_;
		}
	}

	bool enqueue_udp(const struct sockaddr_in& peer, socklen_t peer_len, const uint8_t* data, size_t len) {
		std::unique_lock<std::mutex> lock(mtx_);
		if (stopping_ || size_ >= max_queue_) {
			return false;
		}
		Job& job = queue_[tail_];
		job.type = Job::JOB_UDP;
		job.peer = peer;
		job.peer_len = peer_len;
		job.req_len = len;
		job.fd = -1;
		job.tls = false;
		if (job.req_heap) {
			delete[] job.req_heap;
			job.req_heap = NULL;
		}
		if (len <= INLINE_REQ) {
			std::memcpy(job.req_inline, data, len);
		} else {
			job.req_heap = new uint8_t[len];
			std::memcpy(job.req_heap, data, len);
		}
		tail_ = (tail_ + 1) % queue_.size();
		++size_;
		cv_.notify_one();
		return true;
	}

	bool enqueue_tcp(int fd, bool tls) {
		std::unique_lock<std::mutex> lock(mtx_);
		if (stopping_ || size_ >= max_queue_) {
			return false;
		}
		Job& job = queue_[tail_];
		job.type = Job::JOB_TCP;
		job.fd = fd;
		job.tls = tls;
		job.req_len = 0;
		if (job.req_heap) {
			delete[] job.req_heap;
			job.req_heap = NULL;
		}
		tail_ = (tail_ + 1) % queue_.size();
		++size_;
		cv_.notify_one();
		return true;
	}
};

class UpstreamDoTPool {
public:
	struct Connection {
		int fd;
		SSL* ssl;
		Connection() : fd(-1), ssl(NULL) {}
	};

	struct Handle {
		size_t index;
		Connection* conn;
		Handle() : index(static_cast<size_t>(-1)), conn(NULL) {}
		bool valid() const { return conn != NULL; }
	};

private:
	RuntimeConfig cfg_;
	SslPtr<SSL_CTX> ctx_;
	std::vector<Connection> conns_;
	std::queue<size_t> free_;
	std::mutex mtx_;
	std::condition_variable cv_;

	UpstreamDoTPool(const UpstreamDoTPool&);
	UpstreamDoTPool& operator=(const UpstreamDoTPool&);

	bool open_connection(Connection& c) {
		close_connection(c);
		c.fd = socket(AF_INET, SOCK_STREAM, 0);
		if (c.fd < 0) {
			return false;
		}
		set_cloexec(c.fd);
		set_common_socket_opts(c.fd, cfg_);
		set_timeouts(c.fd, cfg_.upstream_io_timeout_seconds);

		struct sockaddr_in addr;
		std::memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_port = htons(cfg_.dot_port);
		if (inet_pton(AF_INET, cfg_.upstream_dns.c_str(), &addr.sin_addr) != 1) {
			close_connection(c);
			return false;
		}
		if (!connect_with_timeout(c.fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr),
								  cfg_.upstream_connect_timeout_seconds)) {
			Logger::log(Logger::WARN, std::string("Upstream DoT connect failed: ") + std::strerror(errno));
			close_connection(c);
			return false;
		}

		c.ssl = SSL_new(ctx_.get());
		if (c.ssl == NULL) {
			close_connection(c);
			return false;
		}
		SSL_set_fd(c.ssl, c.fd);

		X509_VERIFY_PARAM* param = SSL_get0_param(c.ssl);
		if (param != NULL && X509_VERIFY_PARAM_set1_ip_asc(param, cfg_.upstream_dns.c_str()) != 1) {
			Logger::log(Logger::ERROR, "Could not configure upstream certificate IP verification.");
			close_connection(c);
			return false;
		}
		if (SSL_connect(c.ssl) <= 0) {
			Logger::log(Logger::ERROR, "Upstream TLS handshake failed.");
			close_connection(c);
			return false;
		}
		if (SSL_get_verify_result(c.ssl) != X509_V_OK) {
			Logger::log(Logger::ERROR, "Upstream certificate validation failed.");
			close_connection(c);
			return false;
		}
		return true;
	}

public:
	explicit UpstreamDoTPool(const RuntimeConfig& cfg)
		: cfg_(cfg), ctx_(SSL_CTX_new(TLS_client_method())), conns_(cfg.dot_pool_size), free_(), mtx_(), cv_() {
		if (!ctx_) {
			throw std::runtime_error("failed to initialize upstream TLS context");
		}
		SSL_CTX_set_verify(ctx_.get(), SSL_VERIFY_PEER, NULL);
		if (SSL_CTX_set_default_verify_paths(ctx_.get()) <= 0) {
			Logger::log(Logger::WARN, "Could not load default OS certificate CA paths.");
		}
		SSL_CTX_set_mode(ctx_.get(), SSL_MODE_AUTO_RETRY | SSL_MODE_RELEASE_BUFFERS);
		X509_VERIFY_PARAM* param = SSL_CTX_get0_param(ctx_.get());
		if (param != NULL) {
			X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
		}
		for (size_t i = 0; i < conns_.size(); ++i) {
			free_.push(i);
		}
	}

	~UpstreamDoTPool() {
		for (size_t i = 0; i < conns_.size(); ++i) {
			close_connection(conns_[i]);
		}
	}

	static void close_connection(Connection& c) {
		if (c.ssl != NULL) {
			SSL_shutdown(c.ssl);
			SSL_free(c.ssl);
			c.ssl = NULL;
		}
		if (c.fd >= 0) {
			::close(c.fd);
			c.fd = -1;
		}
	}

	Handle acquire() {
		size_t idx = 0;
		{
			std::unique_lock<std::mutex> lock(mtx_);
			while (free_.empty()) {
				cv_.wait(lock);
			}
			idx = free_.front();
			free_.pop();
		}
		Handle h;
		h.index = idx;
		h.conn = &conns_[idx];
		if (h.conn->fd < 0 || h.conn->ssl == NULL) {
			open_connection(*h.conn);
		}
		return h;
	}

	void release(const Handle& h) {
		if (!h.valid()) {
			return;
		}
		{
			std::lock_guard<std::mutex> lock(mtx_);
			free_.push(h.index);
		}
		cv_.notify_one();
	}
};

class Proxy {
	RuntimeConfig cfg_;
	DnsCache cache_;
	LocalRecords local_records_;
	SslPtr<SSL_CTX> server_ctx_;
	UniqueFd udp_fd_;
	UniqueFd tcp_fd_;
	UniqueFd dot_fd_;
	std::unique_ptr<UpstreamDoTPool> dot_pool_;
	WorkerPool workers_;
	std::vector<uint8_t> udp_buffer_;
	uint32_t next_config_reload_;

	Proxy(const Proxy&);
	Proxy& operator=(const Proxy&);

	friend class WorkerPool;

	static const char* socket_type_name(intS type) {
		return type == SOCK_DGRAM ? "udp" : "tcp";
	}

	UniqueFd create_listener(uint16_t port, intS type) {
		UniqueFd fd(socket(AF_INET, type, 0));
		if (!fd.valid()) {
			Logger::log(Logger::ERROR, std::string("socket ") + socket_type_name(type) + " failed: " + std::strerror(errno));
			return UniqueFd();
		}
		set_cloexec(fd.get());
		set_socket_buffers(fd.get(), cfg_.socket_buffer_bytes);
		if (!set_reuse(fd.get())) {
			Logger::log(Logger::ERROR, std::string("setsockopt SO_REUSEADDR failed: ") + std::strerror(errno));
			return UniqueFd();
		}
		if (!set_nonblocking(fd.get())) {
			Logger::log(Logger::ERROR, std::string("fcntl O_NONBLOCK failed: ") + std::strerror(errno));
			return UniqueFd();
		}

		struct sockaddr_in addr;
		std::memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_port = htons(port);
		if (inet_pton(AF_INET, cfg_.listen_ip.c_str(), &addr.sin_addr) != 1) {
			Logger::log(Logger::ERROR, std::string("Invalid listen IP: ") + cfg_.listen_ip);
			return UniqueFd();
		}
		if (bind(fd.get(), reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
			Logger::log(Logger::ERROR, std::string("bind ") + cfg_.listen_ip + ":" + std::to_string(port) +
						"/" + socket_type_name(type) + " failed: " + std::strerror(errno));
			return UniqueFd();
		}
		if (type == SOCK_STREAM && listen(fd.get(), 2048) < 0) {
			Logger::log(Logger::ERROR, std::string("listen failed: ") + std::strerror(errno));
			return UniqueFd();
		}
		return fd;
	}

	static SSL_CTX* create_server_ctx() {
		SslPtr<SSL_CTX> ctx(SSL_CTX_new(TLS_server_method()));
		if (!ctx) {
			return NULL;
		}
		SSL_CTX_set_min_proto_version(ctx.get(), TLS1_2_VERSION);
		SSL_CTX_set_mode(ctx.get(), SSL_MODE_AUTO_RETRY | SSL_MODE_RELEASE_BUFFERS);

		EVP_PKEY* raw_key = NULL;
		SslPtr<EVP_PKEY_CTX> pctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL));
		if (pctx && EVP_PKEY_keygen_init(pctx.get()) > 0 &&
			EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx.get(), NID_X9_62_prime256v1) > 0 &&
			EVP_PKEY_keygen(pctx.get(), &raw_key) > 0) {
		} else {
			return NULL;
		}

		SslPtr<EVP_PKEY> pkey(raw_key);
		SslPtr<X509> cert(X509_new());
		if (!cert) {
			return NULL;
		}
		ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 1);
		X509_gmtime_adj(X509_get_notBefore(cert.get()), 0);
		X509_gmtime_adj(X509_get_notAfter(cert.get()), 31536000L);
		X509_set_version(cert.get(), 2);
		X509_set_pubkey(cert.get(), pkey.get());

		X509_NAME* name = X509_get_subject_name(cert.get());
		if (name == NULL ||
			X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
										reinterpret_cast<const unsigned char*>("localhost"), -1, -1, 0) != 1 ||
			X509_set_issuer_name(cert.get(), name) != 1) {
			return NULL;
		}
		if (X509_sign(cert.get(), pkey.get(), EVP_sha256()) == 0 ||
			SSL_CTX_use_certificate(ctx.get(), cert.get()) != 1 ||
			SSL_CTX_use_PrivateKey(ctx.get(), pkey.get()) != 1 ||
			SSL_CTX_check_private_key(ctx.get()) != 1) {
			return NULL;
		}
		return ctx.release();
	}

	bool forward_plain_udp(const uint8_t* req, size_t rlen, std::vector<uint8_t>& resp) {
		UniqueFd fd(socket(AF_INET, SOCK_DGRAM, 0));
		if (!fd.valid()) {
			return false;
		}
		set_cloexec(fd.get());
		set_socket_buffers(fd.get(), cfg_.socket_buffer_bytes);
		set_timeouts(fd.get(), cfg_.upstream_io_timeout_seconds);

		struct sockaddr_in addr;
		std::memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_port = htons(cfg_.dns_port);
		if (inet_pton(AF_INET, cfg_.upstream_dns.c_str(), &addr.sin_addr) != 1) {
			return false;
		}
		if (connect(fd.get(), reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
			return false;
		}
		if (!fd_write_all(fd.get(), req, rlen)) {
			return false;
		}

		resp.resize(cfg_.udp_msg_max);
		ssize_t n = recv(fd.get(), resp.empty() ? NULL : &resp[0], resp.size(), MSG_TRUNC);
		if (n <= 0) {
			return false;
		}
		if (static_cast<size_t>(n) > resp.size()) {
			return false;
		}
		resp.resize(static_cast<size_t>(n));
		return true;
	}

	bool forward_plain_tcp(const uint8_t* req, size_t rlen, std::vector<uint8_t>& resp) {
		UniqueFd fd(socket(AF_INET, SOCK_STREAM, 0));
		if (!fd.valid()) {
			return false;
		}
		set_cloexec(fd.get());
		set_common_socket_opts(fd.get(), cfg_);
		set_timeouts(fd.get(), cfg_.upstream_io_timeout_seconds);

		struct sockaddr_in addr;
		std::memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_port = htons(cfg_.dns_port);
		if (inet_pton(AF_INET, cfg_.upstream_dns.c_str(), &addr.sin_addr) != 1) {
			return false;
		}
		if (!connect_with_timeout(fd.get(), reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr),
								  cfg_.upstream_connect_timeout_seconds)) {
			return false;
		}

		uint8_t lenbuf[2];
		put_be16(lenbuf, static_cast<uint16_t>(rlen));
		if (!fd_write_all(fd.get(), lenbuf, sizeof(lenbuf)) || !fd_write_all(fd.get(), req, rlen)) {
			return false;
		}
		if (!fd_read_all(fd.get(), lenbuf, sizeof(lenbuf))) {
			return false;
		}
		size_t n = be16(lenbuf);
		if (n == 0 || n > WIRE_MAX) {
			return false;
		}
		resp.resize(n);
		return fd_read_all(fd.get(), &resp[0], n);
	}

	bool forward_plain_dns(const uint8_t* req, size_t rlen, std::vector<uint8_t>& resp) {
		if (forward_plain_udp(req, rlen, resp)) {
			if (resp.size() >= 4 && (resp[2] & 0x02) != 0) {
				return forward_plain_tcp(req, rlen, resp);
			}
			return true;
		}
		return forward_plain_tcp(req, rlen, resp);
	}

	bool forward_dot(const uint8_t* req, size_t rlen, std::vector<uint8_t>& resp) {
		if (!dot_pool_) {
			return forward_plain_dns(req, rlen, resp);
		}
		UpstreamDoTPool::Handle h = dot_pool_->acquire();
		if (!h.valid() || h.conn == NULL || h.conn->fd < 0 || h.conn->ssl == NULL) {
			if (h.valid()) {
				dot_pool_->release(h);
			}
			return forward_plain_dns(req, rlen, resp);
		}

		uint8_t lenbuf[2];
		put_be16(lenbuf, static_cast<uint16_t>(rlen));
		bool ok = ssl_write_all(h.conn->ssl, lenbuf, sizeof(lenbuf)) && ssl_write_all(h.conn->ssl, req, rlen);
		if (ok && ssl_read_all(h.conn->ssl, lenbuf, sizeof(lenbuf))) {
			size_t n = be16(lenbuf);
			if (n > 0 && n <= WIRE_MAX) {
				resp.resize(n);
				ok = ssl_read_all(h.conn->ssl, &resp[0], n);
			} else {
				ok = false;
			}
		} else {
			ok = false;
		}

		if (!ok) {
			UpstreamDoTPool::close_connection(*h.conn);
			dot_pool_->release(h);
			return forward_plain_dns(req, rlen, resp);
		}
		dot_pool_->release(h);
		return true;
	}

	void reload_config_if_due() {
		uint32_t now = monotonic_seconds();
		if (now < next_config_reload_) {
			return;
		}
		next_config_reload_ = now + RELOAD_INTERVAL_SECONDS;
		local_records_.load_from_file(cfg_.config_path);
	}

	bool process_query(const uint8_t* req, size_t rlen, std::vector<uint8_t>& resp, bool& cache_hit, bool& local_hit) {
		if (req == NULL || rlen < 12 || rlen > WIRE_MAX) {
			return false;
		}

		if (local_records_.answer(req, rlen, resp)) {
			cache_hit = false;
			local_hit = true;
			return true;
		}

		local_hit = false;
		if (cache_.lookup(req, rlen, resp)) {
			cache_hit = true;
			return true;
		}
		cache_hit = false;
		if (!forward_dot(req, rlen, resp)) {
			return build_servfail(req, rlen, resp);
		}
		if (resp.size() >= 2) {
			resp[0] = req[0];
			resp[1] = req[1];
		}
		if (!resp.empty()) {
			cache_.store(req, rlen, &resp[0], resp.size());
		}
		return true;
	}

	void log_result(bool cache_hit, bool local_hit, const std::string& query_info, size_t response_size) const {
		if (!Logger::verbose()) {
			return;
		}
		if (local_hit) {
			Logger::log(Logger::CACHE, "Local override: " + query_info + " (" + std::to_string(response_size) + " bytes)");
		} else if (cache_hit) {
			Logger::log(Logger::CACHE, "Cache hit: " + query_info);
		} else {
			Logger::log(Logger::RES, "Resolved: " + query_info + " (" + std::to_string(response_size) + " bytes)");
		}
	}

	void serve_udp_request(const struct sockaddr_in& peer, socklen_t peer_len, const uint8_t* req, size_t rlen) {
		std::string query_info;
		if (Logger::verbose()) {
			char client_ip[INET_ADDRSTRLEN] = "unknown";
			inet_ntop(AF_INET, &peer.sin_addr, client_ip, sizeof(client_ip));
			query_info = parse_query_info(req, rlen);
			Logger::log(Logger::REQ, "UDP from " + std::string(client_ip) + ":" +
						std::to_string(ntohs(peer.sin_port)) + " -> " + query_info);
		}

		static thread_local std::vector<uint8_t> resp;
		if (resp.capacity() < cfg_.cache_resp_max) {
			resp.reserve(cfg_.cache_resp_max);
		}
		resp.clear();
		bool cache_hit = false;
		bool local_hit = false;
		if (!process_query(req, rlen, resp, cache_hit, local_hit)) {
			return;
		}
		log_result(cache_hit, local_hit, query_info, resp.size());
		if (!resp.empty()) {
			sendto(udp_fd_.get(), &resp[0], resp.size(), MSG_NOSIGNAL,
				   reinterpret_cast<const struct sockaddr*>(&peer), peer_len);
		}
	}

	void handle_udp() {
		std::vector<uint8_t>& buf = udp_buffer_;
		static thread_local std::vector<uint8_t> resp;
		if (resp.capacity() < cfg_.cache_resp_max) {
			resp.reserve(cfg_.cache_resp_max);
		}

		while (true) {
			struct sockaddr_in peer;
			std::memset(&peer, 0, sizeof(peer));
			socklen_t peer_len = sizeof(peer);
			ssize_t n = recvfrom(udp_fd_.get(), buf.empty() ? NULL : &buf[0], buf.size(), MSG_DONTWAIT | MSG_TRUNC,
								 reinterpret_cast<struct sockaddr*>(&peer), &peer_len);
			if (n < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
					return;
				}
				return;
			}
			if (n == 0) {
				continue;
			}
			if (static_cast<size_t>(n) > buf.size()) {
				continue;
			}

			resp.clear();
			if (local_records_.answer(&buf[0], static_cast<size_t>(n), resp)) {
				if (!resp.empty()) {
					sendto(udp_fd_.get(), &resp[0], resp.size(), MSG_NOSIGNAL,
						   reinterpret_cast<const struct sockaddr*>(&peer), peer_len);
				}
				continue;
			}
			if (cache_.lookup(&buf[0], static_cast<size_t>(n), resp)) {
				if (!resp.empty()) {
					sendto(udp_fd_.get(), &resp[0], resp.size(), MSG_NOSIGNAL,
						   reinterpret_cast<const struct sockaddr*>(&peer), peer_len);
				}
				continue;
			}

			if (!workers_.enqueue_udp(peer, peer_len, &buf[0], static_cast<size_t>(n))) {
				static thread_local std::vector<uint8_t> fail;
				fail.clear();
				if (build_servfail(&buf[0], static_cast<size_t>(n), fail) && !fail.empty()) {
					sendto(udp_fd_.get(), &fail[0], fail.size(), MSG_NOSIGNAL,
						   reinterpret_cast<const struct sockaddr*>(&peer), peer_len);
				}
			}
		}
	}

	void serve_tcp_client(int fd, bool tls) {
		UniqueFd client(fd);
		set_common_socket_opts(client.get(), cfg_);
		set_timeouts(client.get(), 10);

		struct sockaddr_in peer;
		std::memset(&peer, 0, sizeof(peer));
		socklen_t peer_len = sizeof(peer);
		char client_ip[INET_ADDRSTRLEN] = "unknown";
		uint16_t client_port = 0;
		if (getpeername(client.get(), reinterpret_cast<struct sockaddr*>(&peer), &peer_len) == 0) {
			inet_ntop(AF_INET, &peer.sin_addr, client_ip, sizeof(client_ip));
			client_port = ntohs(peer.sin_port);
		}

		SslPtr<SSL> ssl;
		if (tls) {
			ssl.reset(SSL_new(server_ctx_.get()));
			if (!ssl) {
				return;
			}
			SSL_set_fd(ssl.get(), client.get());
			if (SSL_accept(ssl.get()) <= 0) {
				return;
			}
		}

		uint8_t lenbuf[2];
		std::vector<uint8_t> req;
		req.reserve(cfg_.cache_key_max);
		std::vector<uint8_t> resp;
		resp.reserve(cfg_.cache_resp_max);

		while (g_running) {
			bool header_ok = tls ? ssl_read_all(ssl.get(), lenbuf, sizeof(lenbuf))
								 : fd_read_all(client.get(), lenbuf, sizeof(lenbuf));
			if (!header_ok) {
				break;
			}
			size_t rlen = be16(lenbuf);
			if (rlen == 0 || rlen > WIRE_MAX) {
				break;
			}
			req.resize(rlen);
			bool body_ok = tls ? ssl_read_all(ssl.get(), &req[0], rlen)
							   : fd_read_all(client.get(), &req[0], rlen);
			if (!body_ok) {
				break;
			}

			std::string query_info;
			if (Logger::verbose()) {
				query_info = parse_query_info(&req[0], req.size());
				Logger::log(Logger::REQ, std::string(tls ? "TCP-DoT" : "TCP") + " from " + client_ip +
							":" + std::to_string(client_port) + " -> " + query_info);
			}

			resp.clear();
			bool cache_hit = false;
			bool local_hit = false;
			if (!process_query(&req[0], req.size(), resp, cache_hit, local_hit) || resp.size() > WIRE_MAX) {
				break;
			}
			log_result(cache_hit, local_hit, query_info, resp.size());

			put_be16(lenbuf, static_cast<uint16_t>(resp.size()));
			bool write_ok = false;
			if (tls) {
				write_ok = ssl_write_all(ssl.get(), lenbuf, sizeof(lenbuf)) &&
						   ssl_write_all(ssl.get(), resp.empty() ? NULL : &resp[0], resp.size());
			} else {
				write_ok = fd_write_all(client.get(), lenbuf, sizeof(lenbuf)) &&
						   fd_write_all(client.get(), resp.empty() ? NULL : &resp[0], resp.size());
			}
			if (!write_ok) {
				break;
			}
		}
		if (ssl) {
			SSL_shutdown(ssl.get());
		}
	}

	void accept_loop(int fd, bool tls) {
		while (true) {
#ifdef SOCK_CLOEXEC
			int client = accept4(fd, NULL, NULL, SOCK_CLOEXEC);
#else
			int client = accept(fd, NULL, NULL);
#endif
			if (client < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
					return;
				}
				return;
			}
#ifndef SOCK_CLOEXEC
			set_cloexec(client);
#endif
			if (!workers_.enqueue_tcp(client, tls)) {
				::close(client);
			}
		}
	}

	static void add_epoll_fd(int efd, int fd, const char* name) {
		struct epoll_event ev;
		std::memset(&ev, 0, sizeof(ev));
		ev.events = EPOLLIN | EPOLLET;
		ev.data.fd = fd;
		if (epoll_ctl(efd, EPOLL_CTL_ADD, fd, &ev) < 0) {
			throw std::runtime_error(std::string("epoll_ctl ") + name + " failed");
		}
	}

public:
	Proxy(int argc, char** argv)
		: cfg_(RuntimeConfig::load(argc, argv)),
		  cache_(cfg_.cache_stripes, cfg_.cache_ways, cfg_.cache_key_max, cfg_.cache_resp_max),
		  local_records_(),
		  server_ctx_(), udp_fd_(), tcp_fd_(), dot_fd_(), dot_pool_(),
		  workers_(cfg_.workers, cfg_.max_work_queue), udp_buffer_(cfg_.udp_msg_max),
		  next_config_reload_(monotonic_seconds() + RELOAD_INTERVAL_SECONDS) {
		if (cfg_.listen_dot) {
			server_ctx_.reset(create_server_ctx());
			if (!server_ctx_) {
				throw std::runtime_error("failed to create local DoT TLS context");
			}
		}

		local_records_.load_from_file(cfg_.config_path);

		udp_fd_ = create_listener(cfg_.dns_port, SOCK_DGRAM);
		tcp_fd_ = create_listener(cfg_.dns_port, SOCK_STREAM);
		if (!udp_fd_.valid() || !tcp_fd_.valid()) {
			throw std::runtime_error("failed to bind DNS listener sockets. Are you running as root/sudo?");
		}
		if (cfg_.listen_dot) {
			dot_fd_ = create_listener(cfg_.dot_port, SOCK_STREAM);
			if (!dot_fd_.valid()) {
				throw std::runtime_error("failed to bind DoT listener socket. Are you running as root/sudo?");
			}
		}

		Logger::log(Logger::INFO, "Listening on " + cfg_.listen_ip + ":" + std::to_string(cfg_.dns_port) +
					" UDP/TCP DNS");
		if (cfg_.listen_dot) {
			Logger::log(Logger::INFO, "Listening on " + cfg_.listen_ip + ":" + std::to_string(cfg_.dot_port) +
						" TCP DoT");
		}
		if (cfg_.upstream_dot) {
			dot_pool_.reset(new UpstreamDoTPool(cfg_));
			Logger::log(Logger::INFO, "Upstream mode: DoT, lazy pool size " + std::to_string(cfg_.dot_pool_size));
		} else {
			Logger::log(Logger::INFO, "Upstream mode: plain DNS UDP/TCP");
		}
		Logger::log(Logger::INFO, "Runtime sizing: workers=" + std::to_string(cfg_.workers) +
					" queue=" + std::to_string(cfg_.max_work_queue) +
					" cache=" + std::to_string(cfg_.cache_stripes) + "x" + std::to_string(cfg_.cache_ways) +
					" udp_max=" + std::to_string(cfg_.udp_msg_max) +
					" sockbuf=" + std::to_string(cfg_.socket_buffer_bytes));

		workers_.start(this);
	}

	void run() {
		UniqueFd epoll_fd(epoll_create1(0));
		if (!epoll_fd.valid()) {
			throw std::runtime_error("epoll_create1 failed");
		}
		add_epoll_fd(epoll_fd.get(), udp_fd_.get(), "udp");
		add_epoll_fd(epoll_fd.get(), tcp_fd_.get(), "tcp");
		if (dot_fd_.valid()) {
			add_epoll_fd(epoll_fd.get(), dot_fd_.get(), "dot");
		}

		std::vector<struct epoll_event> events(16);
		while (g_running) {
			reload_config_if_due();
			int n = epoll_wait(epoll_fd.get(), &events[0], static_cast<int>(events.size()), 500);
			if (n < 0) {
				if (errno == EINTR) {
					continue;
				}
				break;
			}
			for (intS i = 0; i < n; ++i) {
				int fd = events[static_cast<size_t>(i)].data.fd;
				if (fd == udp_fd_.get()) {
					handle_udp();
				} else if (fd == tcp_fd_.get()) {
					accept_loop(tcp_fd_.get(), false);
				} else if (dot_fd_.valid() && fd == dot_fd_.get()) {
					accept_loop(dot_fd_.get(), true);
				}
			}
		}
		Logger::log(Logger::INFO, "Proxy shutting down cleanly.");
	}
};

void WorkerPool::thread_main(Proxy* proxy) {
	while (true) {
		Job job;
		{
			std::unique_lock<std::mutex> lock(mtx_);
			while (!stopping_ && size_ == 0) {
				cv_.wait(lock);
			}
			if (stopping_ && size_ == 0) {
				return;
			}
			job = std::move(queue_[head_]);
			queue_[head_] = Job();
			head_ = (head_ + 1) % queue_.size();
			--size_;
		}

		try {
			if (job.type == Job::JOB_UDP) {
				proxy->serve_udp_request(job.peer, job.peer_len,
									 job.req_heap == NULL ? job.req_inline : job.req_heap,
									 job.req_len);
			} else if (job.type == Job::JOB_TCP) {
				proxy->serve_tcp_client(job.fd, job.tls);
			}
		} catch (const std::exception& e) {
			Logger::log(Logger::ERROR, std::string("Worker job failed: ") + e.what());
		} catch (...) {
			Logger::log(Logger::ERROR, "Worker job failed with an unknown exception.");
		}
	}
}

int main(int argc, char** argv) {
	install_signal_handlers();

	OPENSSL_init_ssl(0, NULL);

	try {
		Proxy proxy(argc, argv);
		proxy.run();
	} catch (const std::exception& e) {
		std::cerr << "Fatal initialization error: " << e.what() << std::endl;
		return 1;
	}
	return 0;
}
