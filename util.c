/**
 * @file util.c
 * @note Copyright (C) 2011 Richard Cochran <richardcochran@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <linux/limits.h>
#include <libgen.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifdef HAVE_LIBCAP
#include <grp.h>
#include <pwd.h>
#include <sys/prctl.h>
#include <sys/capability.h>
#include <unistd.h>
#endif

#include "address.h"
#include "interface.h"
#include "phc.h"
#include "print.h"
#include "sk.h"
#include "util.h"

#define NS_PER_SEC 1000000000LL
#define NS_PER_HOUR (3600 * NS_PER_SEC)
#define NS_PER_DAY (24 * NS_PER_HOUR)

static int running = 1;

const char *ps_str[] = {
	"NONE",
	"INITIALIZING",
	"FAULTY",
	"DISABLED",
	"LISTENING",
	"PRE_MASTER",
	"MASTER",
	"PASSIVE",
	"UNCALIBRATED",
	"SLAVE",
	"GRAND_MASTER",
};

const char *ev_str[] = {
	"NONE",
	"POWERUP",
	"INITIALIZE",
	"DESIGNATED_ENABLED",
	"DESIGNATED_DISABLED",
	"FAULT_CLEARED",
	"FAULT_DETECTED",
	"STATE_DECISION_EVENT",
	"QUALIFICATION_TIMEOUT_EXPIRES",
	"ANNOUNCE_RECEIPT_TIMEOUT_EXPIRES",
	"SYNCHRONIZATION_FAULT",
	"MASTER_CLOCK_SELECTED",
	"INIT_COMPLETE",
	"RS_MASTER",
	"RS_GRAND_MASTER",
	"RS_SLAVE",
	"RS_PASSIVE",
};

const char *ts_str(enum timestamp_type ts)
{
	switch (ts) {
	case TS_SOFTWARE:
		return "SOFTWARE";
	case TS_HARDWARE:
		return "HARDWARE";
	case TS_LEGACY_HW:
		return "LEGACY_HW";
	case TS_ONESTEP:
		return "ONESTEP";
	case TS_P2P1STEP:
		return "P2P1STEP";
	}

	return "???";
}

int addreq(enum transport_type type, struct address *a, struct address *b)
{
	void *bufa, *bufb;
	int len;

	switch (type) {
	case TRANS_UDP_IPV4:
		bufa = &a->sin.sin_addr;
		bufb = &b->sin.sin_addr;
		len = sizeof(a->sin.sin_addr);
		break;
	case TRANS_UDP_IPV6:
		bufa = &a->sin6.sin6_addr;
		bufb = &b->sin6.sin6_addr;
		len = sizeof(a->sin6.sin6_addr);
		break;
	case TRANS_IEEE_802_3:
		bufa = &a->sll.sll_addr;
		bufb = &b->sll.sll_addr;
		len = MAC_LEN;
		break;
	case TRANS_UDS:
	case TRANS_DEVICENET:
	case TRANS_CONTROLNET:
	case TRANS_PROFINET:
	default:
		pr_err("sorry, cannot compare addresses for this transport");
		return 0;
	}
	return memcmp(bufa, bufb, len) == 0 ? 1 : 0;
}

char *bin2str_impl(Octet *data, int len, char *buf, int buf_len)
{
	int i, offset = 0;
	if (len > MAX_PRINT_BYTES)
		len = MAX_PRINT_BYTES;
	buf[0] = '\0';
	if (!data)
		return buf;
	if (len)
		offset += snprintf(buf, buf_len, "%02hhx", data[0]);
	for (i = 1; i < len; i++) {
		if (offset >= buf_len)
			/* truncated output */
			break;
		offset += snprintf(buf + offset, buf_len - offset, ":%02hhx", data[i]);
	}
	return buf;
}

char *cid2str(struct ClockIdentity *id)
{
	static char buf[64];
	unsigned char *ptr = id->id;
	snprintf(buf, sizeof(buf), "%02x%02x%02x.%02x%02x.%02x%02x%02x",
		 ptr[0], ptr[1], ptr[2], ptr[3],
		 ptr[4], ptr[5], ptr[6], ptr[7]);
	return buf;
}

int count_char(const char *str, char c)
{
	int num = 0;
	char s;
	while ((s = *(str++))) {
		if (s == c)
			num++;
	}
	return num;
}

char *pid2str(struct PortIdentity *id)
{
	static char buf[64];
	unsigned char *ptr = id->clockIdentity.id;
	snprintf(buf, sizeof(buf), "%02x%02x%02x.%02x%02x.%02x%02x%02x-%hu",
		 ptr[0], ptr[1], ptr[2], ptr[3],
		 ptr[4], ptr[5], ptr[6], ptr[7],
		 id->portNumber);
	return buf;
}

char *portaddr2str(struct PortAddress *addr)
{
	static char buf[BIN_BUF_SIZE];
	switch (align16(&addr->networkProtocol)) {
	case TRANS_UDP_IPV4:
		if (align16(&addr->addressLength) == 4
			&& inet_ntop(AF_INET, addr->address, buf, sizeof(buf)))
			return buf;
		break;
	case TRANS_UDP_IPV6:
		if (align16(&addr->addressLength) == 16
			&& inet_ntop(AF_INET6, addr->address, buf, sizeof(buf)))
			return buf;
		break;
	}
	bin2str_impl(addr->address, align16(&addr->addressLength), buf, sizeof(buf));
	return buf;
}

const char *ustate2str(enum unicast_state ustate)
{
	switch (ustate) {
	case UC_WAIT:
		return "WAIT";
	case UC_HAVE_ANN:
		return "HAVE_ANN";
	case UC_NEED_SYDY:
		return "NEED_SYDY";
	case UC_HAVE_SYDY:
		return "HAVE_SYDY";
	}

	return "???";
}

enum port_state port_state_normalize(enum port_state state)
{
	switch (state) {
	case PS_MASTER:
	case PS_SLAVE:
	case PS_PRE_MASTER:
	case PS_UNCALIBRATED:
		return state;
	default:
		return PS_DISABLED;
	}
}

void posix_clock_close(clockid_t clock)
{
	if (clock == CLOCK_REALTIME) {
		return;
	}
	phc_close(clock);
}

clockid_t posix_clock_open(const char *device, int *phc_index)
{
	char phc_device_path[PATH_MAX];
	struct sk_ts_info ts_info;
	char phc_device[19];
	int clkid;

	/* check if device is CLOCK_REALTIME */
	if (!strcasecmp(device, "CLOCK_REALTIME")) {
		return CLOCK_REALTIME;
	}

	/* if the device name resolves to a plausible filesystem path, we
	 * assume it is the path to a PHC char device, and treat it as such
	 */
	if (realpath(device, phc_device_path)) {
		clkid = phc_open(device);
		if (clkid == CLOCK_INVALID)
			return clkid;

		if (!strncmp(phc_device_path, "/dev/ptp", strlen("/dev/ptp"))) {
			int r = get_ranged_int(phc_device_path + strlen("/dev/ptp"),
					       phc_index, 0, 65535);
			if (r) {
				fprintf(stderr,
					"failed to parse PHC index from %s\n",
					phc_device_path);
				phc_close(clkid);
				return CLOCK_INVALID;
			}
		}
		return clkid;
	}

	/* check if device is a valid ethernet device */
	if (sk_get_ts_info(device, &ts_info) || !ts_info.valid) {
		pr_err("unknown clock %s: %m", device);
		return CLOCK_INVALID;
	}
	if (ts_info.phc_index < 0) {
		pr_err("interface %s does not have a PHC", device);
		return CLOCK_INVALID;
	}
	snprintf(phc_device, sizeof(phc_device), "/dev/ptp%d", ts_info.phc_index);
	clkid = phc_open(phc_device);
	if (clkid == CLOCK_INVALID) {
		pr_err("cannot open %s for %s: %m", phc_device, device);
	}
	*phc_index = ts_info.phc_index;
	return clkid;
}

int str2addr(enum transport_type type, const char *s, struct address *addr)
{
	unsigned char mac[MAC_LEN];
	struct in_addr ipv4_addr;
	struct in6_addr ipv6_addr;

	memset(addr, 0, sizeof(*addr));

	switch (type) {
	case TRANS_UDS:
	case TRANS_DEVICENET:
	case TRANS_CONTROLNET:
	case TRANS_PROFINET:
		pr_err("sorry, cannot convert addresses for this transport");
		return -1;
	case TRANS_UDP_IPV4:
		if (!inet_aton(s, &ipv4_addr)) {
			pr_err("bad IPv4 address");
			return -1;
		}
		addr->sin.sin_family = AF_INET;
		addr->sin.sin_addr = ipv4_addr;
		addr->len = sizeof(addr->sin);
		break;
	case TRANS_UDP_IPV6:
		if (1 != inet_pton(AF_INET6, s, &ipv6_addr)) {
			pr_err("bad IPv6 address");
			return -1;
		}
		addr->sin6.sin6_family = AF_INET6;
		addr->sin6.sin6_addr = ipv6_addr;
		addr->len = sizeof(addr->sin6);
		break;
	case TRANS_IEEE_802_3:
		if (str2mac(s, mac)) {
			pr_err("bad Layer-2 address");
			return -1;
		}
		addr->sll.sll_family = AF_PACKET;
		addr->sll.sll_halen = MAC_LEN;
		memcpy(&addr->sll.sll_addr, mac, MAC_LEN);
		addr->len = sizeof(addr->sll);
		break;
	}
	return 0;
}

int str2mac(const char *s, unsigned char mac[MAC_LEN])
{
	unsigned char buf[MAC_LEN];
	int c;
	c = sscanf(s, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
		   &buf[0], &buf[1], &buf[2], &buf[3], &buf[4], &buf[5]);
	if (c != MAC_LEN) {
		return -1;
	}
	memcpy(mac, buf, MAC_LEN);
	return 0;
}

int str2cid(const char *s, struct ClockIdentity *result)
{
	struct ClockIdentity cid;
	unsigned char *ptr = cid.id;
	int c;
	c = sscanf(s, " %02hhx%02hhx%02hhx.%02hhx%02hhx.%02hhx%02hhx%02hhx",
		   &ptr[0], &ptr[1], &ptr[2], &ptr[3],
		   &ptr[4], &ptr[5], &ptr[6], &ptr[7]);
	if (c == 8) {
		*result = cid;
		return 0;
	}
	return -1;
}

int str2pid(const char *s, struct PortIdentity *result)
{
	struct PortIdentity pid;
	unsigned char *ptr = pid.clockIdentity.id;
	int c;
	c = sscanf(s, " %02hhx%02hhx%02hhx.%02hhx%02hhx.%02hhx%02hhx%02hhx-%hu",
		   &ptr[0], &ptr[1], &ptr[2], &ptr[3],
		   &ptr[4], &ptr[5], &ptr[6], &ptr[7],
		   &pid.portNumber);
	if (c == 9) {
		*result = pid;
		return 0;
	}
	return -1;
}

int generate_clock_identity(struct ClockIdentity *ci, const char *name)
{
	struct address addr;

	if (sk_interface_macaddr(name, &addr))
		return -1;

	switch (addr.sll.sll_halen) {
		case EUI48:
			ci->id[0] = addr.sll.sll_addr[0];
			ci->id[1] = addr.sll.sll_addr[1];
			ci->id[2] = addr.sll.sll_addr[2];
			ci->id[3] = 0xFF;
			ci->id[4] = 0xFE;
			ci->id[5] = addr.sll.sll_addr[3];
			ci->id[6] = addr.sll.sll_addr[4];
			ci->id[7] = addr.sll.sll_addr[5];
			break;
		case EUI64:
			ci->id[0] = addr.sll.sll_addr[0];
			ci->id[1] = addr.sll.sll_addr[1];
			ci->id[2] = addr.sll.sll_addr[2];
			ci->id[3] = addr.sll.sll_addr[3];
			ci->id[4] = addr.sll.sll_addr[4];
			ci->id[5] = addr.sll.sll_addr[5];
			ci->id[6] = addr.sll.sll_addr[6];
			ci->id[7] = addr.sll.sll_addr[7];
			break;
		default:
			return -1;
	}

	return 0;
}

/* Naive count of utf8 symbols. Doesn't detect invalid UTF-8 and
 * probably doesn't count combining characters correctly. */
static size_t strlen_utf8(const Octet *s)
{
	size_t len = 0;
	char c;
	while ((c = *(s++))) {
		if ((c & 0xC0) != 0x80)
			len++;
	}
	return len;
}

int static_ptp_text_copy(struct static_ptp_text *dst, const struct PTPText *src)
{
	int len = src->length;
	if (dst->max_symbols > 0 && strlen_utf8(src->text) > dst->max_symbols)
		return -1;
	dst->length = len;
	memcpy(dst->text, src->text, len);
	dst->text[len] = '\0';
	return 0;
}

void ptp_text_copy(struct PTPText *dst, const struct static_ptp_text *src)
{
	dst->length = src->length;
	memcpy(dst->text, src->text, src->length);
}

int ptp_text_set(struct PTPText *dst, const char *src)
{
	size_t len;
	if (src) {
		len = strlen(src);
		if (len > MAX_PTP_OCTETS)
			return -1;
		dst->length = len;
		memcpy(dst->text, src, len);
	} else {
		dst->length = 0;
	}
	return 0;
}

int static_ptp_text_set(struct static_ptp_text *dst, const char *src)
{
	int len = strlen(src);
	if (len > MAX_PTP_OCTETS)
		return -1;
	if (dst->max_symbols > 0 && strlen_utf8((Octet *) src) > dst->max_symbols)
		return -1;
	dst->length = len;
	memcpy(dst->text, src, len);
	dst->text[len] = '\0';
	return 0;
}

int is_utc_ambiguous(uint64_t ts)
{
	/* The Linux kernel inserts leap second by stepping the clock backwards
	   at 0:00 UTC, the last second before midnight is played twice. */
	if (NS_PER_DAY - ts % NS_PER_DAY <= NS_PER_SEC)
		return 1;
	return 0;
}

int leap_second_status(uint64_t ts, int leap_set, int *leap, int *utc_offset)
{
	int leap_status = leap_set;

	/* The leap bits obtained by PTP should be set at most 12 hours before
	   midnight and unset at most 2 announce intervals after midnight.
	   Split updates which are too early and which are too late at 6 hours
	   after midnight. */
	if (ts % NS_PER_DAY > 6 * NS_PER_HOUR) {
		if (!leap_status)
			leap_status = *leap;
	} else {
		if (leap_status)
			leap_status = 0;
	}

	/* Fix early or late update of leap and utc_offset. */
	if (!*leap && leap_status) {
		*utc_offset -= leap_status;
		*leap = leap_status;
	} else if (*leap && !leap_status) {
		*utc_offset += *leap;
		*leap = leap_status;
	}

	return leap_status;
}

enum parser_result get_ranged_int(const char *str_val, int *result,
				  int min, int max)
{
	long parsed_val;
	char *endptr = NULL;
	errno = 0;
	parsed_val = strtol(str_val, &endptr, 0);
	if (*endptr != '\0' || endptr == str_val)
		return MALFORMED;
	if (errno == ERANGE || parsed_val < min || parsed_val > max)
		return OUT_OF_RANGE;
	*result = parsed_val;
	return PARSED_OK;
}

enum parser_result get_ranged_uint(const char *str_val, unsigned int *result,
				   unsigned int min, unsigned int max)
{
	unsigned long parsed_val;
	char *endptr = NULL;
	errno = 0;
	parsed_val = strtoul(str_val, &endptr, 0);
	if (*endptr != '\0' || endptr == str_val)
		return MALFORMED;
	if (errno == ERANGE || parsed_val < min || parsed_val > max)
		return OUT_OF_RANGE;
	*result = parsed_val;
	return PARSED_OK;
}

enum parser_result get_ranged_double(const char *str_val, double *result,
				     double min, double max)
{
	double parsed_val;
	char *endptr = NULL;
	errno = 0;
	parsed_val = strtod(str_val, &endptr);
	if (*endptr != '\0' || endptr == str_val)
		return MALFORMED;
	if (errno == ERANGE || parsed_val < min || parsed_val > max)
		return OUT_OF_RANGE;
	*result = parsed_val;
	return PARSED_OK;
}

int get_arg_val_i(int op, const char *optarg, int *val, int min, int max)
{
	enum parser_result r;
	r = get_ranged_int(optarg, val, min, max);
	if (r == MALFORMED) {
		fprintf(stderr,
			"-%c: %s is a malformed value\n", op, optarg);
		return -1;
	}
	if (r == OUT_OF_RANGE) {
		fprintf(stderr,
			"-%c: %s is out of range. Must be in the range %d to %d\n",
			op, optarg, min, max);
		return -1;
	}
	return 0;
}

int get_arg_val_ui(int op, const char *optarg, unsigned int *val,
		   unsigned int min, unsigned int max)
{
	enum parser_result r;
	r = get_ranged_uint(optarg, val, min, max);
	if (r == MALFORMED) {
		fprintf(stderr,
			"-%c: %s is a malformed value\n", op, optarg);
		return -1;
	}
	if (r == OUT_OF_RANGE) {
		fprintf(stderr,
			"-%c: %s is out of range. Must be in the range %u to %u\n",
			op, optarg, min, max);
		return -1;
	}
	return 0;
}

int get_arg_val_d(int op, const char *optarg, double *val,
		  double min, double max)
{
	enum parser_result r;
	r = get_ranged_double(optarg, val, min, max);
	if (r == MALFORMED) {
		fprintf(stderr,
			"-%c: %s is a malformed value\n", op, optarg);
		return -1;
	}
	if (r == OUT_OF_RANGE) {
		fprintf(stderr,
			"-%c: %s is out of range. Must be in the range %e to %e\n",
			op, optarg, min, max);
		return -1;
	}
	return 0;
}

static void handle_int_quit_term(int s)
{
	running = 0;
}

int handle_term_signals(void)
{
	if (SIG_ERR == signal(SIGINT, handle_int_quit_term)) {
		fprintf(stderr, "cannot handle SIGINT\n");
		return -1;
	}
	if (SIG_ERR == signal(SIGQUIT, handle_int_quit_term)) {
		fprintf(stderr, "cannot handle SIGQUIT\n");
		return -1;
	}
	if (SIG_ERR == signal(SIGTERM, handle_int_quit_term)) {
		fprintf(stderr, "cannot handle SIGTERM\n");
		return -1;
	}
	if (SIG_ERR == signal(SIGHUP, handle_int_quit_term)) {
		fprintf(stderr, "cannot handle SIGHUP\n");
		return -1;
	}
	return 0;
}

int is_running(void)
{
	return running;
}

void *xmalloc(size_t size)
{
	void *r;

	r = malloc(size);
	if (!r) {
		pr_err("failed to allocate memory");
		exit(1);
	}

	return r;
}

void *xcalloc(size_t nmemb, size_t size)
{
	void *r;

	r = calloc(nmemb, size);
	if (!r) {
		pr_err("failed to allocate memory");
		exit(1);
	}

	return r;
}

void *xrealloc(void *ptr, size_t size)
{
	void *r;

	r = realloc(ptr, size);
	if (!r) {
		pr_err("failed to allocate memory");
		exit(1);
	}

	return r;
}

char *xstrdup(const char *s)
{
	void *r;

	r = strdup(s);
	if (!r) {
		pr_err("failed to allocate memory");
		exit(1);
	}

	return r;
}

char *string_newf(const char *format, ...)
{
	va_list ap;
	char *s;

	va_start(ap, format);
	if (vasprintf(&s, format, ap) < 0) {
		pr_err("failed to allocate memory");
		exit(1);
	}
	va_end(ap);

	return s;
}

void string_append(char **s, const char *str)
{
	size_t len1, len2;

	len1 = strlen(*s);
	len2 = strlen(str);
	*s = xrealloc(*s, len1 + len2 + 1);
	memcpy((*s) + len1, str, len2 + 1);
}

void string_appendf(char **s, const char *format, ...)
{
	va_list ap;
	size_t len1;
	int len2;
	char *s2;

	len1 = strlen(*s);

	va_start(ap, format);
	len2 = vasprintf(&s2, format, ap);
	va_end(ap);

	if (len2 < 0) {
		*s = NULL;
		return;
	}

	*s = xrealloc(*s, len1 + len2 + 1);
	memcpy((*s) + len1, s2, len2 + 1);
	free(s2);
}

void **parray_new(void)
{
	void **a;

	a = xmalloc(sizeof(*a));
	*a = NULL;

	return a;
}

void parray_append(void ***a, void *p)
{
	parray_extend(a, p, NULL);
}

void parray_extend(void ***a, ...)
{
	va_list ap;
	int ilen, len, alloced;
	void *p;

	for (len = 0; (*a)[len]; len++)
		;
	len++;

	va_start(ap, a);
	for (ilen = 0; va_arg(ap, void *); ilen++)
		;
	va_end(ap);

	/* Reallocate in exponentially increasing sizes. */
	for (alloced = 1; alloced < len; alloced <<= 1)
		;
	if (alloced < len + ilen) {
		while (alloced < len + ilen)
			alloced *= 2;
		*a = xrealloc(*a, alloced * sizeof **a);
	}

	va_start(ap, a);
	while ((p = va_arg(ap, void *)))
		(*a)[len++ - 1] = p;
	va_end(ap);
	(*a)[len - 1] = NULL;
}

int rate_limited(int interval, time_t *last)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts))
		return 1;
	if (*last + interval > ts.tv_sec)
		return 1;

	*last = ts.tv_sec;

	return 0;
}

const int B64[] = {62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61,
	-1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
	14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1,
	26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43,
	44, 45, 46, 47, 48, 49, 50, 51};
static inline int parseB64(const char c)
{
	if (c < '+' || c > 'z')
		return -1;
	return B64[c - '+'];
}
size_t base64_len(const char *str, size_t len)
{
	div_t q;
	int diff = 0;

	if (len == 0)
		len = strlen(str);
	if (len < 2)
		return 0;
	q = div(len, 4);
	if (q.rem == 0) {
		if (str[len - 1] == '=')
			diff--;
		if (str[len - 2] == '=')
			diff--;
	} else {
		diff++;
		if (q.rem > 2)
			diff++;
	}
	return (q.quot * 3) + diff;
}

bool base64_decode(const char *in_str, size_t in_len, void *out, size_t *out_len)
{
	size_t len, i;
	uint8_t *cur, d[4];

	if (!in_str || !out_len)
		return false;
	if (in_len == 0)
		in_len = strlen(in_str);
	if (in_len == 0) {
		*out_len = 0;
		return true;
	}
	if (!out)
		return false;
	len = *out_len;
	cur = (uint8_t *)out;
	for (; in_len > 4; in_len -= 4) {
		// Read 4 characters
		for (i = 0; i < 4; i++) {
			int r = parseB64(*in_str++);
			if (r < 0)
				return false;
			d[i] = r;
		}
		if (len) {
			*cur++ = ((d[0] << 2) & 0xfc) | ((d[1] >> 4) & 0x03);
			len--;
		}
		if (len) {
			*cur++ = ((d[1] << 4) & 0xf0) | ((d[2] >> 2) & 0x0f);
			len--;
		}
		if (len) {
			*cur++ = ((d[2] << 6) & 0xc0) | (d[3] & 0x3f);
			len--;
		}
	}
	if (in_len < 2)
		return false;
	if (in_len == 4 && in_str[3] == '=')
		in_len--;
	if (in_len == 3 && in_str[2] == '=')
		in_len--;
	for (i = 0; i < in_len; i++) {
		int r = parseB64(*in_str++);
		if (r < 0)
			return false;
		d[i] = r;
	}
	if (len) {
		*cur++ = ((d[0] << 2) & 0xfc) | ((d[1] >> 4) & 0x03);
		len--;
	}
	if (in_len > 2) {
		if (len) {
			*cur++ = ((d[1] << 4) & 0xf0) | ((d[2] >> 2) & 0x0f);
			len--;
		}
		if (in_len == 4 && len) {
			*cur++ = ((d[2] << 6) & 0xc0) | (d[3] & 0x3f);
			len--;
		}
	}
	*out_len = *out_len - len;
	return true;
}

int str2prid(const char *s, struct ProfileIdentity *result)
{
	struct ProfileIdentity prid;
	int c;

	c = sscanf(s, " %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
		   &prid.id[0], &prid.id[1], &prid.id[2],
		   &prid.id[3], &prid.id[4], &prid.id[5]);
	if (c == 6) {
		*result = prid;
		return 0;
	}
	return -1;
}

void create_uds_directory(const char *address, const char *user)
{
	char path[MAX_IFNAME_SIZE + 1], *dir;
#ifdef HAVE_LIBCAP
	struct passwd *pw;
#endif

	if (snprintf(path, sizeof(path), "%s", address) >= sizeof(path)) {
		pr_err("path too long for UDS");
		return;
	}

	dir = dirname(path);

	/* Don't do anything if it already exists or cannot be created */
	if (mkdir(dir, 0775)) {
		if (errno != EEXIST)
			pr_err("failed to create %s: %m", dir);
		return;
	}

#ifdef HAVE_LIBCAP
	if (user[0] == '\0')
		return;

	pw = getpwnam(user);
	if (!pw) {
		pr_err("failed to get user/group ID of %s", user);
		rmdir(dir);
		return;
	}

	if (lchown(dir, pw->pw_uid, pw->pw_gid)) {
		pr_err("failed to change owner of %s: %m", dir);
		rmdir(dir);
		return;
	}
#endif
}

int drop_root_privileges(const char *user)
{
#ifdef HAVE_LIBCAP
	struct passwd *pw;
	cap_t cap;
#endif

	if (user[0] == '\0')
		return 0;

#ifdef HAVE_LIBCAP
	pw = getpwnam(user);
	if (!pw) {
		pr_err("failed to get user/group ID of %s", user);
		return -1;
	}

	if (prctl(PR_SET_KEEPCAPS, 1)) {
		pr_err("failed to set KEEPCAPS flag");
		return -1;
	}

	if (initgroups(user, pw->pw_gid)) {
		pr_err("failed to init supplementary groups");
		return -1;
	}

	if (setgid(pw->pw_gid)) {
		pr_err("failed to set group ID");
		return -1;
	}

	if (setuid(pw->pw_uid)) {
		pr_err("failed to set user ID");
		return -1;
	}

	cap = cap_from_text("cap_sys_time,cap_net_admin,"
			    "cap_net_bind_service,cap_net_raw=ep");
	if (!cap) {
		pr_err("failed to initialize capabilities");
		return -1;
	}

	if (cap_set_proc(cap)) {
		pr_err("failed to set process capabilities");
		cap_free(cap);
		return -1;
	}

	cap_free(cap);

	return 0;
#else
	pr_err("cannot drop root privileges without libcap");
	return -1;
#endif
}
