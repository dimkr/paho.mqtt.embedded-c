/*******************************************************************************
 * Copyright (c) 2014, 2017 IBM Corp.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 *
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *   http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * Contributors:
 *    Allan Stockdill-Mander - initial API and implementation and/or initial documentation
 *    Ian Craggs - return codes from linux_read
 *******************************************************************************/

#include "MQTTLinux.h"

void TimerInit(Timer* timer)
{
	timer->end_time = (struct timeval){0, 0};
}

char TimerIsExpired(Timer* timer)
{
	struct timeval now, res;
	gettimeofday(&now, NULL);
	timersub(&timer->end_time, &now, &res);
	return res.tv_sec < 0 || (res.tv_sec == 0 && res.tv_usec <= 0);
}


void TimerCountdownMS(Timer* timer, unsigned int timeout)
{
	struct timeval now;
	gettimeofday(&now, NULL);
	struct timeval interval = {timeout / 1000, (timeout % 1000) * 1000};
	timeradd(&now, &interval, &timer->end_time);
}


void TimerCountdown(Timer* timer, unsigned int timeout)
{
	struct timeval now;
	gettimeofday(&now, NULL);
	struct timeval interval = {timeout, 0};
	timeradd(&now, &interval, &timer->end_time);
}


int TimerLeftMS(Timer* timer)
{
	struct timeval now, res;
	gettimeofday(&now, NULL);
	timersub(&timer->end_time, &now, &res);
	//printf("left %d ms\n", (res.tv_sec < 0) ? 0 : res.tv_sec * 1000 + res.tv_usec / 1000);
	return (res.tv_sec < 0) ? 0 : res.tv_sec * 1000 + res.tv_usec / 1000;
}


int linux_read(Network* n, unsigned char* buffer, int len, int timeout_ms)
{
	struct timeval interval = {timeout_ms / 1000, (timeout_ms % 1000) * 1000};
	if (interval.tv_sec < 0 || (interval.tv_sec == 0 && interval.tv_usec <= 0))
	{
		interval.tv_sec = 0;
		interval.tv_usec = 100;
	}

	setsockopt(n->my_socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&interval, sizeof(struct timeval));

	int bytes = 0;
	while (bytes < len)
	{
#if defined(MQTT_SSL)
		int rc = mbedtls_ssl_read(&n->ssl, &buffer[bytes], (size_t)(len - bytes));
		if (rc < 0)
		{
			if ((rc != MBEDTLS_ERR_SSL_WANT_READ) && (rc != MBEDTLS_ERR_SSL_WANT_WRITE))
#else
		int rc = recv(n->my_socket, &buffer[bytes], (size_t)(len - bytes), 0);
		if (rc == -1)
		{
			if (errno != EAGAIN && errno != EWOULDBLOCK)
#endif
			  bytes = -1;
			break;
		}
		else if (rc == 0)
		{
			bytes = 0;
			break;
		}
		else
			bytes += rc;
	}
	return bytes;
}


int linux_write(Network* n, unsigned char* buffer, int len, int timeout_ms)
{
	struct timeval tv;

	tv.tv_sec = 0;  /* 30 Secs Timeout */
	tv.tv_usec = timeout_ms * 1000;  // Not init'ing this can cause strange errors

	setsockopt(n->my_socket, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv,sizeof(struct timeval));
#if defined(MQTT_SSL)
	int rc = mbedtls_ssl_write(&n->ssl, buffer, len);
	if (rc < 0)
	{
		if ((rc != MBEDTLS_ERR_SSL_WANT_READ) && (rc != MBEDTLS_ERR_SSL_WANT_WRITE))
			return -1;
		return 0;
	}
#else
	int	rc = write(n->my_socket, buffer, len);
#endif
	return rc;
}


void NetworkInit(Network* n)
{
	n->my_socket = 0;
	n->mqttread = linux_read;
	n->mqttwrite = linux_write;
	n->mqttkeepalive = NULL;
#if defined(MQTT_WEBSOCKET)
	TimerInit(&n->last_ping);
	n->ping_outstanding = 0;
	n->len = 0;
#endif
}


#if defined(MQTT_SSL)


static void NetworkDisconnectSSL(Network* n)
{
#  if defined(MQTT_SSL_VERIFY)
	mbedtls_x509_crt_free(&n->ca);
#  endif
	mbedtls_ssl_free(&n->ssl);
	mbedtls_ssl_config_free(&n->conf);
	mbedtls_ctr_drbg_free(&n->ctr_drbg);
	mbedtls_entropy_free(&n->entropy);
}


static int ssl_recv(void* ctx, unsigned char* buf, size_t len)
{
	int s = (int)(intptr_t)ctx;
	ssize_t rc;

	rc = recv(s, buf, len % INT_MAX, 0);
	if (rc < 0)
	{
		if (errno == EAGAIN)
			return MBEDTLS_ERR_SSL_WANT_READ;

		return MBEDTLS_ERR_NET_RECV_FAILED;
	}

	return (int)rc;
}


static int ssl_send(void* ctx, const unsigned char* buf, size_t len)
{
	int s = (int)(intptr_t)ctx;
	ssize_t rc;

	rc = send(s, buf, len % INT_MAX, 0);
	if (rc < 0)
	{
		if (errno == EAGAIN)
			return MBEDTLS_ERR_SSL_WANT_WRITE;

		return MBEDTLS_ERR_NET_SEND_FAILED;
	}

	return (int)rc;
}


extern const unsigned char* ca_certs;
extern const size_t ca_certs_len;


static int NetworkConnectSSL(Network* n, char* addr)
{
	int rc;

	mbedtls_ssl_init(&n->ssl);
	mbedtls_ssl_config_init(&n->conf);
#  if defined(MQTT_SSL_VERIFY)
	mbedtls_x509_crt_init(&n->ca);
#  endif
	mbedtls_ctr_drbg_init(&n->ctr_drbg);

	mbedtls_entropy_init(&n->entropy);
	if (mbedtls_ctr_drbg_seed(&n->ctr_drbg,
	                          mbedtls_entropy_func,
	                          &n->entropy,
	                          NULL,
	                          0) != 0)
		goto fail;

#  if defined(MQTT_SSL_VERIFY)
	if (mbedtls_x509_crt_parse(&n->ca, ca_certs, ca_certs_len) != 0)
		goto fail;
#  endif

	if (mbedtls_ssl_config_defaults(&n->conf,
	                                MBEDTLS_SSL_IS_CLIENT,
	                                MBEDTLS_SSL_TRANSPORT_STREAM,
	                                MBEDTLS_SSL_PRESET_DEFAULT) != 0)
		goto fail;

#  if defined(MQTT_SSL_VERIFY)
	mbedtls_ssl_conf_ca_chain(&n->conf, &n->ca, NULL);
#  else
	mbedtls_ssl_conf_authmode(&n->conf, MBEDTLS_SSL_VERIFY_NONE);
#  endif
	mbedtls_ssl_conf_rng(&n->conf, mbedtls_ctr_drbg_random, &n->ctr_drbg);

	if (mbedtls_ssl_setup(&n->ssl, &n->conf) != 0)
		goto fail;

	if (mbedtls_ssl_set_hostname(&n->ssl, addr) != 0)
		goto fail;

	mbedtls_ssl_set_bio(&n->ssl,
	                    (void *)(intptr_t)n->my_socket,
	                    ssl_send,
	                    ssl_recv,
	                    NULL);

	while (1) {
		rc =  mbedtls_ssl_handshake(&n->ssl);
		if (rc == 0)
			break;

		if ((rc != MBEDTLS_ERR_SSL_WANT_READ) && (rc != MBEDTLS_ERR_SSL_WANT_READ))
			goto fail;
	}

	if (mbedtls_ssl_get_verify_result(&n->ssl) == 0)
		return 0;

fail:
	NetworkDisconnectSSL(n);
	return -1;
}


#endif


#if defined(MQTT_WEBSOCKET)


enum {
	WS_CONT = 0,
	WS_BINARY = 2,
	WS_PING = 9,
	WS_PONG = 0xA,
};


typedef struct Header {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t opcode:4;
	uint8_t rsv3:1;
	uint8_t rsv2:1;
	uint8_t rsv1:1;
	uint8_t fin:1;

	uint8_t len:7;
	uint8_t ismasked:1;
#else
	uint8_t fin:1;
	uint8_t rsv1:1;
	uint8_t rsv2:1;
	uint8_t rsv3:1;
	uint8_t opcode:4;

	uint8_t ismasked:1;
	uint8_t len:7;
#endif
} __attribute__((packed)) Header;


static void websocket_mask(unsigned char* p, size_t len, uint32_t mask, unsigned char* dst)
{
	size_t i;
	union {
		uint32_t u32;
		uint8_t u8[4];
	} masku = {.u32 = mask};

	for (i = 0; i < len; ++i)
		dst[i] = p[i] ^ masku.u8[i % 4];
}


static int websocket_write_frame(Network* n, int opcode, unsigned char* buffer, int len, int timeout_ms)
{
	unsigned char* frame, *p;
	struct Header *hdr;
	int rc, total;
	unsigned int seed;

	total = sizeof(*hdr) + sizeof(uint32_t) + len;

	frame = malloc(total + sizeof(uint64_t));
	if (!frame)
		return -1;

	hdr = (struct Header*)frame;
	p = frame + sizeof(*hdr);

	*hdr = (struct Header){
		.fin = 1,
		.opcode = opcode,
		.ismasked = 1,
	};

	if (len > UINT16_MAX)
	{
		hdr->len = 127;
		*(uint64_t*)p = htobe64((uint64_t)len);
		p += sizeof(uint64_t);
		total += sizeof(uint64_t);
	}
	else if (len > 125)
	{
		hdr->len = 126;
		*(uint16_t*)p = htons((uint16_t)len);
		p += sizeof(uint16_t);
		total += sizeof(uint16_t);
	}
	else
		hdr->len = (uint8_t)len;

	seed = (unsigned int)time(NULL);
	*(uint32_t*)p = (uint32_t)(rand_r(&seed) & 0xFFFFFFFF);

	websocket_mask(buffer, len, *(uint32_t*)p, p + sizeof(uint32_t));

	rc = linux_write(n, frame, total, timeout_ms);
	free(frame);
	if (rc == total)
		return len;
	return rc;
}


static int websocket_write(Network* n, unsigned char* buffer, int len, int timeout_ms)
{
    return websocket_write_frame(n, WS_BINARY, buffer, len, timeout_ms);
}


static int websocket_read_frame(Network* n, unsigned char* buffer, int len, int timeout_ms, int *opcode)
{
	struct Header hdr;
	uint16_t len16;
	uint64_t len64;
	int total = 0, rc;

	do
	{
		if (n->len == 0)
		{
			rc = linux_read(n, (unsigned char*)&hdr, sizeof(hdr), timeout_ms);
			if (rc != sizeof(hdr))
				return rc;

			if (hdr.rsv1 || hdr.rsv2 || hdr.rsv3 || hdr.ismasked)
				return -1;

			switch (hdr.opcode)
			{
				case WS_BINARY:
				case WS_CONT:
				case WS_PING:
				case WS_PONG:
					break;

				default:
					return -1;
			}

			n->opcode = hdr.opcode;
			n->len = (int)hdr.len;

			switch (hdr.len)
			{
				case 126:
					rc = linux_read(n, (unsigned char*)&len16, sizeof(len16), timeout_ms);
					if (rc != sizeof(len16))
						return rc;

					n->len = (int)ntohs(len16);
					break;

				case 127:
					rc = linux_read(n, (unsigned char*)&len64, sizeof(len64), timeout_ms);
					if (rc != sizeof(len64))
						return -1;

					if (be64toh(len64) > INT_MAX)
						return -1;

					n->len = (int)be64toh(len64);
					break;
			}

			if (n->len == 0)
				return -1;
		}

		if (len < n->len)
			return -1;

		rc = linux_read(n, buffer + total, n->len, timeout_ms);
		if (rc <= 0)
			return rc;

		total += rc;
		len -= rc;
		n->len -= rc;
	}
	while (len > 0);

	*opcode = n->opcode;

	return total;
}


static int websocket_keepalive(Network* n, int timeout_ms, int keepAliveInterval)
{
	unsigned char p = 'P';
	int rc;

	if (n->ping_outstanding)
	{
		if (TimerIsExpired(&n->last_ping))
			return -1;

		return 1;
	}

	rc = websocket_write_frame(n, WS_PING, &p, sizeof(p), timeout_ms);
	if (rc <= 0)
		return rc;

	n->ping_outstanding = 1;
	TimerCountdown(&n->last_ping, keepAliveInterval);
	return rc;
}


static int websocket_read(Network* n, unsigned char* buffer, int len, int timeout_ms)
{
	int rc, opcode;

	while (1)
	{
		rc = websocket_read_frame(n, buffer, len, timeout_ms, &opcode);
		if (rc <= 0)
			return rc;

		switch (opcode)
		{
			case WS_BINARY:
			case WS_CONT:
				return rc;

			case WS_PING:
				rc = websocket_write_frame(n, WS_PONG, buffer, len, timeout_ms);
				if (rc <= 0)
					return rc;
				break;

			case WS_PONG:
				if (n->ping_outstanding && (rc == 1) && (buffer[0] == 'P'))
					n->ping_outstanding = 0;
				break;

			default:
				return -1;
		}
	}
}


static const char websocket_upgrade_fmt[] = \
    "GET %s HTTP/1.1\r\n"
    "Host: %s\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Key: %s\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "Sec-WebSocket-Protocol: mqtt\r\n"
    "\r\n";


#include <mbedtls/base64.h>
#include <mbedtls/sha1.h>


int NetworkConnectWebSocket(Network* n, char* addr, char* uri, int timeout_ms)
{
	static unsigned char buf[1024];
	static char line[128];
	static const unsigned char tail[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
	unsigned char key[16], b64[25], sha1[20], accept[32];
	mbedtls_sha1_context ctx;
	size_t len;
	int out, rc, i, validated = 0, lines = 0, mqtt = 0;
	unsigned int seed;

	seed = (unsigned int)time(NULL);
	for (i = 0; i < sizeof(key); ++i)
		key[i] = (unsigned char)(rand_r(&seed) & 0xFF);

	if (mbedtls_base64_encode(b64, sizeof(b64), &len, key, sizeof(key)) != 0)
		return -1;
	b64[len] = '\0';

	mbedtls_sha1_init(&ctx);
	if ((mbedtls_sha1_starts_ret(&ctx) != 0) ||
	    (mbedtls_sha1_update_ret(&ctx, b64, len) != 0) ||
	    (mbedtls_sha1_update_ret(&ctx, tail, sizeof(tail) - 1) != 0) ||
	    (mbedtls_sha1_finish_ret(&ctx, sha1) != 0))
	{
		mbedtls_sha1_free(&ctx);
		return -1;
	}
	mbedtls_sha1_free(&ctx);

	if (mbedtls_base64_encode(accept, sizeof(accept), &len, sha1, sizeof(sha1)) != 0)
		return -1;

	out = snprintf((char*)buf, sizeof(buf), websocket_upgrade_fmt, uri, addr, b64);
	if ((out <= 0) || (out >= sizeof(buf)))
		return -1;

	rc = linux_write(n, buf, out, timeout_ms);
	if (rc != out)
		return rc;

	while (lines < 32)
	{
next:
		for (i = 0; i < sizeof(line); ++i)
		{
			rc = linux_read(n, (unsigned char*)&line[i], 1, timeout_ms);
			if (rc != 1)
				return rc;

			if ((i == 0) || (line[i - 1] != '\r') || (line[i] != '\n'))
				continue;

			if (i == 1)
				goto done;

			--i;

			if ((lines == 0) &&
			    ((i < sizeof("HTTP/1.1 101") - 1) ||
			     (memcmp(line, "HTTP/1.1 101", sizeof("HTTP/1.1 101") - 1) != 0)))
				return -1;

			++lines;

			if ((i >= sizeof("Sec-WebSocket-Protocol:") - 1) &&
			    (memcmp(line, "Sec-WebSocket-Protocol:", sizeof("Sec-WebSocket-Protocol:") - 1) == 0))
			{
				if (mqtt)
					return -1;

				if ((i != sizeof("Sec-WebSocket-Protocol: mqtt") - 1) ||
				    (memcmp(&line[sizeof("Sec-WebSocket-Protocol: ") - 1], "mqtt", sizeof("mqtt") - 1) != 0))
					return -1;

				mqtt = 1;
				goto next;
			}

			if ((i != sizeof("Sec-WebSocket-Accept: ") - 1 + len) ||
				(memcmp(line, "Sec-WebSocket-Accept: ", sizeof("Sec-WebSocket-Accept: ") - 1) != 0))
				goto next;

			if (validated)
				return -1;

			if (memcmp(&line[sizeof("Sec-WebSocket-Accept: ") - 1], accept, len) != 0)
				return -1;

			validated = 1;
			goto next;
		}

		return -1;
	}

done:
	if ((lines < 2) || !mqtt || !validated)
		return -1;

	n->mqttread = websocket_read;
	n->mqttwrite = websocket_write;
	n->mqttkeepalive = websocket_keepalive;

	return 0;
}


#endif


int NetworkConnectURI(Network* n, char* addr, int port, char* uri, int timeout_ms)
{
	int rc = -1;
	struct addrinfo *result = NULL;
	struct addrinfo hints = {.ai_socktype = SOCK_STREAM};
	struct timeval tv = {.tv_sec = 3};

	if (getaddrinfo(addr, NULL, &hints, &result) == 0)
	{
		struct addrinfo* res;

		for (res = result; res; res = res->ai_next)
		{
			if (res->ai_family == AF_INET)
				((struct sockaddr_in*)(res->ai_addr))->sin_port = htons(port);
			else if (res->ai_family == AF_INET6)
				((struct sockaddr_in6*)(res->ai_addr))->sin6_port = htons(port);
			else
				continue;

			n->my_socket = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
			if (n->my_socket != -1) {
				setsockopt(n->my_socket, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv,sizeof(struct timeval));
				rc = connect(n->my_socket, res->ai_addr, res->ai_addrlen);
				if (rc != 0)
					goto fail;

#if defined(MQTT_SSL)
				rc = NetworkConnectSSL(n, addr);
				if (rc != 0)
					goto fail;
#endif

#if defined(MQTT_WEBSOCKET)
				rc = NetworkConnectWebSocket(n, addr, uri, timeout_ms);
				if (rc != 0)
					goto fail;
#endif

				tv.tv_sec = 0;
				setsockopt(n->my_socket, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv,sizeof(struct timeval));
				break;

fail:
				close(n->my_socket);
				n->my_socket = -1;
			}
		}

		freeaddrinfo(result);
	}

	return rc;
}


int NetworkConnect(Network* n, char* addr, int port)
{
	return NetworkConnectURI(n, addr, port, "/", 1000);
}


void NetworkDisconnect(Network* n)
{
#if defined(MQTT_SSL)
	NetworkDisconnectSSL(n);
#endif
	close(n->my_socket);
}
