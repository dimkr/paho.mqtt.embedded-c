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
		return -1;
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
}


#if defined(MQTT_SSL)


static void NetworkDisconnectSSL(Network* n)
{
	mbedtls_x509_crt_free(&n->ca);
	mbedtls_ssl_free(&n->ssl);
	mbedtls_ssl_config_free(&n->conf);
	mbedtls_ctr_drbg_free(&n->ctr_drbg);
	mbedtls_entropy_free(&n->entropy);
}


static int ssl_recv(void *ctx, unsigned char *buf, size_t len)
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


static int ssl_send(void *ctx, const unsigned char *buf, size_t len)
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


extern const unsigned char *ca_certs;
extern const size_t ca_certs_len;


static int NetworkConnectSSL(Network* n, char* addr)
{
	int rc;

	mbedtls_ssl_init(&n->ssl);
	mbedtls_ssl_config_init(&n->conf);
	mbedtls_x509_crt_init(&n->ca);
	mbedtls_ctr_drbg_init(&n->ctr_drbg);

	mbedtls_entropy_init(&n->entropy);
	if (mbedtls_ctr_drbg_seed(&n->ctr_drbg,
	                          mbedtls_entropy_func,
	                          &n->entropy,
	                          NULL,
	                          0) != 0)
		goto fail;

	if (mbedtls_x509_crt_parse(&n->ca, ca_certs, ca_certs_len) != 0)
		goto fail;

	if (mbedtls_ssl_config_defaults(&n->conf,
	                                MBEDTLS_SSL_IS_CLIENT,
	                                MBEDTLS_SSL_TRANSPORT_STREAM,
	                                MBEDTLS_SSL_PRESET_DEFAULT) != 0)
		goto fail;

	mbedtls_ssl_conf_ca_chain(&n->conf, &n->ca, NULL);
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


int NetworkConnect(Network* n, char* addr, int port)
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
				if (rc == 0) {
#if defined(MQTT_SSL)
					rc = NetworkConnectSSL(n, addr);
					if (rc == 0)
#else
					if (1)
#endif
					{
						tv.tv_sec = 0;
						setsockopt(n->my_socket, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv,sizeof(struct timeval));
						break;
					}
				}

				close(n->my_socket);
				n->my_socket = -1;
			}
		}

		freeaddrinfo(result);
	}

	return rc;
}


void NetworkDisconnect(Network* n)
{
#if defined(MQTT_SSL)
	NetworkDisconnectSSL(n);
#endif
	close(n->my_socket);
}
