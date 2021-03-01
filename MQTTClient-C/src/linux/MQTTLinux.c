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
		int rc = recv(n->my_socket, &buffer[bytes], (size_t)(len - bytes), 0);
		if (rc == -1)
		{
			if (errno != EAGAIN && errno != EWOULDBLOCK)
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
	int	rc = write(n->my_socket, buffer, len);
	return rc;
}


void NetworkInit(Network* n)
{
	n->my_socket = 0;
	n->mqttread = linux_read;
	n->mqttwrite = linux_write;
}


int NetworkConnect(Network* n, char* addr, int port)
{
	int rc = -1, one = 1;
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
					tv.tv_sec = 0;
					setsockopt(n->my_socket, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv,sizeof(struct timeval));
					setsockopt(n->my_socket, SOL_TCP, TCP_NODELAY, (char *)&one,sizeof(one));
					break;
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
	close(n->my_socket);
}
