#ifndef _LB_LISTEN_H_
#define _LB_LISTEN_H_

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "hashring.h"
#include "hashget.h"

#define UNUSED(x)       (void)(x)
#define SOCKET_NAME     "/var/lib/testpmd/lb.sock"
#define DUT_REPLICAS    (4)
#define DUT_MAC_ADDED   (1)
#define DUT_MAC_REMOVED (2)

void
lb_listen_init(void);
void
lb_listen_deinit(void);
static void *
lb_listen(void *arg);
static void
process_data(char *data);

static pthread_t lb_thread;
static uint8_t lb_listen_flag = 0;
static int sock_conn, sock_data;
static struct hash_ring_t *ring;

void
lb_listen_init(void)
{
	if (lb_listen_flag == 1)
		return;
	pthread_create(&lb_thread, NULL, lb_listen, NULL);
	lb_listen_flag = 1;
	ring = hash_ring_create(DUT_REPLICAS);
}

void
lb_listen_deinit(void)
{
	if (lb_listen_flag == 0)
		return;
	lb_listen_flag = 0;
	printf("shuttindown socket %s \n", SOCKET_NAME);
	shutdown(sock_conn, SHUT_RD);
	close(sock_conn);
	// TODO(skarama): Cleanup all the clones
	if (ring != NULL)
		hash_ring_destroy(ring);
}

static void *
lb_listen(void *arg)
{
	char *buffer = NULL;
	char *tokbuf = NULL;
	char *token_save = NULL;
	uint32_t size = 512;
	struct sockaddr_un server;
	int ret;
	int len, partial;

	UNUSED(arg);
	buffer = malloc(size + 1);
	if (buffer == NULL)
		return NULL;

	tokbuf = malloc(size + 1);
	if (buffer == NULL)
	{
		free(buffer);
		return NULL;
	}

	memset(buffer, 0, size + 1);
	sock_conn = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock_conn < 0)
		return NULL;
	server.sun_family = AF_UNIX;
	strcpy(server.sun_path, SOCKET_NAME);

	ret = bind(sock_conn, (struct sockaddr *) &server, sizeof(struct sockaddr_un));
	if (ret < 0 )
		return NULL;

	ret = listen(sock_conn, 32);
	if (ret < 0 )
		return NULL;

	while (1)
	{
		sock_data = accept(sock_conn, NULL, NULL);
		if (sock_data == -1 && lb_listen_flag == 0)
		{
			printf("exiting gracefully...\n");
			break;
		}
		else if (sock_data == -1)
		{
			printf("exiting with socket accept error...\n");
			exit(EXIT_FAILURE);
		}

		ret = 0;
		while (1)
		{
			partial = 0;
			len = 0;
			memset(buffer, 0, size + 1);
			ret = read(sock_data, buffer, size);
			if (ret == -1)
			{
				printf("socket read error\n");
				break;
			}
			else if (ret == 0)
			{
				printf("end of data\n");
				break;
			}

			/* Parse Data */
			len = strlen(buffer);
			if (buffer[len - 1] != ';')
				partial = 1;

			printf("socket data received - len(%d) buffer(%s)\n", len, buffer);
			char *token = strtok_r(buffer, ";", &token_save);
			while (token != NULL)
			{
				strcpy(tokbuf, token);
				process_data(tokbuf);
				hash_ring_dump(ring);
				token = strtok_r(NULL, ";", &token_save);
			}

			if (partial == 1)
				printf("Pending Partial data implementation\n");

		}
		if (ret == -1)
		{
			printf("existing on failure to read socket data\n");
			break;
		}
		close(sock_data);
		hash_ring_updated(ring);

	}
	free(buffer);
	free(tokbuf);
	close(sock_conn);
	unlink(SOCKET_NAME);
	remove(SOCKET_NAME);
	return NULL;
}

static void
parse_mac(char *mac_str, uint8_t *mac)
{
	int offset = 0;
	char *token = NULL;
	char *token_save = NULL;

	token = strtok_r(mac_str, ":", &token_save);
	while (token != NULL)
	{
		mac[offset++] = strtol(token, NULL, 16);
		token = strtok_r(NULL, ":", &token_save);
	}
}

static void
process_data(char *data)
{
	char *token = NULL;
	char *token_save = NULL;
	char *mac1_str = NULL;
	char *mac2_str = NULL;
	char *name = NULL;
	int operation = 0;
	struct hash_ring_node_t *node;

	/* In the current data version, we are expecting only 1 comma (2 values) */
	token = strtok_r(data, ",", &token_save);
	if (token == NULL)
		return;
	operation = atoi(token);

	token = strtok_r(NULL, ",", &token_save);
	if (token != NULL)
	{
		mac1_str = malloc(strlen(token + 1));
		if (mac1_str != NULL)
			strcpy(mac1_str, token);
	}
	token = strtok_r(NULL, ",", &token_save);
	if (token != NULL)
	{
		mac2_str = malloc(strlen(token + 1));
		if (mac2_str != NULL)
			strcpy(mac2_str, token);
	}


	token = strtok_r(NULL, ",", &token_save);
	if (token != NULL)
	{
		name = malloc(strlen(token + 1));
		if (name != NULL)
			strcpy(name, token);
	}

	node = malloc(sizeof(struct hash_ring_node_t));
	if (node != NULL && mac1_str != NULL && mac2_str != NULL)
	{
		node->name = (uint8_t*)name;
		if (name != NULL)
			node->name_length = strlen(name);
		switch (operation)
		{
			case DUT_MAC_ADDED:
				parse_mac(mac1_str, node->mac);
				hash_ring_add_node(ring, node);
				parse_mac(mac2_str, node->mac);
				hash_ring_add_node(ring, node);
				break;

			case DUT_MAC_REMOVED:
				parse_mac(mac1_str, node->mac);
				hash_ring_remove_node(ring, node);
				parse_mac(mac2_str, node->mac);
				hash_ring_remove_node(ring, node);
				break;

			default:
			{
				printf("Operation(%d) is not handled\n", operation);
				break;
			}
		}
	}
	else
	{
		if (node == NULL)
			printf("ERROR: failed to allocate node memory\n");
		if (mac1_str == NULL)
			printf("ERROR: mac1 is not found\n");
		if (mac2_str == NULL)
			printf("ERROR: mac2 is not found\n");
	}

	if (node != NULL)
		free(node);
	if (name != NULL)
		free(name);
	if (mac1_str != NULL)
		free(mac1_str);
	if (mac2_str != NULL)
		free(mac2_str);
}

#endif /* _LB_LISTEN_H */
