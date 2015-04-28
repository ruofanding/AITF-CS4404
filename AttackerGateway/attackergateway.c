/* Attacker host's gateway router */

#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <fcntl.h>

#include "flow.h"

#define TCP_PORT 50000   // The port on which to send data
#define UDP_PORT 50002   // The arbitrary port to send UDP datagrams
#define NONCE_SIZE 64
#define R_SIZE 64

struct arg_struct_cV {
	struct in_addr victim_addr;
	int nonce1;
};

/* Prototypes */
void sendUDPDatagram(struct in_addr, void *, int);
void *listenGatewayRequest(void *);
void *contactVictim(void *);
void notifyAttacker(struct in_addr);
void handle_victim_gw_request(int, struct in_addr, int);

/* Send UDP Datagrams to specified target */
void sendUDPDatagram(struct in_addr raw_h_addr, void *msg, int msg_size) {
	char *host_addr = inet_ntoa((struct in_addr)raw_h_addr);
	int sock, length;
	struct sockaddr_in host;
	
	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		perror("Socket\n");
		exit(1);
	}
	
	host.sin_family = AF_INET;
	host.sin_port = htons(UDP_PORT);
	inet_pton(AF_INET, host_addr, &host.sin_addr);
	
	length = sizeof(struct sockaddr_in);
	if ((sendto(sock, msg, msg_size, 0, (struct sockaddr *)&host, length)) < 0) {
		perror("Sendto\n");
	}
}

/* Listens and Connects to Victim Gateway */
void *listenGatewayRequest(void *arg) {
	pthread_detach(pthread_self());
	pthread_t p2;
	int sockfd = *((int *)arg);
	free(arg);
	int nonce1 = 0xFFFF;
	struct flow flow;
	bzero(&flow, 60);
	
	int size;
	/* Read from socket */
	size = read(sockfd, &flow, sizeof(flow));
	printf("Size read: %d\n", size);
	printf("Received filter request:\n");
	printf("src:  %s\n", inet_ntoa((struct in_addr)flow.src_addr));
	printf("dest: %s\n", inet_ntoa((struct in_addr)flow.dest_addr));
	
	/* Spawn child thread to spam UDP at victim */
	struct arg_struct_cV *arg_t = malloc(sizeof(struct arg_struct_cV));
	
	arg_t->victim_addr = flow.dest_addr;
	arg_t->nonce1 = nonce1;
	
	printf("Sending UDP Packets to Victim: %s\n", inet_ntoa((struct in_addr)flow.dest_addr));
	pthread_create(&p2, NULL, contactVictim, arg_t);
	handle_victim_gw_request(sockfd, flow.src_addr, nonce1);
	pthread_exit(NULL);
}

/* Send TCP Message to Victim GW with nonce2 */
void handle_victim_gw_request(int sockfd, struct in_addr attacker_addr, int nonce1) {
	int i = 0, strcmp_flg = 0;
	int nonce_recv[2];
	
	int size = read(sockfd, nonce_recv, sizeof(nonce_recv));

	printf("Received nonce1 value: %d\n", nonce_recv[0]);
	printf("Received nonce2 value: %d\n", nonce_recv[1]);
	printf("Actual nonce1 value  : %d\n", nonce1);
	
	if (nonce_recv[0] == nonce1) {
		strcmp_flg = 1;
	}
	
	/* Check nonce1 value (2nd line of content) */
	if (strcmp_flg) {
		/* Check R value for Attacker GW (check RR shim) */
		if (1/*received_RR == actual_RR*/) {
			
			/* Tell Attacker to stop sending traffic to flow */
			printf("Notifying Attacker\n");
			notifyAttacker(attacker_addr);
			
			/* Store filter in TCAM (filter table)*/
			printf("Storing filter in TCAM\n");
			//add_filter_temp(flow);
			
			/* Send packet with nonce2 */
			printf("Sending nonce2 to Victim Gateway\n");
			// Insert shim
			if (1/* TODO: Check R value */) {
				//msg[4] = 0xFF;
			}
			else {
				//msg[4] = 0x00;
			}
			
			write(sockfd, &nonce_recv[1], sizeof(int));
		}
		/* Incorrect RR */
		else {
			/* Send packet with correct RR and nonce2 */
			printf("Incorrect RR - Sending nonce2 to Victim Gateway\n");
			// Insert shim
			if (1/* TODO: Check R value */) {
				//msg[4] = 0xFF;
			}
			else {
				//msg[4] = 0x00;
			}
			
			write(sockfd, &nonce_recv[1], sizeof(int));
		}
	}
	
	close(sockfd);
}

/* Send UDP Packets to Victim */
void *contactVictim(void *arg) {
	pthread_detach(pthread_self());
	int i = 0;
	struct arg_struct_cV *args = arg;
	struct in_addr victim_addr = args->victim_addr;
	int nonce1 = args->nonce1;
	
	for (i = 0; i < 10; ++i) {
		sendUDPDatagram(victim_addr, &nonce1, sizeof(int)); // check if input is right
		usleep(1000);
	}
	pthread_exit(NULL);
}

/* Tell Attacker to stop
 * Disconnects Attacker if it doesn't stop
 */
void notifyAttacker(struct in_addr raw_h_addr) {
	int i = 0;
	char *stop_msg = "AITFSTOP";
	
	printf("Sending UDP Packets to Attacker: %s\n", inet_ntoa((struct in_addr)raw_h_addr));
	for (i = 0; i < 10; ++i) {
		sendUDPDatagram(raw_h_addr, stop_msg, strlen(stop_msg));
		usleep(1000);
	}
}

int main(int argc, char **argv) {
	//printf("%d\n", sizeof(struct arg_struct_cV));
	int i = 0;
	int sock, connected, true = 1;
	int sin_size = sizeof(struct sockaddr_in);
	struct sockaddr_in server_addr, client_addr;
	
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		perror("Error: Create Socket\n");
		exit(1);
	}
	
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &true, sizeof(int)) == -1) {
		perror("Error: Setsockopt\n");
		exit(1);
	}
	
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(TCP_PORT);
	server_addr.sin_addr.s_addr = INADDR_ANY;
	bzero(&(server_addr.sin_zero), 8);
	
	/* Bind Socket */
	if (bind(sock, (struct sockaddr *)&server_addr, sizeof(struct sockaddr)) == -1) {
		perror("Error: Unable to bind\n");
		exit(1);
	}
	
	/* Listen to Socket */
	if (listen(sock, 10) == -1) {
		perror("Error: Listen\n");
		exit(1);
	}
	
	printf("Listening on Port 50000\n");
	fflush(stdout);
	
	while (1) {
		pthread_t p1;
		/* Create thread */
		int *arg = malloc(sizeof(int));
		
		/* Accept Connection */
		connected = accept(sock, (struct sockaddr*) &client_addr, &sin_size);
		*arg = connected;
		
		if (connected < 0) {
			printf("Error: Accept\n");
		}
		else {
			printf("---------Connected to a Victim Gateway-------------\n");
			printf("gateway address: %s\n", inet_ntoa((struct in_addr)client_addr.sin_addr));
			
			pthread_create(&p1, NULL, listenGatewayRequest, arg);
			
			fflush(stdout);
		}
	}
	
	return 0;
}
