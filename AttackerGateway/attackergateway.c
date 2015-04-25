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

/* Prototypes */
void sendUDPDatagram(struct in_addr, char *);
void listenGatewayRequest(void);
int notifyAttacker(struct in_addr);
void handle_victim_gw_request(int, struct in_addr, char *);

/* Send UDP Datagrams to specified target */
void sendUDPDatagram(struct in_addr raw_h_addr, char *msg) {
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
	if ((sendto(sock, msg, strlen(msg), 0, (struct sockaddr *)&host, length)) < 0) {
		perror("Sendto\n");
	}
}

/* Listens and Connects to Victim Gateway */
void listenGatewayRequest() {
	int sock, connected, bytes_recieved, true = 1;
	char send_data [1024] , recv_data[1024];
	struct sockaddr_in server_addr, client_addr;
	int sin_size;
	clock_t start, end;
	double elapsedT;
    
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		perror("Socket\n");
		exit(1);
	}
	
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &true, sizeof(int)) == -1) {
		perror("Setsockopt\n");
		exit(1);
	}
	
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(TCP_PORT);
	server_addr.sin_addr.s_addr = INADDR_ANY;
	bzero(&(server_addr.sin_zero), 8);
	
	// Bind Socket
	if (bind(sock, (struct sockaddr *)&server_addr, sizeof(struct sockaddr)) == -1) {
		perror("Unable to bind\n");
		exit(1);
	}
	
	// Listen to Socket
	if (listen(sock, 10) == -1) {
		perror("Listen\n");
		exit(1);
	}
	
	printf("Listening on port 50000\n");
	printf("%d\n", sizeof(struct flow));
	fflush(stdout);
	
	while (1) {
		sin_size = sizeof(struct sockaddr_in);
		
		while (1) {
			
			// Accept Connection
			connected = accept(sock, (struct sockaddr*) &client_addr, &sin_size);
			if (connected < 0) {
				printf("ERROR on accept\n");
			}
			else {
				printf("---------connected to a victim gateway-------------\n");
				//int nonce1_int = rand();
				char *nonce1 = "1234";
				printf("gateway address: %s\n", inet_ntoa((struct in_addr)client_addr.sin_addr));
				
				/* Reads the flow */
				struct flow flow;
				int tmp_read = 0;
				tmp_read = read(connected, &flow, sizeof(flow)); // may have issues here
				printf("Read1: %d\n", tmp_read);
				printf("Received filter request:\n");
				printf("src:  %s\n", inet_ntoa((struct in_addr)flow.src_addr));
				printf("dest: %s\n", inet_ntoa((struct in_addr)flow.dest_addr));
				
				/* Spawn child process to spam UDP at victim */
				pid_t process_id;
				process_id = fork();
				if (process_id == 0) { //child process
					int i = 0;
					
					// Send UDP Datagrams
					printf("Sending UDP Packets to %s\n", inet_ntoa((struct in_addr)flow.dest_addr));
					for (i = 0; i < 10; ++i) {
						sendUDPDatagram(flow.dest_addr, nonce1); // check if input is right
						usleep(1000);
					}
					_Exit(0);
				}
				else { //parent_process
					handle_victim_gw_request(connected, flow.src_addr, nonce1);
				}
			}
		}
	}
}

/* Send TCP Message to Victim GW with nonce2 */
void handle_victim_gw_request(int sockfd, struct in_addr attacker_addr, char *nonce1) {
	int i = 0, strcmp_flg = 1;
	char msg[5];
	char buf[8];
	memset(buf, 0, 8);
	memset(msg, 0, 5);
	
	int size = read(sockfd, buf, sizeof(buf));
	for (i = 0; i < 4; i++) {
		msg[i] = buf[i + 4];
	}
	printf("Received nonce1 value: %s\n", buf);
	printf("Received nonce2 value: %s\n", msg);
	printf("Actual nonce1 value  : %s\n", nonce1);
	
	/* Compare original nonce1 and received nonce1 */
	for (i = 0; i < 4; i++) {
		fflush(stdout);
		if (nonce1[i] != buf[i]) {
			strcmp_flg = 0;
		}
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
				msg[4] = 0xFF;
			}
			else {
				msg[4] = 0x00;
			}
			
			write(sockfd, msg, sizeof(msg));
		}
		/* Incorrect RR */
		else {
			/* Send packet with correct RR and nonce2 */
			printf("Incorrect RR - Sending nonce2 to Victim Gateway\n");
			// Insert shim
			if (1/* TODO: Check R value */) {
				msg[4] = 0xFF;
			}
			else {
				msg[4] = 0x00;
			}
			
			write(sockfd, msg, sizeof(msg));
		}
	}
	
	close(sockfd);
}

/* Tell Attacker to stop
 * Disconnects Attacker if it doesn't stop
 */
int notifyAttacker(struct in_addr raw_h_addr) {
	int i = 0;
	char *stop_msg = "AITFSTOP";
	printf("Sending UDP Packets to %s\n", inet_ntoa((struct in_addr)raw_h_addr));
	for (i = 0; i < 10; ++i) {
		sendUDPDatagram(raw_h_addr, stop_msg);
		usleep(1000);
	}
}

int main() {
	listenGatewayRequest();
	return 0;
}
