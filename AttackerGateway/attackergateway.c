/* Attacker host's gateway router */

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
void sendUDPDatagram(void);
void listenGatewayRequest(void);
void notifyAttacker(void);
void handle_victim_gw_request(int, struct in_addr);

/* Send UDP Datagrams */
void sendUDPDatagram(char *victim_addr) {
	    struct sockaddr_in si_me, si_other;
    21    int s, i, slen=sizeof(si_other);
    22    char buf[BUFLEN];
    23
    24    if ((s=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP))==-1)
    25      diep("socket");
    26
    27    memset((char *) &si_me, 0, sizeof(si_me));
    28    si_me.sin_family = AF_INET;
    29    si_me.sin_port = htons(PORT);
    30    si_me.sin_addr.s_addr = htonl(INADDR_ANY);
    31    if (bind(s, &si_me, sizeof(si_me))==-1)
    32        diep("bind");
    33
    34    for (i=0; i<NPACK; i++) {
    35      if (recvfrom(s, buf, BUFLEN, 0, &si_other, &slen)==-1)
    36        diep("recvfrom()");
		printf("Received packet from %s:%d\nData: %s\n\n", 
		inet_ntoa(si_other.sin_addr), ntohs(si_other.sin_port), buf);
	}
	close(s);
	return 0;
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

				printf("%s\n", inet_ntoa((struct in_addr)client_addr.sin_addr));
				
				pid_t process_id;
				process_id = fork();
				if (process_id == 0) { //child process
					// Send UDP Datagrams
					sendUDPDatagram();
					_Exit(0);
				}
				else { //parent_process
					handle_victim_gw_request(connected, client_addr.sin_addr);
				}
			}
		}
	}
}

/* Send TCP Message to Victim GW with nonce2 */
void handle_victim_gw_request(int sockfd, struct in_addr victim_gw_addr) {
	struct flow flow;
	read(sockfd, &flow, sizeof(flow));
	char *msg;
	 
	/* Check nonce1 value (2nd line of content) */
	if (received_nonce1 == actual_nonce1) {
		/* Check R value for Attacker GW (check RR shim) */
		if (received_RR == actual_RR) {
			//msg = nonce2
			write(sockfd, msg, sizeof(msg));
			
			/* Tell Attacker to stop sending traffic to flow */
			notifyAttacker();
			
			/* Store filter in TCAM (filter table)*/
			
			
			/* Send packet with nonce2 */
			
		}
		/* Incorrect RR */
		else {
			/* Send packet with correct RR and nonce2 */
			
		}
	}
	
	close(sockfd);
}

int main() {
	listenGatewayRequest();
	return 0;
}
