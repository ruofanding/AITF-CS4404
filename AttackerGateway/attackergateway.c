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

#define V_GW "0.0.0.0"
#define PORT 50000   // The port on which to send data
#define T_V 1        // Period UDP datagrams will be sent

/* Prototypes */
void sendUDPDatagram(void);
void listenGatewayRequest(void);
void notifyAttacker(void);
void handle_victim_gw_request(int, struct in_addr);

/* Send a UDP Datagram */
void sendUDPDatagram() {
	const char *hostname = 0; /* localhost */
	const char *portname = "daytime";
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	hints.ai_flags = AI_ADDRCONFIG;
	struct addrinfo *res = 0;
	int err = getaddrinfo(hostname, portname, &hints, &res);
	char content[64];
	
	if (err != 0) {
		//die("failed to resolve remote socket address (err=%d)", err);
	}
	
	int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (fd == -1) {
		//die("%s", strerror(errno));
	}
	
	// nonce1 = hash(V_GW);
	// content = "undesired_flow" + "1000100010001000" // nonce1
	if (sendto(fd, content, sizeof(content), 0, res->ai_addr, res->ai_addrlen) == -1) {
		//die("UDP_e: %s", strerror(errno));
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
	server_addr.sin_port = htons(PORT);
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
					// Read & Write
					handle_victim_gw_request(connected, client_addr.sin_addr);
					_Exit(0);
				}
				else { //parent_process
					
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
	
	write(sockfd, msg, sizeof(msg));
	close(sockfd);
}

int main() {
	listenGatewayRequest();
	return 0;
}
