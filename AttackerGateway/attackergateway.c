/* Attacker host's gateway router */

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>
//#include <sys/uio.h>

#define V_GW "0.0.0.0"
#define PORT 50000   // The port on which to send data
#define T_V 1        // Period UDP datagrams will be sent

/* Prototypes */
void sendUDPDatagram(void);
void listenGatewayRequest(void);
void notifyAttacker(void);

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
		die("failed to resolve remote socket address (err=%d)", err);
	}
	
	int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (fd == -1) {
		die("%s", strerror(errno));
	}
	
	// nonce1 = hash(V_GW);
	// content = "undesired_flow" + "1000100010001000" // nonce1
	if (sendto(fd, content, sizeof(content), 0, res->ai_addr, res->ai_addrlen) == -1) {
		die("UDP_e: %s", strerror(errno));
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
		perror("Socket");
		exit(1);
	}
	
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &true, sizeof(int)) == -1) {
		perror("Setsockopt");
		exit(1);
	}
	
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(PORT);
	server_addr.sin_addr.s_addr = INADDR_ANY;
	bzero(&(server_addr.sin_zero), 8);
	
	if (bind(sock, (struct sockaddr *)&server_addr, sizeof(struct sockaddr)) == -1) {
		perror("Unable to bind");
		exit(1);
	}
	
	if (listen(sock, 5) == -1) {
		perror("Listen");
		exit(1);
	}
	
	printf("\nTCPServer Waiting for client on port 50000");
	fflush(stdout);
	
	while (1) {
		sin_size = sizeof(struct sockaddr_in);
		connected = accept(sock, (struct sockaddr *)&client_addr, &sin_size);
		printf("\n I got a connection from (%s , %d)",
			inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
		
		/* Respond to packet from Victim's gateway containing undesired flow
		 * with UDP datagram containing nonce1 for some T seconds
		 */
		start = clock();
		while (1) {
			end = clock();
			elapsedTime = (double)(end - start) / CLOCKS_PER_SEC;
			if (elapsedTime < T_V)
				sendUDPDatagram();
			else
				break;
				
			
		}
		
		
		
		/* Other stuff */
		while (1) {
			printf("\n SEND (q or Q to quit) : ");
			gets(send_data);
			if (strcmp(send_data , "q") == 0 || strcmp(send_data , "Q") == 0) {
				send(connected, send_data,strlen(send_data), 0);
				close(connected);
				break;
			}
			else
				send(connected, send_data, strlen(send_data), 0);
				
			bytes_recieved = recv(connected, recv_data, 1024, 0);
			recv_data[bytes_recieved] = '\0';
			if (strcmp(recv_data , "q") == 0 || strcmp(recv_data , "Q") == 0) {
				close(connected);
				break;
			}
			else
				printf("\n RECIEVED DATA = %s " , recv_data);
			fflush(stdout);
		}
	
		close(sock);
		sleep(1);
	}
}

