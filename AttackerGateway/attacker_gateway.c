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
#include "netfilter.h"

#define TCP_PORT 50000   // The port on which to send data
#define UDP_PORT 50002   // The arbitrary port to send UDP datagrams
#define NONCE_SIZE 64
#define R_SIZE 64

int private_key;
struct in_addr my_addr;
struct arg_struct_cV {
  struct in_addr victim_addr;
  int nonce1;
};

/* Prototypes */
void sendUDPDatagram(struct in_addr, void *, int, int, int);
void *acceptGatewayRequest(void *);
void *contactVictim(void *);
void notifyAttacker(struct in_addr);
void handle_victim_gw_request(int, struct flow*, int);

/* Send UDP Datagrams to specified target for a certain number of packets*/
void sendUDPDatagram(struct in_addr raw_h_addr, void *msg, int msg_size
		     ,int packet_num, int interval) {
  char *host_addr = inet_ntoa((struct in_addr)raw_h_addr);
  int sock, length;
  int i;
  struct sockaddr_in host;
  
  if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
    perror("Socket\n");
    exit(1);
  }
  
  host.sin_family = AF_INET;
  host.sin_port = htons(UDP_PORT);
  inet_pton(AF_INET, host_addr, &host.sin_addr);
  
  length = sizeof(struct sockaddr_in);
  for(i = 0; i < packet_num; i++){
    sendto(sock, msg, msg_size, 0, (struct sockaddr *)&host, length);
    usleep(interval);
  }
}

/* Accepts and Connects to Victim Gateway */
void *acceptGatewayRequest(void *arg) {
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
  printf("Received filter request:\n");
  print_flow(&flow);
  
  /* Spawn child thread to spam UDP at victim */
  struct arg_struct_cV *arg_t = malloc(sizeof(struct arg_struct_cV));
  
  arg_t->victim_addr = flow.dest_addr;
  arg_t->nonce1 = nonce1;
  
  //sending udp packet.
  pthread_create(&p2, NULL, contactVictim, arg_t);
  handle_victim_gw_request(sockfd, &flow, nonce1);
  pthread_exit(NULL);
}

/* Send TCP Message to Victim GW with nonce2 */
void handle_victim_gw_request(int sockfd, struct flow* flow, int nonce1) {
  int i, RR_spoofing;
  int nonce_recv[2];
  
  int size = read(sockfd, nonce_recv, sizeof(nonce_recv));
  
  //printf("Received nonce1 value: %d\n", nonce_recv[0]);
  //printf("Received nonce2 value: %d\n", nonce_recv[1]);
  //printf("Actual nonce1 value  : %d\n", nonce1);
  
  int respond[2];
  respond[0] = nonce_recv[1];
  
  
  /* Check nonce1 value is correct */
  if (nonce_recv[0] == nonce1){
    /* Check R value for Attacker GW (check RR shim) */
    for(i = 0; i < flow->number; i++){
      if(equal_addr(&flow->route_record[i].addr, &my_addr)){
	if(decrypt(flow->route_record[i].hash_value, private_key) 
	   == flow->route_record[i].hash_value){
	  RR_spoofing = 0;
	}else{
	  RR_spoofing = 1;
	}
	break;
      }
    }  
    
    if(RR_spoofing == 0){
      add_filter_temp(flow);

      /* Tell Attacker to stop sending traffic to flow */
      //notifyAttacker(flow->src_addr);
    }

    respond[1] = RR_spoofing;
    write(sockfd, &respond, sizeof(respond));
  }
  /* Incorrect RR */
  else {
    /* Send packet with correct RR and nonce2 */
    printf("Incorrect RR - Sending nonce2 to Victim Gateway\n");
    
    respond[1] = 2;
    write(sockfd, respond, sizeof(respond));
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

  //Send udp 10 udp packet every 1000 usec
  sendUDPDatagram(victim_addr, &nonce1, sizeof(int), 10, 1000);

  pthread_exit(NULL);
}

/* Tell Attacker to stop
 * Disconnects Attacker if it doesn't stop
 */
void notifyAttacker(struct in_addr raw_h_addr) {
  int i = 0;
  char *stop_msg = "AITFSTOP";
  
  printf("Sending UDP Packets to Attacker: %s\n", inet_ntoa((struct in_addr)raw_h_addr));

  sendUDPDatagram(raw_h_addr, stop_msg, strlen(stop_msg), 10, 1000);
}

/**
 * Setup to accept TCP connection
 */
void set_up_listen()
{
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
      
      pthread_create(&p1, NULL, acceptGatewayRequest, arg);
      
      fflush(stdout);
    }
  }
}

int main(int argc, char **argv) {
  pthread_t pid;
  struct nfq_handle* h;
   
  h= set_up_forward_nfq();
  pthread_create(&pid, NULL, (void*) run_nfq, h);

  
  h = set_up_in_nfq();
  pthread_create(&pid, NULL, (void*) run_nfq, h);

  set_up_listen();  
  return 0;
}
