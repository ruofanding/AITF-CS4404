#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/signal.h>
#include "flow.h"
#include "netfilter.h"

#define BUFFER_SIZE 2056
#define NAME_SIZE 256
#define ATTACKER_GATEWAY_PORT 50000
#define VICTIM_GATEWAY_PORT 50001
#define ATTACKER_GATEWAY_IP_ADDRESS "10.10.128.122"
#define TIME_TO_WAIT 100000
int intercept_udp_packet(struct in_addr src_addr, struct in_addr dest_addr){
  int result;
  int intercept_rule_index;

  intercept_rule_index = get_intercept_rule_spot();

  memcpy(&intercept_rule_array[intercept_rule_index].src_addr, 
	 &src_addr, sizeof(struct in_addr));
  memcpy(&intercept_rule_array[intercept_rule_index].dest_addr, 
	 &dest_addr, sizeof(struct in_addr));

  intercept_rule_array[intercept_rule_index].requester = pthread_self();

  int rc = usleep(TIME_TO_WAIT);
  if(rc != 0){ // Signaled by sniff thread before finish sleep;
    result = intercept_rule_array[intercept_rule_index].nonce;
  }else{       // Not signaled by sniff thread, so no udp packet catched 
    result = 0;
  }

  free_intercept_rule_spot(intercept_rule_index);
  return result;
}

int send_filter_request(struct flow* flow_pt){
  struct sockaddr_in attacker_gw_addr;
  int sock_fd;
  
  // create a socket
  sock_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (sock_fd < 0)   {
    printf("socket setup error");
    return 1;
  }
  
  // set up the sockaddr_in structure.  
  attacker_gw_addr.sin_family = AF_INET;
  attacker_gw_addr.sin_port = htons(ATTACKER_GATEWAY_PORT);
  inet_aton(ATTACKER_GATEWAY_IP_ADDRESS, &attacker_gw_addr.sin_addr);
  
  if (connect(sock_fd, (struct sockaddr *) &attacker_gw_addr, 
	      sizeof(attacker_gw_addr)) < 0)  {
    printf("socket connection fail");
    return 1;
  }
  write(sock_fd, flow_pt, sizeof(struct flow));

  int nonce1 = intercept_udp_packet(attacker_gw_addr.sin_addr, flow_pt->dest_addr);
  if(nonce1 == 0){
    printf("Fail to intercept the udp packet.\n");
  }else{
    printf("Intercept the udp packet with nonce = %x.\n", nonce1);

    int nonce2 = rand();
    char buf[8];
  
    //Concatenate nonce1 with nonce2
    memcpy(buf, &nonce1, sizeof(int));
    memcpy(buf + sizeof(int), &nonce2, sizeof(int));

    write(sock_fd, buf, sizeof(int) * 2);

    memset(buf, 0, sizeof(buf));
    read(sock_fd, buf, sizeof(int) + sizeof(char));
    if(memcmp(buf, &nonce2, sizeof(int))){
      printf("not same\n");
    }else{
      printf("same\n");
    }

  }
  close(sock_fd);
  return 0;
}

typedef struct{
  int sockfd;
  struct in_addr victim_addr;
}HandlerData;

void* handle_victim_request(void* data){
  HandlerData* passed_data = (HandlerData*) data;
  int sockfd = passed_data->sockfd;
  
  struct flow flow;
  read(sockfd, &flow, sizeof(flow));

  char *msg;
  if(memcmp(&flow.dest_addr, &passed_data->victim_addr, 
	    sizeof(struct in_addr)) != 0){
    printf("Victim request's destination IP doesn't match victim's IP address\n");
    msg = "Fake IP!\n";
    write(sockfd, msg, sizeof(msg));
  }else{
    printf("Reqeust from: %s\n", inet_ntoa(flow.src_addr));
    msg = "OK\n";
    write(sockfd, msg, sizeof(msg));
  }
  close(sockfd);
  free(passed_data);
  send_filter_request(&flow);
  fflush(stdout);
}

/**
 *Empty function for sigaction
*/
void signal_handler(int signo){
}

void set_up_sig_handler(){
  struct sigaction actions;
  
  memset(&actions, 0, sizeof(actions));
  sigemptyset(&actions.sa_mask);
  actions.sa_flags = 0;
  actions.sa_handler = signal_handler;
  
  sigaction(SIGALRM,&actions,NULL);
}

void listen_victim(){
  struct sockaddr_in server_addr;
  int serverfd;
    
  // Establish the socket that will be used for listening
  serverfd = socket(AF_INET, SOCK_STREAM, 0);
  if(serverfd < 0){
    printf("Socket setup error.\n");
    fflush(stdout);
    exit(1);
  }

  // Do a bind of that socket
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = INADDR_ANY; 
  server_addr.sin_port = htons((int) VICTIM_GATEWAY_PORT);
  if(bind(serverfd, (struct sockaddr *) &server_addr, 
	  sizeof(server_addr)) != 0 ){
    printf("Bind error.\n");
    fflush(stdout);
    exit(1);
  }else{
    printf("Bind successfully.\n");
  }

  // Set up to listen
  if(listen(serverfd, 10) != 0){
    printf("Listening error.\n");
    exit(1);
  }else{
    printf("Start listening victims' requests.\n");
  }
  fflush(stdout);

  int newsockfd;
  struct sockaddr_in victim_addr;
  socklen_t addr_len;

  while(1){
    // Do the accept
    addr_len = sizeof(victim_addr);
    newsockfd = accept(serverfd, (struct sockaddr*) &victim_addr, &addr_len);
    if (newsockfd < 0){
      printf("ERROR on accept\n");
    }else{
      printf("---------connect to a new victim-------------\n");

      printf("%s\n", inet_ntoa((struct in_addr)victim_addr.sin_addr));

      HandlerData* data = malloc(sizeof(HandlerData));
      data->sockfd = newsockfd;
      memcpy(&data->victim_addr, &victim_addr.sin_addr, sizeof(struct in_addr));
      pthread_t pid;
      pthread_create(&pid, NULL, handle_victim_request, data);  
      printf("One requester, %li\n", (unsigned long int) pid);
      fflush(stdout);
    }
  }  
}

int main ( int argc, char *argv[] )
{
  pthread_t pid;
  pthread_create(&pid, NULL, (void*) set_up_nfq, NULL);
  set_up_sig_handler();
  /*
  sleep(1);
  struct flow flow;
  inet_aton("10.4.18.3", &flow.src_addr);
  inet_aton("10.4.18.4", &flow.dest_addr);
  flow.number = 0;
  add_filter_temp(&flow);
  */
  listen_victim();
  return 0;
}
