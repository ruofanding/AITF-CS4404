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
#include "sniff.h"

#define BUFFER_SIZE 2056
#define NAME_SIZE 256
#define ATTACKER_GATEWAY_PORT 50000
#define VICTIM_GATEWAY_PORT 50001
#define ATTACKER_GATEWAY_IP_ADDRESS "192.168.1.1"

void send_filter_request(){
  struct sockaddr_in attacker_gw_addr;
  int sock_fd;
  
  // create a socket
  sock_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (sock_fd < 0)   {
    printf("socket setup error");
    return;
  }
  
  // set up the sockaddr_in structure.  
  attacker_gw_addr.sin_family = AF_INET;
  attacker_gw_addr.sin_port = htons(ATTACKER_GATEWAY_PORT);
  inet_aton(ATTACKER_GATEWAY_IP_ADDRESS, &attacker_gw_addr.sin_addr);
  
  if (connect(sock_fd, (struct sockaddr *) &attacker_gw_addr, sizeof(attacker_gw_addr)) < 0)  {
    printf("socket connection fail");
    return;
  }
  //  write(sock_fd, H_END, strlen(H_END));
  close(sock_fd);
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

  if(memcmp(&flow.src_addr, &passed_data->victim_addr, sizeof(struct in_addr)) != 0){
    printf("Victim request's destination IP doesn't match victim's IP address\n");
    msg = "Fake IP!\n";
  }else{
    printf("Reqeust from: %s\n", inet_ntoa(flow.src_addr));
    msg = "OK\n";
  }
  write(sockfd, msg, sizeof(msg));
  close(sockfd);
  free(passed_data);
  
  int sniff_rule_index = getEmptySpot();
  /*
  if(sniff_rule_index == -1){
    perror("No sniff space left\n");
    exit(1);
    }*/
  memcpy(&sniff_rule_array[sniff_rule_index].src_addr, &flow.src_addr, sizeof(struct in_addr));
  sniff_rule_array[sniff_rule_index].requester = pthread_self();
  int rc = sleep(50);
  printf("Thread ends at %d\n", rc);
  fflush(stdout);
}

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
  if(bind(serverfd, (struct sockaddr *) &server_addr, sizeof(server_addr)) != 0 ){
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
  set_up_sniff_thread();
  set_up_sig_handler();
  listen_victim();
  return 0;
}
