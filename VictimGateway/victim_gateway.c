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
#define ATTACKER_GATEWAY_PORT 50000
#define VICTIM_GATEWAY_PORT 50001
#define TIME_TO_WAIT 100000

struct in_addr my_addr;

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

/** Victim gateway will contact with the attacker's gateway to filter out
 *  the undesired flow.
 * @param flow_pt a pointer to struct flow, which should be filtered out.
 * @param upper_gateay the IP address of the upstream gateway that will be
 * contacted.
 * @return result 0 if request succeeds
 *                1 if AITF fails or not corporates
 *               -1 if RR shim is not correct.
 */
int send_filter_request(struct flow* flow_pt, struct in_addr upstream_gateway){
  int sock_fd;
  
  // create a socket
  sock_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (sock_fd < 0)   {
    printf("socket setup error");
    return 1;
  }
  
  // set up the sockaddr_in structure.
  struct sockaddr_in attacker_gw_addr;  
  attacker_gw_addr.sin_family = AF_INET;
  attacker_gw_addr.sin_port = htons(ATTACKER_GATEWAY_PORT);
  //inet_aton(ATTACKER_GATEWAY_IP_ADDRESS, &attacker_gw_addr.sin_addr);
  attacker_gw_addr.sin_addr.s_addr = upstream_gateway.s_addr;

  if (connect(sock_fd, (struct sockaddr *) &attacker_gw_addr, 
	      sizeof(attacker_gw_addr)) < 0)  {
    printf("socket connection fail");
    return 1;
  }
  write(sock_fd, flow_pt, sizeof(struct flow));

  //Intercetp nonce1
  int nonce1 = intercept_udp_packet(attacker_gw_addr.sin_addr, flow_pt->dest_addr);
  if(nonce1 == 0){
    printf("Fail to intercept the udp packet.\n");
    close(sock_fd);
    return 1;
  }
  printf("Intercept the udp packet with nonce = %x.\n", nonce1);
  
  //Send nonce1 with nonce2
  int nonce2 = rand();
  char buf[8];  
  memcpy(buf, &nonce1, sizeof(int));
  memcpy(buf + sizeof(int), &nonce2, sizeof(int));
  write(sock_fd, buf, sizeof(int) * 2);

  //Read nonce2 with success/fail 
  memset(buf, 0, sizeof(buf));
  read(sock_fd, buf, sizeof(int) + sizeof(char));
  close(sock_fd);
  if(memcmp(buf, &nonce2, sizeof(int))){
    return 1;
  }
  
  if((buf[4]^0xff) == 0){ //Success
    return 0;
  }else{
    return -1;
  }
}

typedef struct{
  int sockfd;
  struct in_addr victim_addr;
}HandlerData;

void shift_flow(struct flow *flow){
  if(flow->number == 0){
    return;
  }

  int i;
  for(i=0; i < flow->number - 1; i++){
    memcpy(&flow->route_record[i], &flow->route_record[i+1], sizeof(struct record));
  }
  
  flow->number--;
}

void* handle_victim_request(void* data){
  HandlerData* passed_data = (HandlerData*) data;
  int sockfd = passed_data->sockfd;
  struct in_addr victim_addr;
  victim_addr.s_addr = passed_data->victim_addr.s_addr;
  free(passed_data);
  
  struct flow flow;
  read(sockfd, &flow, sizeof(flow));

  char *msg;
  //Compare the destination IP address with requester's IP address
  if(memcmp(&flow.dest_addr, &victim_addr, sizeof(struct in_addr)) != 0){
    printf("Victim request's destination IP doesn't match victim's IP address\n");
    msg = "Fail";
    write(sockfd, msg, sizeof(msg));
    close(sockfd);
    return;
  }else{
    printf("Reqeust from: %s\n", inet_ntoa(flow.src_addr));
  }

  //Contact with upstream gateways.
  int i;
  int success = 0;
  while(flow.number > 0){
    print_flow(&flow);
    if(equal_addr(&flow.route_record[i].addr, &my_addr)){
      break;
    }

    if(send_filter_request(&flow, flow.route_record[i].addr) == 0){
      success = 1;
      break;

    }else{    
      shift_flow(&flow);

    } 
  }

  if(!success){ //Fail to install filter rule remotely
    add_filter_temp(&flow); //Install filter rule locally
  }

  msg = "OK";
  write(sockfd, msg, sizeof(msg));
  close(sockfd);
  return;
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
  get_my_addr("eth0", &my_addr);

  set_up_sig_handler();

  pthread_t pid;
  struct nfq_handle* h = set_up_forward_nfq();
  pthread_create(&pid, NULL, (void*) run_nfq, h);

  //h = set_up_in_nfq();
  //pthread_create(&pid, NULL, (void*) run_nfq, h);

  struct flow flow;
  inet_aton("10.4.18.2", &flow.src_addr);
  inet_aton("10.4.18.1", &flow.dest_addr);
  flow.number = 0;

  //add_filter_temp(&flow);
  listen_victim();
  return 0;
}
