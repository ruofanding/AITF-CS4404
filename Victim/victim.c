#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include "flow.h"

#include "netfilter.h"

#define BUFFER_SIZE 512
#define VICTIM_GATEWAY_PORT 50001

void send_filter_request_to_gw(struct flow *flow){
  struct sockaddr_in victim_gw_addr;
  int sock_fd;
  
  print_addr("Send filter request to gateway ", 
	     flow->route_record[flow->number-1].addr);
  fflush(stdout);
  // create a socket
  sock_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (sock_fd < 0)   {
    printf("Socket setup error\n");
    return;
  }
  
  // set up the sockaddr_in structure.  
  victim_gw_addr.sin_family = AF_INET;
  victim_gw_addr.sin_port = htons(VICTIM_GATEWAY_PORT);             
  victim_gw_addr.sin_addr.s_addr = flow->route_record[flow->number-1].addr.s_addr;
  
  if (connect(sock_fd, (struct sockaddr *) &victim_gw_addr, 
	      sizeof(victim_gw_addr)) < 0)  {
    printf("Socket connection fail\n");
    return;
  }
  
  write(sock_fd, flow, sizeof(struct flow));
  char buffer[BUFFER_SIZE];
  size_t size =read(sock_fd, buffer, sizeof(buffer));
  buffer[size] = 0;
  printf("Response from the gateway: %s\n", buffer);
  close(sock_fd);
}


int main ( int argc, char *argv[] )
{
  if(argc == 2){
    int ms = 50;
    int limit = 5;
    enable_statistic(ms, limit, 1, send_filter_request_to_gw);
    
    printf("Statistic enable\n");
    printf("Threshold: %f\n pkg/sec", limit / (ms / 1000.0));
  }  
  get_my_addr("eth0", &my_addr);
  print_addr("My ip", my_addr);

  struct nfq_handle* h = set_up_in_nfq();

  run_nfq(h);
}
