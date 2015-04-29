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
#define BUFFER_SIZE 2056
#define NAME_SIZE 256
#define VICTIM_GATEWAY_PORT 50001
#define VICTIM_GATEWAY_IP_ADDRESS "10.10.128.150"

struct in_addr my_addr;
void send_filter_request(struct flow *flow){
  struct sockaddr_in victim_gw_addr;
  int sock_fd;
  
  // create a socket
  sock_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (sock_fd < 0)   {
    printf("socket setup error");
    return;
  }
  
  // set up the sockaddr_in structure.  
  victim_gw_addr.sin_family = AF_INET;
  victim_gw_addr.sin_port = htons(VICTIM_GATEWAY_PORT);             
  victim_gw_addr.sin_addr.s_addr = flow->route_record[flow->number-1].addr.s_addr;
  //inet_aton(&flow->route_record[flow->number - 1].addr, 
  //	    &victim_gw_addr.sin_addr);  
  
  if (connect(sock_fd, (struct sockaddr *) &victim_gw_addr, sizeof(victim_gw_addr)) < 0)  {
    printf("socket connection fail");
    return;
  }
  

  write(sock_fd, flow, sizeof(struct flow));
  char buffer[1024];
  size_t size =read(sock_fd, buffer, sizeof(buffer));
  buffer[size] = 0;
  printf("%s\n", buffer);

  close(sock_fd);
}

int main ( int argc, char *argv[] )
{
  get_my_addr("eth0", &my_addr);
  print_addr("My ip", my_addr);
  pthread_t pid;
  struct nfq_handle* h = set_up_in_nfq();
  pthread_create(&pid, NULL, (void*) run_nfq, h);

  struct flow flow;
  assign_addr(&flow.dest_addr, &my_addr);
  inet_aton("10.4.18.1", &(flow.src_addr)); 
  flow.number = 2;

  inet_aton("10.10.128.150", &(flow.route_record[0].addr)); 
  inet_aton("10.4.18.3", &(flow.route_record[1].addr));

  send_filter_request(&flow);
  while(1){
    sleep(10);
  }
  //send_filter_request();
  return 0;
}
