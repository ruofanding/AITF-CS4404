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
  /*
  struct flow flow;
  flow.number = 3;
  assign_addr(&flow.dest_addr, &my_addr);
  inet_aton("10.4.18.1", &(flow.route_record[0].addr)); 
  flow.route_record[0].hash_value = 0;
  inet_aton("10.4.18.2", &(flow.route_record[1].addr)); 
  flow.route_record[1].hash_value = 1;
  inet_aton("10.4.18.3", &(flow.route_record[2].addr)); 
  flow.route_record[2].hash_value = 2;
  inet_aton("10.4.18.4", &(flow.src_addr)); 
  
  Node* root = malloc(sizeof(Node));;
  root->record.addr.s_addr = my_addr.s_addr;
  root->counter = 0;
  root->children_size = 0;
  add_flow(root, &flow, 3);
  flow.route_record[1].hash_value = 0xff;

  add_flow(root, &flow, 3);
  inet_aton("10.4.18.5", &(flow.src_addr)); 

  add_flow(root, &flow, 3);

  inet_aton("10.4.18.6", &(flow.route_record[0].addr)); 
  inet_aton("10.4.18.8", &(flow.src_addr)); 
  add_flow(root, &flow, 3);
  
  int i;
  for(i = 0; i < 25; i++){
    flow.src_addr.s_addr = i;
    add_flow(root, &flow, 3);
  }
  print_node(root, 1);
  struct flow* unflow;
  unflow = undesired_flow(root, 1);
  if(unflow != NULL){
    unflow->dest_addr.s_addr = my_addr.s_addr;
    print_flow(unflow);
  }
  free_node(root);
  return 0;*/
  
  get_my_addr("eth0", &my_addr);
  print_addr("My ip", my_addr);
  pthread_t pid;
  struct nfq_handle* h = set_up_in_nfq();
  enable_statistic(1);
  //pthread_create(&pid, NULL, (void*) run_nfq, h);
  run_nfq(h);
  /*
  //  struct flow flow;
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
  return 0;*/
}
