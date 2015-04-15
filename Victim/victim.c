#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include "flow.h"

#define BUFFER_SIZE 2056
#define NAME_SIZE 256
#define VICTIM_GATEWAY_PORT 50001
#define VICTIM_GATEWAY_IP_ADDRESS "127.0.0.1"

void send_filter_request(){
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
  victim_gw_addr.sin_port = htons(VICTIM_GATEWAY_PORT);               /* client & server see same port*/
  inet_aton(VICTIM_GATEWAY_IP_ADDRESS, &victim_gw_addr.sin_addr);  /* the kernel assigns the IP addr*/
  
  if (connect(sock_fd, (struct sockaddr *) &victim_gw_addr, sizeof(victim_gw_addr)) < 0)  {
    printf("socket connection fail");
    return;
  }
  
  struct flow flow;
  inet_aton("127.0.0.1", &(flow.src_addr)); 
  write(sock_fd, &flow, sizeof(flow));
  char buffer[1024];
  size_t size =read(sock_fd, buffer, sizeof(buffer));
  buffer[size] = 0;
  printf("%s\n", buffer);
  //  write(sock_fd, H_END, strlen(H_END));
  close(sock_fd);
}

int main ( int argc, char *argv[] )
{
  send_filter_request();
  return 0;
}
