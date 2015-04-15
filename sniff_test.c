#include "sniff.h"
#include <netinet/ip.h>
#include <stdio.h>

#include <arpa/inet.h>


void print_packet(void* pkt, size_t size){
  struct in_addr dest_addr;
  struct in_addr src_addr;
  struct iphdr ip_header;
  
  struct iphdr *iph = (struct iphdr*)pkt; 
  dest_addr.s_addr = iph->daddr;
  src_addr.s_addr = iph->saddr;
  
  printf("Size: %zu\n", size);
  printf("From:%s\n", inet_ntoa(src_addr));
  printf("To  :%s\n\n", inet_ntoa(dest_addr));  
}

int main(){
  int raw_socket;
  raw_socket = set_up_raw_socket("eth2");
  read_packet(raw_socket, print_packet);
  return 0;
}
