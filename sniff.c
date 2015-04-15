#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include <netpacket/packet.h>
#include <net/ethernet.h> 

#include <netinet/ip.h>

#define DEVICE "eth2"
#define PACKET_SIZE 65536

main ( int argc, char *argv[] )
{
  char* device = "eth2";
  int raw_sock;

  // create a socket
  raw_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (raw_sock < 0)   {
    printf("Raw socket setup error. Need sudo");
    exit(-1);
  }

  struct sockaddr_ll sll;
  struct ifreq ifr;
  bzero(&sll, sizeof(struct sockaddr_ll));
  bzero(&ifr, sizeof(struct ifreq));
  /* First Get the Interface Index */
  strncpy((char *)ifr.ifr_name, device, IFNAMSIZ);
  if((ioctl(raw_sock, SIOCGIFINDEX, &ifr)) == -1)
    {
      printf("Error getting Interface %s index !\n", device); 
      exit(-1);
    } 
  
  
  /* Bind our raw socket to this interface */
  sll.sll_family = AF_PACKET;
  sll.sll_ifindex = ifr.ifr_ifindex;
  sll.sll_protocol = htons(ETH_P_ALL);
  if((bind(raw_sock, (struct sockaddr *)&sll, sizeof(sll)))== -1){
    perror("Error binding raw socket to interface\n");
    exit(-1);
  }
  
  unsigned char pkt[PACKET_SIZE];
  struct in_addr dest_addr;
  struct in_addr src_addr;
  struct sockaddr_in receiver;
  struct iphdr ip_header;
  
  socklen_t len = sizeof(receiver);
  int i = 0;
  size_t size;
  while(1){
    size = recvfrom(raw_sock, pkt, PACKET_SIZE, 0, &receiver, &len);
    //Ethernet II has 14 bytes MAC header!
    struct iphdr *iph = (struct iphdr*) (pkt + 14); 
    dest_addr.s_addr = iph->daddr;
    src_addr.s_addr = iph->saddr;

    printf("Size: %d\n", size);
    printf("From:%s\n", inet_ntoa(src_addr));
    printf("To  :%s\n\n", inet_ntoa(dest_addr));
  }
  return 0;
}
