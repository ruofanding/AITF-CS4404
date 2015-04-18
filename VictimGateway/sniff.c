#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
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
#include "sniff.h"
#include <sys/signal.h>

#define DEVICE "eth2"
#define PACKET_SIZE 65536


SniffRule sniff_rule_array[SNIFF_RULE_SIZE];
int sniff_rule_used[SNIFF_RULE_SIZE];

int sniff_rule_number;
pthread_mutex_t sniff_lock;

int compareAddr(struct in_addr* a1, struct in_addr* a2){
  return memcmp(a1, a2, sizeof(struct in_addr));
}

int set_up_raw_socket(char* device){
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
  return raw_sock;
}

void read_packet(int raw_sock, void (*process_func)(void*, size_t)){
  unsigned char pkt[PACKET_SIZE];
  struct sockaddr_in receiver;
  socklen_t len = sizeof(receiver);

  size_t size;

  printf("=====sniff starts======\n");
  while(1){
    size = recvfrom(raw_sock, pkt, PACKET_SIZE, 0, (struct sockaddr*)&receiver, &len);
    //Ethernet II has 14 bytes MAC header!
    (*process_func)((void*)(pkt + 14), size); 
  }
}

void print_packet(void* pkt, size_t size){
  struct in_addr dest_addr;
  struct in_addr src_addr;
  struct iphdr ip_header;
  
  struct iphdr *iph = (struct iphdr*)pkt; 
  dest_addr.s_addr = iph->daddr;
  src_addr.s_addr = iph->saddr;
  /*
  printf("Size: %zu\n", size);
  printf("From:%s\n", inet_ntoa(src_addr));
  printf("To  :%s\n\n", inet_ntoa(dest_addr));  
  */
  int i;

  printf("\t\t\t%d\n", sniff_rule_number);
  for(i = 0; i < sniff_rule_number; i++){
    if(!compareAddr(&src_addr, &sniff_rule_array[i].src_addr)
       && !compareAddr(&dest_addr, &sniff_rule_array[i].dest_addr)){
      printf("One match, %li\n", (unsigned long int) sniff_rule_array[i].requester);
      pthread_kill(sniff_rule_array[i].requester, SIGALRM);
    }
  }
}


void* start_sniff(void* device){
  int sock_fd = set_up_raw_socket((char*)device);
  read_packet(sock_fd, print_packet);
}

pthread_t set_up_sniff_thread(){
  pthread_t sniff_id;      

  pthread_mutex_init(&sniff_lock, NULL);
  pthread_create(&sniff_id, NULL, start_sniff, "eth2");
  return sniff_id;
}

int get_sniff_rule_spot(){
  int i;
  int result = -1;
  pthread_mutex_lock(&sniff_lock);
  for(i = 0; i < SNIFF_RULE_SIZE;i++){
    if(!sniff_rule_used[i]){
      sniff_rule_used[i] = 1;
      sniff_rule_number++;
      result = -1;
      break;
    }
  }
  pthread_mutex_unlock(&sniff_lock);
  return result;
}

void free_sniff_rule_spot(int index){
  pthread_mutex_lock(&sniff_lock);
  sniff_rule_number --;
  sniff_rule_used[index] = 0;
  pthread_mutex_unlock(&sniff_lock);
}
