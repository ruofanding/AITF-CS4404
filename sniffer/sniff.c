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
#include <netinet/udp.h>

#include "sniff.h"
#include "flow.h"
#include <sys/signal.h>

#define PACKET_SIZE 65536

//============================Helper functions========================
inline int equalAddr(struct in_addr* a1, struct in_addr* a2)
{
  return !memcmp(a1, a2, sizeof(struct in_addr));
}

int match_filter_rule(struct flow* rule, struct flow* flow, int ignore_src){
  int i;

  if(!equalAddr(&rule->dest_addr, &flow->dest_addr)){
    return 0;
  }
  if(rule->number > flow->number){
    return 0;
  }
  
  for(i = 0; i < rule->number; i++){
    if(!equalAddr(&(rule->route_record[i].addr), &(flow->route_record[i].addr))){
      return 0;
    }
  }
  
  if(!ignore_src){
    if(!equalAddr(&rule->dest_addr, &flow->dest_addr)){
      return 0;
    }
  }
  return 1;
}


//============================Start of Intercept=======================
#ifdef INTERCEPT
InterceptRule intercept_rule_array[INTERCEPT_RULE_SIZE];
int intercept_rule_used[INTERCEPT_RULE_SIZE];
int intercept_rule_number;
pthread_mutex_t intercept_lock;

void intercept_packet_set_up()
{
  memset(intercept_rule_used, 0, sizeof(intercept_rule_used));
  pthread_mutex_init(&intercept_lock, NULL);
}

void intercept_packet(void* pkt)
{
  struct in_addr dest_addr;
  struct in_addr src_addr;
  struct iphdr ip_header;
  
  struct iphdr *iph = (struct iphdr*)pkt; 
  dest_addr.s_addr = iph->daddr;
  src_addr.s_addr = iph->saddr;

  int i = 0;
  int counter = 0;
  for(counter = 0, i = 0; counter < intercept_rule_number; counter++, i++){
    while(!intercept_rule_used[i]){
      i++;
    }
    printf("%d \n", i);
    printf("packet:%s\n", inet_ntoa(src_addr));
    printf("rule :%s\n\n", inet_ntoa(intercept_rule_array[i].src_addr));

    
    //    if(equalAddr(&src_addr, &intercept_rule_array[i].src_addr)
    //   && equalAddr(&dest_addr, &intercept_rule_array[i].dest_addr)){
    
    if(equalAddr(&src_addr, &intercept_rule_array[i].src_addr)){
      struct udphdr *udph = (struct udphdr *)((void *) iph + sizeof(struct iphdr));
      char* msg = (char*)((void*)udph + sizeof(struct udphdr));
      uint16_t size = ntohs(udph->len);
      int msg_size = size - sizeof(struct udphdr);
      if(msg_size != 4){
	break;
      }
      memcpy(&intercept_rule_array[i].nonce, msg, sizeof(intercept_rule_array[i].nonce));
      printf("One match, %li\n", (unsigned long int) intercept_rule_array[i].requester);
      fflush(stdout);
      pthread_kill(intercept_rule_array[i].requester, SIGALRM);
    }
  }
}


int get_intercept_rule_spot()
{
  int i;
  int result = -1;
  pthread_mutex_lock(&intercept_lock);
  for(i = 0; i < INTERCEPT_RULE_SIZE;i++){
    if(!intercept_rule_used[i]){
      intercept_rule_used[i] = 1;
      intercept_rule_number++;
      result = i;
      break;
    }
  }
  pthread_mutex_unlock(&intercept_lock);
  return result;
}


void free_intercept_rule_spot(int index)
{
  pthread_mutex_lock(&intercept_lock);
  intercept_rule_number --;
  intercept_rule_used[index] = 0;
  pthread_mutex_unlock(&intercept_lock);
}
#endif
//============================End of Intercept=======================


//============================Start of Filter=======================
#ifdef FILTER
FilterRule filter_rule_array[FILTER_RULE_SIZE];
int filter_rule_used[FILTER_RULE_SIZE];
int filter_rule_number;
pthread_mutex_t filter_lock;

void filter_packet_set_up()
{
  memset(filter_rule_used, 0, sizeof(filter_rule_used));
  pthread_mutex_init(&filter_lock, NULL);
}

int filter_packet(void* pkt)
{
  struct in_addr dest_addr;
  struct in_addr src_addr;
  struct iphdr ip_header;
  
  struct iphdr *iph = (struct iphdr*)pkt; 
  dest_addr.s_addr = iph->daddr;
  src_addr.s_addr = iph->saddr;

  int i = 0;
  int counter = 0;
  for(counter = 0, i = 0; counter < filter_rule_number; counter++, i++){
    while(!filter_rule_used[i]){
      i++;
    }    
    if(match_filter_rule(&filter_rule_array[i].flow, NULL)){
      //Filter out.
    }
  }
}


int get_filter_rule_spot()
{
  int i;
  int result = -1;
  pthread_mutex_lock(&filter_lock);
  for(i = 0; i < FILTER_RULE_SIZE;i++){
    if(!filter_rule_used[i]){
      filter_rule_used[i] = 1;
      filter_rule_number++;
      result = i;
      break;
    }
  }
  pthread_mutex_unlock(&filter_lock);
  return result;
}


void free_filter_rule_spot(int index)
{
  pthread_mutex_lock(&filter_lock);
  filter_rule_number --;
  filter_rule_used[index] = 0;
  pthread_mutex_unlock(&filter_lock);
}
#endif
//============================End of Filter=======================


int set_up_raw_socket(char* device)
{
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
  /*
  struct packet_mreq mreq;
  mreq.mr_ifindex = ifr.ifr_ifindex;
  mreq.mr_type = PACKET_MR_PROMISC;
  mreq.mr_alen = 6;
  setsockopt(raw_sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, (void*)&mreq, (socklen_t)sizeof(mreq));
  */
  return raw_sock;
}

void read_packet(int raw_sock, void (*process_func)(void*, size_t))
{
  unsigned char pkt[PACKET_SIZE];
  struct sockaddr_ll receiver;
  socklen_t len;

  size_t size;

  printf("=====sniff starts======\n");
  while(1){
    len = sizeof(receiver);
    size = recvfrom(raw_sock, pkt, PACKET_SIZE, 0, (struct sockaddr*)&receiver, &len);
    //    printf("size of reciever %d\n", len);
    //    printf("%d %d\n\n", receiver.sll_pkttype, receiver.sll_family);
    //    if(receiver.sll_pkttype == PACKET_HOST){
      (*process_func)((void*)(pkt + 14), size); 
      //}else if(receiver.sll_pkttype == PACKET_OUTGOING){
    
      //}
    //Ethernet II has 14 bytes MAC header!
  }
}

void print_packet(void* pkt, size_t size)
{
  struct in_addr dest_addr;
  struct in_addr src_addr;
  struct iphdr ip_header;
  
  struct iphdr *iph = (struct iphdr*)pkt; 
  dest_addr.s_addr = iph->daddr;
  src_addr.s_addr = iph->saddr;

  printf("New packet\n");
  printf("Size: %zu\n", size);
  printf("From:%s\n", inet_ntoa(src_addr));
  printf("To  :%s\n\n", inet_ntoa(dest_addr)); 
  fflush(stdout);
}

void process_pkt(void* pkt, size_t size)
{
  //intercept_packet(pkt);
  print_packet(pkt, size);
}

void* start_sniff(void* device)
{
  int sock_fd = set_up_raw_socket((char*)device);
  read_packet(sock_fd, process_pkt);
}


pthread_t set_up_sniff_thread(char* device)
{
  intercept_packet_set_up();

  pthread_t sniff_id;      
  pthread_create(&sniff_id, NULL, start_sniff, device);
  return sniff_id;
}

