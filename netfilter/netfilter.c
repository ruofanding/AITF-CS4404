#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include <stdlib.h>
//#include <sys/signal.h> //SIG
#include <signal.h>
#include <stdio.h>
#include <string.h> //memcpy memset

#include "netfilter.h"
#define NFQUEUE_NUM 0


InterceptRule intercept_rule_array[INTERCEPT_RULE_SIZE];
int intercept_rule_used[INTERCEPT_RULE_SIZE];
int intercept_rule_number;
pthread_mutex_t intercept_lock;

inline int equalAddr(struct in_addr* a1, struct in_addr* a2)
{
  return !memcmp(a1, a2, sizeof(struct in_addr));
}

void intercept_packet_set_up()
{
  memset(intercept_rule_used, 0, sizeof(intercept_rule_used));
  pthread_mutex_init(&intercept_lock, NULL);
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

void intercept(struct in_addr src_addr, struct in_addr dest_addr){
  int i = 0;
  int counter = 0;
  for(counter = 0, i = 0; counter < intercept_rule_number; counter++, i++){
    while(!intercept_rule_used[i]){
      i++;
    }

    
    if(equalAddr(&src_addr, &intercept_rule_array[i].src_addr)
       && equalAddr(&dest_addr, &intercept_rule_array[i].dest_addr)){
      /*
      struct udphdr *udph = (struct udphdr *)((void *) iph + sizeof(struct iphdr));
      char* msg = (char*)((void*)udph + sizeof(struct udphdr));
      uint16_t size = ntohs(udph->len);
      int msg_size = size - sizeof(struct udphdr);

      memcpy(&intercept_rule_array[i].nonce, msg, sizeof(intercept_rule_array[i].nonce));
      printf("One match, %li\n", (unsigned long int) intercept_rule_array[i].requester);*/
      intercept_rule_array[i].nonce = 1234;
      fflush(stdout);

      pthread_kill(intercept_rule_array[i].requester, SIGALRM);
    }
  }
}

int cb (struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	struct nfq_data *nfa, void *data)
{
  int verdict;
  int id;
  int ret;
  unsigned char *buffer;
  struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr (nfa);
  if (ph){
    id = ntohl (ph->packet_id);
    printf ("received packet with id %d", id);
  }
  
  ret = nfq_get_payload (nfa, &buffer);
  struct iphdr * ip_info = (struct iphdr *)buffer;
  struct in_addr dest_addr;
  struct in_addr src_addr;
  dest_addr.s_addr = ip_info->daddr;
  src_addr.s_addr = ip_info->saddr;

  printf("From %s", inet_ntoa(src_addr));
  printf("to %s\n", inet_ntoa(dest_addr));
  intercept(src_addr, dest_addr);
  /*
    if (ret)
    {
    switch (ph->hook)
    {
    case PREROUTING:
    printf ( "inbound packet");
    //my_mangling_fun();
    break;
    case OUTPUT:
	  printf ( "outbound packet");
	  //my_mangling_fun();
	  break;
	}
	}*/
  verdict = nfq_set_verdict (qh, id, NF_ACCEPT, ret, buffer);
  if (verdict)
    printf ( "verdict ok");
  return verdict;
}

void set_up_nfq()
{
  struct nfq_handle * h = nfq_open();
  if (!h) {
    fprintf(stderr, "error during nfq_open()\n");
    exit(1);
  }
  
  printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
  if (nfq_unbind_pf(h, AF_INET) < 0) {
    fprintf(stderr, "error during nfq_unbind_pf()\n");
    exit(1);
  }
  
  printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
  if (nfq_bind_pf(h, AF_INET) < 0) {
    fprintf(stderr, "error during nfq_bind_pf()\n");
    exit(1);
  }


  printf("binding this socket to queue '0'\n");
  struct nfq_q_handle * qh = nfq_create_queue(h,  NFQUEUE_NUM, cb, NULL);
  if (!qh) {
    fprintf(stderr, "error during nfq_create_queue()\n");
    exit(1);
  }

  printf("setting copy_packet mode\n");
  if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
    fprintf(stderr, "can't set packet_copy mode\n");
    exit(1);
  }

  int fd = nfq_fd(h);
  int rv;
  char buf[0xffff];
  while ((rv = recv(fd, (void*)buf, sizeof(buf), 0)) >= 0) {
    printf("pkt received\n");
    nfq_handle_packet(h, buf, rv);
  }
}

