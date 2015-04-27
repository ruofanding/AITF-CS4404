#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include <stdlib.h>
#include <signal.h> //SIGALRM
#include <stdio.h>
#include <string.h> //memcpy memset
#include <time.h>  //time
#include "netfilter.h"

#define NFQUEUE_NUM 0
#define T_TEMP 1000
//============================Helper functions=======================
inline void print_addr(char *msg, struct in_addr a){
  printf("%s %s\n", msg, inet_ntoa(a));
}

inline void assign_addr(struct in_addr* a, struct in_addr* b){
  a->s_addr = b->s_addr;
}

inline int equalAddr(struct in_addr* a1, struct in_addr* a2)
{
  printf("Compare %s ", inet_ntoa(*a1));
  printf("with %s\n", inet_ntoa(*a2));
  return !memcmp(a1, a2, sizeof(struct in_addr));
}

inline void print_flow(struct flow* flow){
  printf("%s->", inet_ntoa(flow->src_addr));
  int i;
  for(i = 0; i < flow->number; i++){
    printf("%s->", inet_ntoa(flow->route_record[i].addr));
  }
  printf("%s\n", inet_ntoa(flow->dest_addr));
}
//============================Helper functions=======================


//============================Start of Intercept=======================
InterceptRule intercept_rule_array[INTERCEPT_RULE_SIZE];
int intercept_rule_used[INTERCEPT_RULE_SIZE];
int intercept_rule_number;
pthread_mutex_t intercept_lock;

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

void intercept(struct in_addr src_addr, struct in_addr dest_addr, struct iphdr* iph){
  int i = 0;
  int counter = 0;
  for(counter = 0, i = 0; counter < intercept_rule_number; counter++, i++){
    while(!intercept_rule_used[i]){
      i++;
    }

    
    if(equalAddr(&src_addr, &intercept_rule_array[i].src_addr)
       && equalAddr(&dest_addr, &intercept_rule_array[i].dest_addr)){

      struct udphdr *udph = (struct udphdr *)((void *) iph + sizeof(struct iphdr));
      char* msg = (char*)((void*)udph + sizeof(struct udphdr));
      uint16_t size = ntohs(udph->len);
      int msg_size = size - sizeof(struct udphdr);

      memcpy(&intercept_rule_array[i].nonce, msg, sizeof(intercept_rule_array[i].nonce));
      printf("Net filter intercepts a udp with nonce = %x\n", intercept_rule_array[i].nonce); 
      fflush(stdout);
      pthread_kill(intercept_rule_array[i].requester, SIGALRM);
    }
  }
}
//============================End of Intercept=======================


//============================Start of Intercept=======================
struct flow filter_rule_array[FILTER_RULE_SIZE];
time_t filter_rule_expire[FILTER_RULE_SIZE];
int filter_rule_used[FILTER_RULE_SIZE];
int filter_rule_number = 0;
pthread_mutex_t filter_lock;

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

void clean_filter_rule()
{
  time_t current;
  int i, counter;
  while(1){
    current = time(NULL);
    for(i = 0, counter = 0; i < FILTER_RULE_SIZE; i++){
      if(counter >= filter_rule_number){
	break;
      }

      if(filter_rule_used[i]){
	counter ++;
	//Remove the filter rule if it is expired
	if( current >= filter_rule_expire[i] ){
	  printf("Filter rule %d expire\n", i);
	  print_flow(&filter_rule_array[i]);
	  fflush(stdout);
	  free_filter_rule_spot(i);
	}
      }
    }
    sleep(1);
  }
}

int add_filter_temp(struct flow* flow_pt)
{
  int filter_index = get_filter_rule_spot();
  if(filter_index == -1){
    printf("Fail to insert filter rule\n");
    fflush(stdout);
    return 0;
  }

  filter_rule_expire[filter_index] = time(NULL) + T_TEMP;
  memcpy(&filter_rule_array[filter_index], flow_pt, sizeof(struct flow));
  /*
  print_addr("add_filter dest", filter_rule_array[filter_index].dest_addr);
  print_addr("add_filter src", filter_rule_array[filter_index].src_addr);
  */
  printf("Add filter rule %d\n",filter_index);
  return 1;
}

int match_filter_rule(struct flow* rule, struct flow* flow){
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
  
  // src_addr will be compared only if source address is set not 0.0.0.0
  if(flow->src_addr.s_addr ^ 0){ 
    if(!equalAddr(&rule->src_addr, &flow->src_addr)){
      return 0;
    }
  }
  return 1;
}

/**
 *@param flow the flow need to be checked by all filter rules
 *@return result 0: pass, 1:drop
 */
int filter_out(struct flow* flow_pt)
{
  int i, counter ;
  int d;

  for(i = 0, counter = 0; i < filter_rule_number; i++){
    if(filter_rule_used[i]){
      counter ++;
      if(match_filter_rule(&filter_rule_array[i], flow_pt)){
	return 1;
      }
    }
    if(counter == filter_rule_number){
      break;
    }
  }
  return 0;
}

//============================End of FILTER=======================

void *add_shim(struct iphdr* ip, int *size);

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
    //printf ("received packet with id %d\n", id);
  }
  
  ret = nfq_get_payload (nfa, &buffer);
  struct iphdr * ip_info = (struct iphdr *)buffer;
  struct in_addr dest_addr;
  struct in_addr src_addr;
  dest_addr.s_addr = ip_info->daddr;
  src_addr.s_addr = ip_info->saddr;

  printf("From %s", inet_ntoa(src_addr));
  printf("to %s\n", inet_ntoa(dest_addr));
  intercept(src_addr, dest_addr, ip_info);

  struct flow flow;
  flow.src_addr.s_addr = src_addr.s_addr;
  flow.dest_addr.s_addr = dest_addr.s_addr;
  flow.number = 0;
  
  
  int size = ret;
  buffer = add_shim(ip_info, &size);

  printf("new size: %d\n", size);
  if(filter_out(&flow)){
    printf("packet dropped\n");
    verdict = nfq_set_verdict (qh, id, NF_DROP, 0, NULL);
  }else{
    printf("packet passed\n");
    verdict = nfq_set_verdict (qh, id, NF_ACCEPT, size, buffer);
  }
  
  if(size != ret){
    free(buffer);
  }

  printf("\n");
  fflush(stdout);
  return verdict;
}

#define AITF_PROTOCOL_NUM 253
typedef struct{
  int origin_protocol;
  int number;
  struct record route_record[6];
}Shim;

void *add_shim(struct iphdr* ip, int *size) {
  struct in_addr my_addr;
  my_addr.s_addr = 0xffffffff;
  int iphdr_size = ip->ihl * 4;
  int shim_size = sizeof(Shim);
  unsigned short total_size = ntohs(ip->tot_len);

  printf("%d %hu %d\n", iphdr_size, total_size, *size);
  Shim* shim;
  if(ip->protocol != AITF_PROTOCOL_NUM){
    ip->protocol == AITF_PROTOCOL_NUM;
    struct iphdr* new_ip = malloc(ip->tot_len + shim_size);
    shim = (void*)new_ip + iphdr_size;
    //Set the size to total_size + shim_size.
    *size = *size + shim_size;
    
    //Copy the ip header. 
    memcpy(new_ip, ip, iphdr_size);
    new_ip->tot_len = htons(*size);
    
    //Set the protocol number, and store the origin protocol number.
    shim->origin_protocol = ip->protocol;
    new_ip->protocol = AITF_PROTOCOL_NUM;   

    //Init the number of route records.
    shim->number = 0;

    //Copy data after IP header
    memcpy((void*)new_ip + iphdr_size + shim_size, (void*) ip + iphdr_size, 
	   total_size - iphdr_size);
    

    //Add route record
    assign_addr(&shim->route_record[shim->number].addr, &my_addr);
    shim->number++;
    return new_ip;

  }else{

    shim = (void*)ip + iphdr_size;
    assign_addr(&shim->route_record[shim->number].addr, &my_addr);
    shim->number++;
    return ip;

  }
}

#ifdef NO
  /* Check options to see if packet already has an RR Shim */
  if (((*(src_addr + 14)) & 0xF0) >> 4 != 5) {
    /* Packet already has a Shim
     * Insert router IP addr and random R value */
    hop_ctr = *(src_addr + 34);
    memcpy(src_addr + 38 + hop_ctr*8, r_addr, 4);
    memcpy(src_addr + 42 + hop_ctr*8, rr_val, 4);
    hop_ctr++;
		memcpy(src_addr + 34, &hop_ctr, 4);
		return src_addr;
  }
  else {
    temp_buf = malloc(*size + 52); // (shim + options)
    
    /* Copy MAC Header to temp buffer (14 bytes) */
    memcpy(temp_buf, src_addr, 14);
		
    /* Copy and modify IHL */
    memset(temp_buf + 14, ((src_addr + 14) | 0xF6), 1);
    /* Copy rest of IP header */
    memcpy(temp_buf + 15, src_addr + 15, 19);
    /* Increment counter */
    src_ctr = *(src_addr + 34) + 1;
    memcpy(temp_buf + 34, &hop_ctr, 4);
    
    /* Insert Shim with random R value and router IP addr (shim = 48 bytes) */
    memcpy(temp_buf + 38, r_addr, 4); // Insert IP addr
    memcpy(temp_buf + 42, rr_val, 4); // Insert random R value
    memset(temp_buf + 46, 0, 40); // 0 out rest of shim
    
    /* Copy rest of packet to temp buffer */
    memcpy(temp_buf + 86, src_addr + 34, *size - 34);
    *size += 52;
    return temp_buf;
  }
}
#endif

struct nfq_handle * set_up_nfq()
{
  printf("size:%d\n", sizeof(Shim));
  memset(intercept_rule_used, 0, sizeof(intercept_rule_used));
  pthread_mutex_init(&intercept_lock, NULL);

  memset(filter_rule_used, 0, sizeof(filter_rule_used));
  pthread_mutex_init(&filter_lock, NULL);

  //Run filter clean thread
  pthread_t pid;
  pthread_create(&pid, NULL, clean_filter_rule, NULL);

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
  return h;
}

void run_nfq(struct nfq_handle *h){
  int fd = nfq_fd(h);
  int rv;
  char buf[0xffff];

  while ((rv = recv(fd, (void*)buf, sizeof(buf), 0)) >= 0) {
    printf("pkt received\n");
    nfq_handle_packet(h, buf, rv);
  }
}
