#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include <ifaddrs.h> //getifaddrs

#include <stdlib.h>
#include <signal.h> //SIGALRM
#include <stdio.h>
#include <string.h> //memcpy memset
#include <time.h>  //time
#include "netfilter.h"

#define FORWARD_NFQUEUE_NUM 0
#define IN_NFQUEUE_NUM 1
#define T_TEMP 1000


#define AITF_PROTOCOL_NUM 253
typedef struct{
  int origin_protocol;
  int number;
  struct record route_record[6];
}Shim;

int statistic_enable = 0;

//============================Helper functions=======================
inline void print_addr(char *msg, struct in_addr a){
  printf("%s %s\n", msg, inet_ntoa(a));
}

inline void assign_addr(struct in_addr* a, struct in_addr* b){
  a->s_addr = b->s_addr;
}

inline int equal_addr(struct in_addr* a1, struct in_addr* a2)
{
  //printf("Compare %s ", inet_ntoa(*a1));
  //printf("with %s\n", inet_ntoa(*a2));
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

void get_my_addr(char* device, struct in_addr* addr){
  struct ifaddrs *ifap, *tmp;

  getifaddrs(&ifap);
  tmp = ifap;

  while(tmp){

    if(tmp->ifa_addr->sa_family == AF_INET && strcmp(tmp->ifa_name, device) == 0){
      struct sockaddr_in *pAddr = (struct sockaddr_in *)tmp->ifa_addr;
      addr->s_addr = pAddr->sin_addr.s_addr;
      break;
    }

    tmp = tmp->ifa_next;

  }

  freeifaddrs(ifap);
}

inline int encrypt(int plain, int key){
  return plain ^ key;
}

inline int decrypt(int cipher, int key){
  return 0x12345678;
  return cipher ^ key;
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

void 
intercept(struct in_addr src_addr, struct in_addr dest_addr, struct iphdr* iph){
  int i = 0;
  int counter = 0;
  struct udphdr* udph;

  if(iph->protocol == AITF_PROTOCOL_NUM){
    Shim* shim = (void*) iph + sizeof(struct iphdr);

    //Not udp packet
    if(shim->origin_protocol != 17){
      return ;
    }
    udph = (struct udphdr *)((void*)shim + sizeof(Shim));

  }else if(iph->protocol == 17){

    udph = (struct udphdr *)((void *) iph + sizeof(struct iphdr));

  }

  for(counter = 0, i = 0; counter < intercept_rule_number; counter++, i++){
    while(!intercept_rule_used[i]){
      i++;
    }

    if(equal_addr(&src_addr, &intercept_rule_array[i].src_addr)
       && equal_addr(&dest_addr, &intercept_rule_array[i].dest_addr)){
      
      char* msg = (char*)((void*)udph + sizeof(struct udphdr));
      uint16_t size = ntohs(udph->len);
      int msg_size = size - sizeof(struct udphdr);

      memcpy(&intercept_rule_array[i].nonce, msg, 
	     sizeof(intercept_rule_array[i].nonce));
      //printf("Net filter intercepts a udp with nonce = %x\n", 
      //     intercept_rule_array[i].nonce); 
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
    return 0;
  }

  filter_rule_expire[filter_index] = time(NULL) + T_TEMP;
  memcpy(&filter_rule_array[filter_index], flow_pt, sizeof(struct flow));

  printf("Add filter rule %d\n",filter_index);
  print_flow(flow_pt);
  fflush(stdout);
  return 1;
}

int match_filter_rule(struct flow* rule, struct flow* flow){
  int i;

  if(!equal_addr(&rule->dest_addr, &flow->dest_addr)){
    return 0;
  }

  /*
  if(rule->number > flow->number){
    return 0;
  }
  
  for(i = 0; i < rule->number; i++){
    if(!equal_addr(&(rule->route_record[i].addr), &(flow->route_record[i].addr))){
      return 0;
    }
    }*/
  
  // src_addr will be compared only if source address is set not 0.0.0.0
  if(flow->src_addr.s_addr ^ 0){ 
    if(!equal_addr(&rule->src_addr, &flow->src_addr)){
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

//============================Start of FORWARD NFQ=======================
int private_key;
struct in_addr my_addr;

void *add_shim(struct iphdr* ip, int *size) {
  int iphdr_size = ip->ihl * 4;
  int shim_size = sizeof(Shim);
  unsigned short total_size = ntohs(ip->tot_len);

  if(total_size != *size){
    printf("The size doesn't match in add shim\n");
    return ip;
  }

  Shim* shim;
  if(ip->protocol != AITF_PROTOCOL_NUM){
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
    shim->route_record[shim->number].hash_value = 
      ip->daddr ^ private_key;
    shim->number++;
    
    //Recalculate the checksum
    nfq_ip_set_checksum(new_ip);
    return new_ip;

  }else{

    shim = (void*)ip + iphdr_size;
    assign_addr(&shim->route_record[shim->number].addr, &my_addr);
    shim->route_record[shim->number].hash_value = 
      ip->daddr ^ private_key;
    
    shim->number++;
    return ip;

  }
}

int forward_callback (struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
		      struct nfq_data *nfa, void *data)
{
  int verdict;
  int id;
  int ret;
  unsigned char *buffer;
  struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr (nfa);
  if (ph){
    id = ntohl (ph->packet_id);
  }
  
  ret = nfq_get_payload (nfa, &buffer);
  struct iphdr * ip_info = (struct iphdr *)buffer;
  struct in_addr dest_addr;
  struct in_addr src_addr;
  dest_addr.s_addr = ip_info->daddr;
  src_addr.s_addr = ip_info->saddr;

  intercept(src_addr, dest_addr, ip_info);

  struct flow flow;
  flow.src_addr.s_addr = src_addr.s_addr;
  flow.dest_addr.s_addr = dest_addr.s_addr;
  flow.number = 0;
  
  
  int size = ret;
  buffer = add_shim(ip_info, &size);

  if(filter_out(&flow)){
    printf("packet dropped\n");
    printf("From %s", inet_ntoa(src_addr));
    printf("to %s\n", inet_ntoa(dest_addr));
    verdict = nfq_set_verdict (qh, id, NF_DROP, 0, NULL);
  }else{
    //printf("packet passed\n");
    verdict = nfq_set_verdict (qh, id, NF_ACCEPT, size, buffer);
  }
  
  if(size != ret){
    free(buffer);
  }

  return verdict;
}

struct nfq_handle * set_up_forward_nfq()
{
  printf("===== setting up FORWARD nfq =====\n");

  memset(intercept_rule_used, 0, sizeof(intercept_rule_used));
  pthread_mutex_init(&intercept_lock, NULL);

  memset(filter_rule_used, 0, sizeof(filter_rule_used));
  pthread_mutex_init(&filter_lock, NULL);

  srand(time(NULL));
  private_key = rand();
  get_my_addr("eth0", &my_addr);
  printf("My private key is %x\n", private_key);

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


  printf("binding this socket to queue '%d'\n", FORWARD_NFQUEUE_NUM);
  struct nfq_q_handle * qh = nfq_create_queue(h, FORWARD_NFQUEUE_NUM, 
					      forward_callback, NULL);
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

//============================End of FORWARD NFQ=======================

//============================Start of Policy module=======================
Node* stat_root;

inline equal_record(struct record* r1, struct record* r2){
  if(memcmp(r1, r2, sizeof(struct record)) == 0){
    return 1;
  }else{
    return 0;
  }
}

inline assign_record(struct record* r1, struct record* r2){
  memcpy(r1, r2, sizeof(struct record));
}

void add_flow(Node* current, struct flow *flow, int flow_index){
  int i;
  struct record* next_record;
  struct record temp_record;
  current->counter ++;

  if(flow_index == -1){
    return;
  }

  if(flow_index > 0){
    next_record = &flow->route_record[flow_index - 1];

  }else{
    temp_record.addr.s_addr = flow->src_addr.s_addr;
    next_record = &temp_record;
  }

  int size = (current->children_size < NODE_CHILDREN_MAX)? 
    current->children_size : NODE_CHILDREN_MAX;

  for(i = 0; i < size; i++){
    if(equal_record(&current->children[i]->record, next_record)){
      add_flow(current->children[i], flow, flow_index - 1);
      return;
    }
  }

  if(current->children_size < NODE_CHILDREN_MAX){
    Node* new_child = (Node*) malloc(sizeof(Node));
    assign_record(&new_child->record, next_record);
   
    new_child->counter = 0;
    new_child->children_size = 0;
    
    current->children[current->children_size] = new_child;
    current->children_size++;

    add_flow(new_child, flow, flow_index - 1);

  }else{
    current->children_size++;
  }
}

void print_node(Node* node, int c){
  if(node == NULL){
    return;
  }
  int i,j;
  printf("%d %d ",node->counter, node->children_size); 
  printf("%x ", node->record.hash_value);
  print_addr("", node->record.addr);

  int size = (node->children_size < NODE_CHILDREN_MAX)? 
    node->children_size : NODE_CHILDREN_MAX;

  for(i=0; i < size; i++){
    for(j=0; j < c; j++){
      printf("\t");
    }
    print_node(node->children[i], c + 1);
  }
}

int limit = 10;
struct flow*  undesired_flow(Node* node, int root){
  struct flow* flow;
  int i;
  if(node->counter > limit){
    //source ip address; leaf of the tree.
    if(node->children_size == 0){
      flow = malloc(sizeof(struct flow));
      flow->number = 0;

      flow->src_addr.s_addr = node->record.addr.s_addr;
      return flow;
    }
    //IP spoofing
    if(node->children_size > NODE_CHILDREN_MAX){
      flow = malloc(sizeof(struct flow));
      flow->number = 0;

      assign_record(&flow->route_record[flow->number], &node->record);
      flow->number++;

      memset(&flow->src_addr, 0, sizeof(struct in_addr));
      return flow;

    }else{
      //Fint the children with the largest counter
      Node* max_node = NULL;
      int max = -1;
      for(i = 0; i < node->children_size; i++){
	if(node->children[i]->counter > max){
	  max = node->children[i]->counter;
	  max_node = node->children[i];
	}
      }
      flow = undesired_flow(max_node, 0);
      if(flow != NULL){
	if(!root){
	  assign_record(&flow->route_record[flow->number], &node->record);
	  flow->number++;
	}else{
	  flow->dest_addr.s_addr = my_addr.s_addr;
	}
      }
      return flow;
    }
  }else{
    return NULL;
  }
}

void free_node(Node* node){
  if(node == NULL){
    return;
  }
  int i;

  int size = (node->children_size < NODE_CHILDREN_MAX)? 
    node->children_size : NODE_CHILDREN_MAX;

  for(i = 0; i < size; i++){
    free_node(node->children[i]);
  }
  free(node);
}

int refresh_stat = 1;

void stat_refresh(int usec){
  struct flow* flow;
  while(1){
    if(refresh_stat == 0){
      flow = undesired_flow(stat_root, 1);
      if(flow != NULL){
	print_flow(flow);
      }
      refresh_stat = 1;
    }
    usleep(usec);
  }
}
void enable_statistic(double frequency)
{
  stat_root = NULL;
  pthread_t pid;
  int usec = frequency * 1000000;
  pthread_create(&pid, NULL, stat_refresh, (void*)usec);
  statistic_enable = 1;
}


void update_stat(struct iphdr* ip)
{
  if(statistic_enable && ip->protocol == AITF_PROTOCOL_NUM){
    if(stat_root != NULL && refresh_stat == 1){
      free_node(stat_root);
      stat_root = NULL;
      refresh_stat = 0;
    }
    if(stat_root == NULL){
      refresh_stat = 0;
      stat_root = malloc(sizeof(Node));
      stat_root->children_size = 0;
      stat_root->counter = 0;
      stat_root->record.addr.s_addr = my_addr.s_addr;
    }
   
    int i;
    Shim* shim = (void*)ip + sizeof(struct iphdr);
    struct flow flow;
    for(i = 0; i < shim->number; i++){
      memcpy(&flow.route_record[i], & shim->route_record[i], 
	     sizeof(struct record));
    }
    flow.number = shim->number;
    flow.src_addr.s_addr = ip->saddr;
    add_flow(stat_root, &flow, flow.number);
  }
}
//============================End of Policy module=======================


//============================Start of IN NFQ=======================

int remove_shim(struct iphdr* ip, int size) {
  int iphdr_size = ip->ihl * 4;
  int shim_size = sizeof(Shim);
  unsigned short total_size = ntohs(ip->tot_len);

  if(total_size != size){
    printf("The size doesn't match\n");
    return size;
  }

  Shim* shim;
  if(ip->protocol == AITF_PROTOCOL_NUM){
    
    //Restore the protocol number
    shim = (void*)ip + iphdr_size;    
    ip->protocol = shim->origin_protocol;
    
    //Restore the tot_len to total_size - shim_size.
    ip->tot_len = htons(total_size - shim_size);

    //Remove the shim by moving data after shim forward.
    char buffer[total_size - iphdr_size - shim_size];    
    memcpy(buffer, (void*)ip + iphdr_size + shim_size, sizeof(buffer));
    memcpy((void*)ip + iphdr_size, buffer, sizeof(buffer));

    //Recalculate the checksum
    nfq_ip_set_checksum(ip);


    return total_size - shim_size;

  }else{

    return total_size;

  }
}

int counter = 1;
int in_callback (struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
		 struct nfq_data *nfa, void *data)
{
  int verdict;
  int id;
  int ret;
  unsigned char *buffer;
  struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr (nfa);
  if (ph){
    id = ntohl (ph->packet_id);
  }

  ret = nfq_get_payload (nfa, &buffer);
  struct iphdr * ip_info = (struct iphdr *)buffer;
  struct in_addr dest_addr;
  struct in_addr src_addr;
  dest_addr.s_addr = ip_info->daddr;
  src_addr.s_addr = ip_info->saddr;

  //printf("From %s", inet_ntoa(src_addr));
  //printf("to %s\n", inet_ntoa(dest_addr));
  
  update_stat(ip_info);
  ret = remove_shim(ip_info, ret);

  verdict = nfq_set_verdict (qh, id, NF_ACCEPT, ret, buffer);

  return verdict;
}

struct nfq_handle * set_up_in_nfq()
{
  printf("===== setting up IN nfq =====\n");
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

  printf("binding this socket to queue '%d'\n", IN_NFQUEUE_NUM);
  struct nfq_q_handle * qh = nfq_create_queue(h,  IN_NFQUEUE_NUM, 
					      in_callback, NULL);
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
//============================End of IN NFQ=======================


void run_nfq(struct nfq_handle *h){
  int fd = nfq_fd(h);
  int rv;
  char buf[0xffff];

  while ((rv = recv(fd, (void*)buf, sizeof(buf), 0)) >= 0) {
    nfq_handle_packet(h, buf, rv);
  }
}
