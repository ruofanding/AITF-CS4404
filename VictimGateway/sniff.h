#ifndef SNIFF_H
#define SNIFF_H
#include <stdlib.h>
#include <pthread.h>
#include <netinet/ip.h>

#ifdef INTERCEPT

typedef struct{
  pthread_t requester;
  struct in_addr src_addr;
  struct in_addr dest_addr;
  int nonce;
}InterceptRule;

#define INTERCEPT_RULE_SIZE 1000
extern InterceptRule intercept_rule_array[INTERCEPT_RULE_SIZE];
extern int intercept_rule_used[INTERCEPT_RULE_SIZE];
extern int intercept_rule_number;

/**
 *Get an index for intercept_rule_array where a intercept_rule can be put.
 *This is thread safe because it is using mutex.
 */
int get_intercept_rule_spot();

/**
 *Free an index for intercept_rule_array which is requested by get_intercept_rule_spot.
 *This is thread safe because it is using mutex.
 */
void free_intercept_rule_spot(int index);

#endif

#ifdef FILTER
typedef struct{
  struct flow flow;
  int usec;
}FilterRule;

#define FILTER_RULE_SIZE 1000
extern FilterRule filter_rule_array[FILTER_RULE_SIZE];
extern int filter_rule_used[FILTER_RULE_SIZE];
extern int filter_rule_number;

/**
 *Get an index for filter_rule_array where a filter_rule can be put.
 *This is thread safe because it is using mutex.
 */
int get_filter_rule_spot();

/**
 *Free an index for filter_rule_array which is requested by get_filter_rule_spot.
 *This is thread safe because it is using mutex.
 */
void free_filter_rule_spot(int index);
#endif

/**
 *Set up the raw socket 
 *@param device the name of device the socket listen to.
 *@return raw_sock the file descripter of the raw socket.
 **/
int set_up_raw_socket(char* device);


/**
 *Read packets on the raw socket, and process the packet.
 *@param raw_sock the file descripter of the raw socket.
 *@param process_func a pointer to a function which is responsible for processing packets.
*/
void read_packet(int raw_sock, void (*process_func)(void*, size_t));


void print_packet(void* pkt, size_t size);


/**
 *Set up a sniff program, and start it.
 *It will start a thread, and then call set_up_raw_socket, and read_packet.
 */
pthread_t set_up_sniff_thread();

#endif
