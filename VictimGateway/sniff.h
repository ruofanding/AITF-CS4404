#ifndef SNIFF_H
#define SNIFF_H
#include <stdlib.h>
#include <pthread.h>
#include <netinet/ip.h>
#define SNIFF_RULE_SIZE 1000

typedef struct{
  pthread_t requester;
  struct in_addr src_addr;
  struct in_addr dest_addr;
}SniffRule;

extern SniffRule sniff_rule_array[SNIFF_RULE_SIZE];
extern int sniff_rule_used[SNIFF_RULE_SIZE];
extern int sniff_rule_number;


/**
 *Set up the raw socket 
 *@param device the name of device the socket listen to.
 *@return raw_sock the file descripter of the raw socket.
*/
int set_up_raw_socket(char* device);


/**
 *Read packets on the raw socket, and process the packet.
 *@param raw_sock the file descripter of the raw socket.
 *@param process_func a pointer to a function which is responsible for processing packets.
*/
void read_packet(int raw_sock, void (*process_func)(void*, size_t));


void print_packet(void* pkt, size_t size);

/**
 *Get an index for sniff_rule_array where a sniff_rule can be put.
 *This is thread safe because it is using mutex.
 */
int get_sniff_rule_spot();

/**
 *Free an index for sniff_rule_array which is requested by get_sniff_rule_spot.
 *This is thread safe because it is using mutex.
 */
void free_sniff_rule_spot(int index);

/**
 *Set up a sniff program, and start it.
 *It will start a thread, and then call set_up_raw_socket, and read_packet.
 *
pthread_t set_up_sniff_thread();

#endif
