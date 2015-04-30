#include "flow.h"
#include <libnetfilter_queue/libnetfilter_queue.h>


typedef struct{
  pthread_t requester;
  struct in_addr src_addr;
  struct in_addr dest_addr;
  int nonce;
}InterceptRule;

typedef struct{
  int origin_protocol;
  int number;
  struct record route_record[6];
}Shim;

#define INTERCEPT_RULE_SIZE 1000
extern InterceptRule intercept_rule_array[INTERCEPT_RULE_SIZE];
extern int intercept_rule_used[INTERCEPT_RULE_SIZE];
extern int intercept_rule_number;


inline void print_addr(char *msg, struct in_addr a);

inline void assign_addr(struct in_addr* a, struct in_addr* b);

inline int equal_addr(struct in_addr* a1, struct in_addr* a2);

inline void print_flow(struct flow* flow);

void get_my_addr(char* device, struct in_addr* addr);


/**
 * Get an index for intercept_rule_array where a intercept_rule can be put.
 * This is thread safe because it is using mutex.
 * @return the index for the intercept rule array.
 */
int get_intercept_rule_spot();

/**
 * Free an index for intercept_rule_array which is requested by get_intercept_rule_spot.
 * This is thread safe because it is using mutex.
 */
void free_intercept_rule_spot(int index);



#define FILTER_RULE_SIZE 1000

/** 
 * Filter out the flow for Ttmp.
 * @param flow a pointer to a flow which should be filter out
 * @return result 0 for failing to add the filter rule
 */
int add_filter_temp(struct flow* flow);

/** 
 * Filter out the flow for Tlong.
 * @param flow a pointer to a flow which should be filter out
 * @return result 0 for failing to add the filter rule
 */
int add_filter_long(struct flow* flow);


/**
 * Set up the netfilter FORWARD queue. The setup includes open, bind, set_mode
 * for nfq_queue, as well as setting up for intercept and filter. It is also
 * responsible for adding shim.
 * @return h nfq_handle
 */
struct nfq_handle* set_up_forward_nfq();

/**
 * Set up the netfilter IN queue. The setup includes open, bind, set_mode for
 * nfq_queue. It is responsible for removing shim.
 * @return h nfq_handle
 */
struct nfq_handle* set_up_in_nfq();


/**
 * Run the net filter program. This function should only be called after set_up_*_nfq.
 * @param h nfq_handel
 */
void run_nfq(struct nfq_handle* h);
