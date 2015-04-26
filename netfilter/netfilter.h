#include "flow.h"


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
 * Get an index for intercept_rule_array where a intercept_rule can be put.
 * This is thread safe because it is using mutex.
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
 */
void add_filter_temp(struct flow* flow);

/** 
 * Filter out the flow for Tlong.
 * @param flow a pointer to a flow which should be filter out
 */
void add_filter_long(struct flow* flow);


/**
 * Set up the net filter queue. The setup includes open, bind, set_mode for nfq_queue, as well as setting up for intercept and filter.
 */
void set_up_nfq();
