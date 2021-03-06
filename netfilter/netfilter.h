#include "flow.h"
#include <libnetfilter_queue/libnetfilter_queue.h>


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
extern struct in_addr my_addr;
extern int private_key;

inline void print_addr(char *msg, struct in_addr a);

inline void assign_addr(struct in_addr* a, struct in_addr* b);

inline int equal_addr(struct in_addr* a1, struct in_addr* a2);

inline void print_flow(struct flow* flow);

void get_my_addr(char* device, struct in_addr* addr);

inline int encrypt(struct in_addr addr, int key);




#define NODE_CHILDREN_MAX 20

struct node{
  struct record record;
  int children_size;
  struct node* children[NODE_CHILDREN_MAX];
  int counter;
};

typedef struct node Node;
/** Call this function will enable statistic on the runner ends.
 *
 *@param interval_ms, interval for each refresh in milli seconds.
 *@param limit, the limit for the maximum flow in t milli seconds.
 *@param log_enable, indicate whether the function will enable log or not.
 *@param cb, a callback function which takes a struct flow* as paramter
 */
void enable_statistic(int interval_ms, int limit, int log_enable, 
		      void (*cb)(struct flow*));

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
#define SHADOW_TABLE_SIZE 1000

#define T_TEMP 2
#define T_LONG 600
/** 
 * Filter out the flow.
 * @param flow a pointer to a flow which should be filter out
 * @return result 0 for failing to add the filter rule
 */
int add_filter(struct flow* flow);


/**
 *Register legacy host
 */
void add_legacy_host(struct in_addr addr);


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
