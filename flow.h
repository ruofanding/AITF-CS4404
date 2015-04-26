#ifndef FLOW_H
#define FLOW_H

#include<netinet/in.h>

struct record{
  struct in_addr addr;
  int hash_value;
};

struct flow{
  int number;
  struct in_addr dest_addr;
  struct in_addr src_addr;
  struct record route_record[6];
};

#endif
