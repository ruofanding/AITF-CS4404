#ifndef SNIFF_H
#define SNIFF_H

#include <stdlib.h>
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

#endif
