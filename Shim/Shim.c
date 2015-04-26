#include <netinet/in.h> 
#include <linux/netfilter.h> 
#include <libipq.h> 
#include <stdio.h> 
#include <stdlib.h>
#define BUFSIZE 2048

static void die(struct ipq_handle *h) {
	ipq_perror("passer");
	ipq_destroy_handle(h);
	exit(1);
}

/* void * to allow for flexibility, this is the new function */
void *add_shim(void *src_addr, int *size) {
	char *temp_buf = NULL;
	
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

/* Unnecessary function; possibly DEPRECATED */
void insert_RR_shim(ipq_packet_msg_t msg, struct in_addr r_addr) {
	char temp_buf[1518];
	uint32_t *src_addr;
	uint32_t hop_ctr = 0;
	uint32_t rr_val = 0xFFFFFFFFFFFFFFFF;
	
	/* Obtain pointer to source buffer of packet */
	sscanf(msg->hw_addr, "%p", (uint32_t **)&src_addr); // TODO: Make sure this works
	
	/* Check options to see if packet already has an RR Shim */
	if (((*(src_addr + 14)) & 0xF0) >> 4 != 5) {
		/* Packet already has a Shim
		 * Insert router IP addr and random R value */
		hop_ctr = *(src_addr + 34);
		memcpy(src_addr + 38 + hop_ctr*8, r_addr, 4);
		memcpy(src_addr + 42 + hop_ctr*8, rr_val, 4);
		hop_ctr++;
		memcpy(src_addr + 34, &hop_ctr, 4);
	}
	else {
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
		memcpy(temp_buf + 86, src_addr + 34, msg->data_len - 34);
		msg->data_len += 52;
	}
	
	/* Copy modified packet to source buffer */
	memcpy(src_addr, temp_buf, msg->data_len);
}

/* DEPRECATED function */
int modify_packet(struct in_addr router_addr) {
	int status, i = 0;
	unsigned char buf[BUFSIZE];
	struct ipq_handle *h;
	h = ipq_create_handle(0, NFPROTO_IPV4);
	
	if (!h)     die(h);
	
	status = ipq_set_mode(h, IPQ_COPY_PACKET, BUFSIZE);
	
	if (status < 0) die(h);
	
	do {
		i++;
		status = ipq_read(h, buf, BUFSIZE, 0);
		
		if (status < 0) die(h);
		
		switch (ipq_message_type(buf)) {
			case NLMSG_ERROR:
				fprintf(stderr, "Received error message %d\n",
					ipq_get_msgerr(buf));
				break;
			case IPQM_PACKET:
			{
				ipq_packet_msg_t *m = ipq_get_packet(buf);
				printf("\nReceived Packet");
				
				/* Insert RR Shim */
				insert_RR_shim(m, router_addr);
				
				status = ipq_set_verdict(h, m->packet_id, NF_ACCEPT, 0, NULL);
				if (status < 0)  die(h);
				break;
			}
			default:
				fprintf(stderr, "Unknown message type!\n");
				break;
		}
	} while (1);
	ipq_destroy_handle(h);
	return 0;
}