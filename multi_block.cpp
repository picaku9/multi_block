#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include "radix.h"
r_node* root = NULL;

void init(){
	system("iptables -F");
	system("iptables -A OUTPUT -j NFQUEUE --queue-num 0");
	system("iptables -A INPUT -j NFQUEUE --queue-num 0");
}

struct ip_addr {
	u_int8_t s_ip[4];
};

struct libnet_ipv4_hdr
{
	u_int8_t ip_hl_v;		//header length and version - modified
	u_int8_t ip_tos;       /* type of service */
	u_int16_t ip_len;         /* total length */
	u_int16_t ip_id;          /* identification */
	u_int16_t ip_off;
	u_int8_t ip_ttl;          /* time to live */
	u_int8_t ip_p;            /* protocol */
	u_int16_t ip_sum;         /* checksum */
	struct ip_addr ip_src, ip_dst; /* source and dest address */
};

struct libnet_tcp_hdr
{
	u_int16_t th_sport;       /* source port */
	u_int16_t th_dport;       /* destination port */
	u_int32_t th_seq;          /* sequence number */
	u_int32_t th_ack;          /* acknowledgement number */
	u_int8_t th_x2_off;        // data offset and (unused) - modified
	u_int8_t  th_flags;       /* control flags */
	u_int16_t th_win;         /* window */
	u_int16_t th_sum;         /* checksum */
	u_int16_t th_urp;         /* urgent pointer */
};

int radix() {
	FILE* fp;
	char buffer[100];
	int num = 0;
	fp = fopen("top-1m.csv","r");

	while(!feof(fp)){
		if (fp == NULL) return 0;
//		printf("%d r_node made\n", num);
		fscanf(fp, "%d,%s\n",&num, buffer);
		root = insert(root, buffer);
	}
	return 0;
}

void dump(unsigned char* buf, int size) {
    int i;
    for (i = 0; i < size; i++) {
        if (i % 16 == 0)
            printf("\n");
        printf("%02x ", buf[i]);
    }
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi; 
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0) {
		printf("payload_len=%d ", ret);

//		dump(data, ret);
	}
	fputc('\n', stdout);

	return id;
}
	

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
//	u_int32_t id = print_pkt(nfa);
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	ph = nfq_get_msg_packet_hdr(nfa);
	if (ph) {
		id = ntohl(ph->packet_id);
	}

	int ret;
	unsigned char *packet;
	ret = nfq_get_payload(nfa, &packet);
	char *get_str = "GET";
	char *host_str = "Host";
	int num;
	int i,j,k;
	if (ret >= 0) {
		struct libnet_ipv4_hdr* ip4 = (struct libnet_ipv4_hdr *)(packet);
		uint8_t ip_hd_len = (ip4->ip_hl_v & 0xf) * 4;
//		printf("Is there TCP? \n");
		if(ip4->ip_p == 6) {
			struct libnet_tcp_hdr* tcp = (struct libnet_tcp_hdr *)(packet + ip_hd_len);
//			printf("Yes there is. ");
			uint16_t tcp_hd_len = ((tcp->th_x2_off & 0xf0)>>4) * 4;
			uint16_t tcp_len = ntohs(ip4->ip_len) - ip_hd_len;
			uint16_t tcp_payload_len = tcp_len - tcp_hd_len ;
			uint8_t *tcp_payload = (uint8_t *)packet + ip_hd_len + tcp_hd_len;

			if(tcp_payload_len == 0) {
//				printf("There is no tcp_data\n");
			}
			else {
//				printf("There is tcp_data : \n");
//				memcpy(tmp, tcp_payload, len(tcp_payload));

				if(memcmp(tcp_payload, get_str, strlen(get_str)) == 0) {
					printf("Starts with GET\n");
					for(i = 0; i < tcp_payload_len; i++) {
						if(tcp_payload[i] == 13 && tcp_payload[i+1] == 10) {
							if(memcmp(tcp_payload+i+2, host_str, strlen(host_str)) == 0) {
								printf("\nStarts with HOST\n");
								int host_len = 0;
								char* target = (char *)(tcp_payload+i+8);
								while(*target!='\r')
								{
									target = target+1;
									host_len++;
								}
								memcpy(target, tcp_payload+i+8, host_len);
								target[host_len] = '\0';

								printf("%s\n", target);
								if (find(root, target)) {
									printf("There is a target \n");
									return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
								}
								else {
									printf("There is no target \n");
								}
							}
						}
					}
				}
			}
		}
	}
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));
	init();
	radix();
//	cmp = argv[1];

	printf("opening library handle\n");
	h = nfq_open();
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
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
//			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. Please, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
