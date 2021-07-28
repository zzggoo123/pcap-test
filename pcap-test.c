#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#define 	ETHER_ADDR_LEN   6
#define 	ETHERTYPE_IP	0x0800
#define 	LIBNET_LIL_ENDIAN	1
#define 	LIBNET_BIG_ENDIAN	0
#pragma comment(lib, "ws2_32.lib") 
/* Ethernet II header
 *  Static header size: 14 bytes*/
struct libnet_ethernet_hdr
{
	u_int8_t  ether_dhost[6];/* destination ethernet address */
	u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
	u_int16_t ether_type;                 /* protocol */
};

/*
 *  IPv4 header
 *  Internet Protocol, version 4
 *  Static header size: 20 bytes
 */
struct libnet_ipv4_hdr
{
#if (LIBNET_LIL_ENDIAN)
	u_int8_t ip_hl : 4,      /* header length */
		ip_v : 4;         /* version */
#endif
#if (LIBNET_BIG_ENDIAN)
	u_int8_t ip_v : 4,       /* version */
		ip_hl : 4;        /* header length */
#endif
	u_int8_t ip_tos;       /* type of service */
#ifndef IPTOS_LOWDELAY
#define IPTOS_LOWDELAY      0x10
#endif
#ifndef IPTOS_THROUGHPUT
#define IPTOS_THROUGHPUT    0x08
#endif
#ifndef IPTOS_RELIABILITY
#define IPTOS_RELIABILITY   0x04
#endif
#ifndef IPTOS_LOWCOST
#define IPTOS_LOWCOST       0x02
#endif
	u_int16_t ip_len;         /* total length */
	u_int16_t ip_id;          /* identification */
	u_int16_t ip_off;
#ifndef IP_RF
#define IP_RF 0x8000        /* reserved fragment flag */
#endif
#ifndef IP_DF
#define IP_DF 0x4000        /* dont fragment flag */
#endif
#ifndef IP_MF
#define IP_MF 0x2000        /* more fragments flag */
#endif 
#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
#endif
	u_int8_t ip_ttl;          /* time to live */
	u_int8_t ip_p;            /* protocol */
	u_int16_t ip_sum;         /* checksum */
	struct in_addr ip_src, ip_dst; /* source and dest address */
};

/*
 *  TCP header
 *  Transmission Control Protocol
 *  Static header size: 20 bytes
 */
struct libnet_tcp_hdr
{
	u_int16_t th_sport;       /* source port */
	u_int16_t th_dport;       /* destination port */
	u_int32_t th_seq;          /* sequence number */
	u_int32_t th_ack;          /* acknowledgement number */
#if (LIBNET_LIL_ENDIAN)
	u_int8_t th_x2 : 4,         /* (unused) */
		th_off : 4;        /* data offset */
#endif
#if (LIBNET_BIG_ENDIAN)
	u_int8_t th_off : 4,        /* data offset */
		th_x2 : 4;         /* (unused) */
#endif
	u_int8_t  th_flags;       /* control flags */
#ifndef TH_FIN
#define TH_FIN    0x01      /* finished send data */
#endif
#ifndef TH_SYN
#define TH_SYN    0x02      /* synchronize sequence numbers */
#endif
#ifndef TH_RST
#define TH_RST    0x04      /* reset the connection */
#endif
#ifndef TH_PUSH
#define TH_PUSH   0x08      /* push data to the app layer */
#endif
#ifndef TH_ACK
#define TH_ACK    0x10      /* acknowledge */
#endif
#ifndef TH_URG
#define TH_URG    0x20      /* urgent! */
#endif
#ifndef TH_ECE
#define TH_ECE    0x40
#endif
#ifndef TH_CWR   
#define TH_CWR    0x80
#endif
	u_int16_t th_win;         /* window */
	u_int16_t th_sum;         /* checksum */
	u_int16_t th_urp;         /* urgent pointer */
};

struct Data {
	char data[9];
};
void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

void print_eth(struct libnet_ethernet_hdr* eth) {
	printf("<Ethernet Header>\nsrc mac: ");

	for (int i = 0; i < ETHER_ADDR_LEN - 1; i++) {
		printf("%02x:", eth->ether_dhost[i]);
	}
	printf("%02x:\n", eth->ether_dhost[5]);
	printf("dst mac: ");
	for (int i = 0; i < ETHER_ADDR_LEN - 1; i++) {
		printf("%02x:", eth->ether_shost[i]);
	}
	printf("%02x:\n", eth->ether_shost[5]);
	return;
}

void print_ip(struct libnet_ipv4_hdr* ipv4) {
	uint32_t sip = ntohl(ipv4->ip_src.s_addr);
	uint8_t a, b, c, d;
	a = (sip & 0xFF000000) >> 24;
	b = (sip & 0x00FF0000) >> 16;
	c = (sip & 0x0000FF00) >> 8;
	d = (sip & 0x000000FF) >> 0;
	printf("<IP Header>\nsrc ip: %u.%u.%u.%u\n", a, b, c, d);
	uint32_t dip = ntohl(ipv4->ip_dst.s_addr);
	a = (dip & 0xFF000000) >> 24;
	b = (dip & 0x00FF0000) >> 16;
	c = (dip & 0x0000FF00) >> 8;
	d = (dip & 0x000000FF) >> 0;
	printf("dst ip: %u.%u.%u.%u\n", a, b, c, d);
	return;
}

void print_tcp(struct libnet_tcp_hdr* tcp) {
	printf("<TCP Header>\nsrc port: %d\n", ntohs(tcp->th_sport));
	printf("dst port: %d\n", ntohs(tcp->th_dport));
	return;
}

void print_data(struct Data* payload, uint8_t length) {
	printf("<Payload>\nData: ");
	for (int i = 0; i < 8; i++)
		printf("%02x", (payload->data[i] & 0xff));
	return;
}

int main(int argc, char* argv[]) {

	struct libnet_ethernet_hdr* eth;
	struct libnet_ipv4_hdr* ipv4;
	struct libnet_tcp_hdr* tcp;

	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	printf("ok1\n");
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	printf("ok2\n");
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}
	printf("ok3\n");
	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		struct Data* payload = (struct Data*)(packet + sizeof(*eth) + sizeof(*ipv4) + sizeof(*tcp));
		eth = (struct libnet_ethernet_hdr*) packet;
		ipv4 = (struct libnet_ipv4_hdr*) (packet + sizeof(struct libnet_ethernet_hdr));
		tcp = (struct libnet_tcp_hdr*) (packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ethernet_hdr));

		if ((ntohs(eth->ether_type) == 0x0800) && (ipv4->ip_p == IPPROTO_TCP)) {

			printf("%u bytes captured\n", header->caplen);
			printf("It is TCP packet\n");
			print_eth(eth);
			print_ip(ipv4);
			print_tcp(tcp);
			uint8_t length = header->caplen - sizeof(*eth) - sizeof(*ipv4) - sizeof(*tcp);
			print_data(payload, length);
			printf("\n------------------------------------\n");
		}
	}
	pcap_close(pcap);
}
