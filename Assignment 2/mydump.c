#include <asm/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <sys/types.h>

#define SIZE_ETHERNET 14


struct my_ip {
	u_int8_t	ip_vhl;		/* header length, version */
#define IP_V(ip)	(((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)	((ip)->ip_vhl & 0x0f)
	u_int8_t	ip_tos;		/* type of service */
	u_int16_t	ip_len;		/* total length */
	u_int16_t	ip_id;		/* identification */
	u_int16_t	ip_off;		/* fragment offset field */
#define	IP_DF 0x4000		/* dont fragment flag */
#define	IP_MF 0x2000		/* more fragments flag */
#define	IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_int8_t	ip_ttl;		/* time to live */
	u_int8_t	ip_p;		/* protocol */
	u_int16_t	ip_sum;		/* checksum */
	struct	in_addr ip_src,ip_dst;	/* source and dest address */
};


struct my_tcp {
	u_short source;		/* source port */
	u_short dest;		/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */
	u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
};

/*
* Custom strstr function for comparing regex.
*/
int my_strstr(const u_char* payload, int len, char* payload_filter){
    const u_char *ch;
    ch = payload;
    char *filter;
    filter = payload_filter;
    int i = 0;
    while (i < len) {
		if (isprint(*ch)){
			while(*ch == *filter) {
				filter++;
				ch++;
				i++;
				if(i > len) {
					break;
				}

				if((*filter) == 0) {
					return 0;
                }
            }
            filter = payload_filter;
		}
		ch++;
		i++;
	}
	return -1;
 }

/*
* Print Ethernet Header Details
*/
void print_ether_details(const struct pcap_pkthdr* pkthdr, const struct ether_header* ethernetHeader, const u_char* packet) {

	struct timeval tv;
	time_t nowtime;
	struct tm *nowtm;
	char tmbuf[64], buf[64];
	const u_char *ptr;
	int i;	

	tv = pkthdr->ts;

	gettimeofday(&tv, NULL);
	nowtime = pkthdr->ts.tv_sec;
	nowtm = localtime(&nowtime);
	strftime(tmbuf, sizeof tmbuf, "%Y-%m-%d %H:%M:%S", nowtm);
	snprintf(buf, sizeof buf, "%s.%06ld", tmbuf, pkthdr->ts.tv_usec);

	printf("%s ", buf);

	ptr = ethernetHeader->ether_shost;
	i = ETHER_ADDR_LEN;
	do{
		printf("%s%02X",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
	} while(--i>0);

	printf(" -> ");

	ptr = ethernetHeader->ether_dhost;
	i = ETHER_ADDR_LEN;
	do{
		printf("%s%02X",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
    } while(--i>0);

	printf(" type 0x%03x ", ntohs(ethernetHeader->ether_type));
	printf("len %d\n", pkthdr->len);
}

/*
* Print Payload Details
*/
void print_hex_ascii_line(const u_char *payload, int len, int offset) {

	int i, gap;
	const u_char *ch;

	printf("%05d   ", offset);
	
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;

		if (i == 7) {
			printf(" ");
		}
	}

	if (len < 8) {
		printf(" ");
	}	

	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

	return;
}


void print_data(const u_char *payload, int len) {

	int len_rem = len;
	int line_width = 16;			
	int line_len;
	int offset = 0;					
	const u_char *ch = payload;

	if (len <= 0)
		return;

	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	for ( ;; ) {
		line_len = line_width % len_rem;
		print_hex_ascii_line(ch, line_len, offset);
		len_rem = len_rem - line_len;
		ch = ch + line_len;
		offset = offset + line_width;
		if (len_rem <= line_width) {
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

	return;
}

/*
* Print the values of the packets based arguments.
*/
void print_payload(u_char *arg, int dataLength, const u_char *data, const struct pcap_pkthdr* pkthdr,
				   const struct ether_header* ethernetHeader, const u_char* packet, const struct my_ip *ipHeader,
				   const struct my_tcp* tcphdr, const struct udphdr* udphdr, const struct icmphdr* icmphdr) {

	int ret_val;
	char srcip[256], dstip[256];

	if(arg) {
	   	ret_val = my_strstr((const u_char*)data, dataLength, (char *)arg);
		if (ret_val != 0){
			return;
		}
	}

	print_ether_details(pkthdr, ethernetHeader, packet);

	if (ipHeader) {
		strcpy(srcip, inet_ntoa(ipHeader->ip_src));
		strcpy(dstip, inet_ntoa(ipHeader->ip_dst));

		if (tcphdr) {
			printf("%s:%d -> %s:%d TCP ", srcip, ntohs(tcphdr->source), dstip, ntohs(tcphdr->dest));
			printf("Flags [%c%c%c%c%c%c]\n",
					(tcphdr->th_flags & TH_URG  ? 'U' : '*'),
					(tcphdr->th_flags & TH_ACK  ? 'A' : '*'),
					(tcphdr->th_flags & TH_PUSH ? 'P' : '*'),
					(tcphdr->th_flags & TH_RST  ? 'R' : '*'),
					(tcphdr->th_flags & TH_SYN  ? 'S' : '*'),
					(tcphdr->th_flags & TH_FIN  ? 'F' : '*'));
		} else if (udphdr) {
			printf("%s:%d -> %s:%d UDP\n", srcip, ntohs(udphdr->source), dstip, ntohs(udphdr->dest));
		} else if (icmphdr) {
			printf("%s -> %s ICMP type %d\n", srcip, dstip, icmphdr->type);
		} else {
			printf("%s -> %s OTHER\n", srcip, dstip);
		}
	}
	print_data(data, dataLength);
}

/*
* Parse the IP packet and check for TCP, UDP, ICMP and OTHER protocols.
*/
void print_ip_details(u_char *arg, const struct ether_header* ethernetHeader, const struct my_ip *ipHeader, const u_char* packet, const struct pcap_pkthdr* pkthdr) {

	const struct icmphdr* icmphdr;
    const struct my_tcp* tcphdr;
    const struct udphdr* udphdr;

	int dataLength = 0;
	u_int hlen, size_tcp;
	const u_char *data;

	hlen = IP_HL(ipHeader);

    switch (ipHeader->ip_p) {
		case IPPROTO_TCP:
		    tcphdr = (struct my_tcp*)(packet + SIZE_ETHERNET + hlen*4);
			size_tcp = TH_OFF(tcphdr)*4;
			data = (u_char*)(packet + SIZE_ETHERNET + hlen*4 + size_tcp);
			dataLength = pkthdr->len - (SIZE_ETHERNET + hlen*4 + size_tcp);
			print_payload(arg, dataLength, data, pkthdr, ethernetHeader, packet, ipHeader, tcphdr, NULL, NULL);
		    break;
	 
		case IPPROTO_UDP:
		    udphdr = (struct udphdr*)(packet + SIZE_ETHERNET + hlen*4);

			data = (u_char*)(packet + SIZE_ETHERNET + hlen*4 + sizeof(udphdr));
			dataLength = pkthdr->len - (SIZE_ETHERNET + hlen*4 + sizeof(udphdr));
			print_payload(arg, dataLength, data, pkthdr, ethernetHeader, packet, ipHeader, NULL, udphdr, NULL);
		    break;
	 
		case IPPROTO_ICMP:
		    icmphdr = (struct icmphdr*)(packet + SIZE_ETHERNET + hlen*4);
			
			data = (u_char*)(packet + SIZE_ETHERNET + hlen*4 + sizeof(icmphdr));
			dataLength = pkthdr->len - (SIZE_ETHERNET + hlen*4 + sizeof(icmphdr));
			print_payload(arg, dataLength, data, pkthdr, ethernetHeader, packet, ipHeader, NULL, NULL, icmphdr);
		    break;

		default:
			data = (u_char*)(packet + SIZE_ETHERNET + hlen*4);
			dataLength = pkthdr->len - (SIZE_ETHERNET + hlen*4);
			print_payload(arg, dataLength, data, pkthdr, ethernetHeader, packet, ipHeader, NULL, NULL, NULL);
			break;
    }
}

/*
*Parsing the packet to Ethernet and others.
*/
void print_packet(u_char *arg, const struct pcap_pkthdr* pkthdr, const u_char* packet) {

	const struct ether_header* ethernetHeader;
  	const struct my_ip* ipHeader;
	int dataLength = 0;
	const u_char *data;

	ethernetHeader = (struct ether_header*)packet;
	ipHeader = (struct my_ip*)(packet + SIZE_ETHERNET);

    if (ntohs (ethernetHeader->ether_type) == ETHERTYPE_IP) {
		print_ip_details(arg, ethernetHeader, ipHeader, packet, pkthdr);
    } else {
    	data = (u_char*)(packet + SIZE_ETHERNET);
		dataLength = pkthdr->len - (SIZE_ETHERNET);
		print_payload(arg, dataLength, data, pkthdr, ethernetHeader, packet, NULL, NULL, NULL, NULL);
    }
}

/*
* This function initializes is called from the main program with command line arguments.
* This function is responsible for reading network traffic either from interface or file.
* The packet captured is passed for parsing from here. 
*/
void initialize(char* interface, char* filename, char* regex, char* expression) {

    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    struct bpf_program fp;
    bpf_u_int32 maskp;
    bpf_u_int32 netp;
 
    if(filename == NULL) {
		if(interface == NULL) {
			dev = pcap_lookupdev(errbuf);

			if(dev == NULL) {
				fprintf(stderr, "%s\n", errbuf);
        		exit(1);
    		}
	    } else {
			dev = interface;
	    }

		pcap_lookupnet(dev, &netp, &maskp, errbuf);

		descr = pcap_open_live(dev, BUFSIZ, 1,-1, errbuf);
    } else {
		descr = pcap_open_offline(filename, errbuf);
    }

    if(descr == NULL) {
        printf("pcap_open failed(): %s\n", errbuf);
        exit(1);
    }

	if (pcap_datalink(descr) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}
 
    if(pcap_compile(descr, &fp, expression, 0, netp) == -1) {
        fprintf(stderr, "Error calling pcap_compile\n");
        exit(1);
    }
 
    if(pcap_setfilter(descr, &fp) == -1) {
        fprintf(stderr, "Error setting filter\n");
        exit(1);
    }
 
    pcap_loop(descr, -1, print_packet, (u_char *)regex);

	pcap_freecode(&fp);
	pcap_close(descr);
}

int main(int argc, char **argv){

    extern int optind;
    extern char* optarg;

    char* expression = NULL; 
    char* regex = NULL;
    char* interface = NULL;
    char* pcap_file = NULL;

    int help = 0;
    int option = 0; 
    
    while ((option = getopt (argc, argv, "i:r:s:h")) != -1){
        switch(option){
            case 'i':
                interface = optarg;
                break;
            case 'r':
                pcap_file = optarg;
            	break;
            case 's':
                regex = optarg;
                break;
            case 'h':
                help = 1;
                break;
            default:
                help = 1;
        }
    }


    if(help){
        printf("USAGE: ./mydump [-i interface] [-r file] [-s string] expression \n");
		printf("-i: Live capture from the network device <interface>. \n");
		printf("-r: Read packets from <file> in tcpdump format. \n");
		printf("-s: Keep only packets that contain <string> in their payload. \n");
		printf("expression: BPF filter that specifies which packets will be dumped.\n");
        return 0;
    }

    if(interface && pcap_file){
        printf("You have selected both Interface and File read. Please select only one (-i : interface, -r : file)\n");
        printf("Please Use \"./mydump -h\" for help\n");
        return 1;
    }

    if(argc-optind > 1){
        printf("Please pass the right no. of arguments\n");
        printf ("Please Use \"./mydump -h\" for help\n");
        return 1;
    }

    expression = argv[optind];

	initialize(interface, pcap_file, regex, expression);

    return 0;
}

