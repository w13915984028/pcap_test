
/* 
test of pcap function in Linux 

wangjian, 2017/09/06

*/

#include <pcap.h>
#include <stdio.h>
#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/ip.h>


#define ERR_VAL (-1)
#define OK_VAL (0)

/* ----------- function declaration------------------ */

/* 
    parse the packet captured by pcap, generally it is first a Ethernet packet
    This function can be used as a callback for pcap_loop() 
*/
void local_pcap_packet_handler(
    u_char *args,
    const struct pcap_pkthdr* header,
    const u_char* packet
);
int pcap_test_default_dev();


/* 
    parse IPv4 packet, print the src IP and dest IP, also the transport protocol like TCP, UDP
*/
int tst_parse_ipv4(
    const u_char *packet, 
    const u_char* header_start, 
    const u_char* packet_end);

/*
    parse Layer3 IPv4 packet
*/
int tst_parse_layer3_IPv4_packet(
    const u_char *packet, 
    const u_char *header_start, 
    const u_char *packet_end);

/*
    capture given count of packets from given device, eg:
    100, eth0
*/
int tst_pcap_given_port(
    int cap_count, 
    char* given_device);
    

/* ----------- function implementation------------------ */
    


/* 
    parse IPv4 packet, print the src IP and dest IP, also the transport protocol like TCP, UDP
*/
int tst_parse_ipv4(
    const u_char *packet, 
    const u_char* header_start, 
    const u_char* packet_end)
{
    struct ip *ipV4 = (struct ip *)header_start;
    u_char* src_ip = NULL;
    u_char* dst_ip = NULL;
    
    if(NULL == ipV4)
    {
        fprintf(stderr, "tst_parse_ipv4:error, ip hearder is NULL.\r\n");
        return(ERR_VAL);
    }

    /* IPv4 head size invalid */
    if(header_start + sizeof(struct ip) > packet_end)
    {
        fprintf(stderr, "tst_parse_ipv4:error, ip hearder invalid.\r\n");
        return(ERR_VAL);
    }    
    
    src_ip = (u_char*)&ipV4->ip_src;
    dst_ip = (u_char*)&ipV4->ip_dst;    

    /* only print IPv4 addr */
    fprintf(stdout, "src ip=%u.%u.%u.%u, dst ip =%u.%u.%u.%u, next_prot=%u; ip_head_len=%u, total_len=%u\r\n",
        *src_ip, *(src_ip+1), *(src_ip+2), *(src_ip+3), 
        *dst_ip, *(dst_ip+1), *(src_ip+2), *(dst_ip+3),
        ipV4->ip_p,
        ipV4->ip_hl*4,
        ntohs(ipV4->ip_len));
    
    if (6 == ipV4->ip_p)    
    {
        fprintf(stdout, "A TCP packet\r\n");
    }else if(17 == ipV4->ip_p)
    {
        fprintf(stdout, "A UDP packet\r\n");
    }
    
    return (OK_VAL);
}


/*
    parse IPv4 packet
*/
int tst_parse_layer3_IPv4_packet(
    const u_char *packet, 
    const u_char *header_start, 
    const u_char *packet_end)
{
	/* Note that packet_end points to the byte beyond the end of packet. */
	struct ip *ipV4 = NULL;

	/* Examine IPv4/IPv6 header. */
	if (header_start + sizeof(struct ip) > packet_end) {
		fprintf(stderr, "IP header overflows packet");
		return ERR_VAL;
	}

	/* Look at the IP version number, which is in the first 4 bits
	 * of both IPv4 and IPv6 packets.
	 */
	ipV4 = (struct ip *) (header_start);
	if (ipV4->ip_v == 4)
		return tst_parse_ipv4(packet, header_start, packet_end);
	else if (ipV4->ip_v == 6)
    {
        fprintf(stderr, "TBD: parse IPv6 packet \r\n");
        return ERR_VAL;		//to be add in the future
    }
    
	fprintf(stderr, "TBD: IP other protocol version");
	return ERR_VAL;
}


/* 
    parse the packet captured by pcap, generally it is first a Ethernet packet
    This function can be used as a callback for pcap_loop() 
*/
void local_pcap_packet_handler(
    u_char *args,
    const struct pcap_pkthdr* header,
    const u_char* packet
) 
{
    struct ether_header *eth_header;
    unsigned short sProtocol = 0;

    if (NULL == packet)
        return;

    /* first check the ethernet header, it is always the same (14 bytes) */
    eth_header = (struct ether_header *) packet;

    fprintf(stdout, "Packet captured length: %d; total header length:%d \r\n", 
        header->caplen, header->len); 

    sProtocol = ntohs(eth_header->ether_type);
    if (sProtocol == ETHERTYPE_IP) 
    {
        /* go on IPv4 parse */
        tst_parse_layer3_IPv4_packet(packet, packet + sizeof(struct ether_header),
                   packet + header->len);
        
    } else  if (sProtocol == ETHERTYPE_ARP) 
    {
        fprintf(stdout, " The packet is belong to ARP \r\n");
    } else  if (sProtocol == ETHERTYPE_REVARP) 
    {
        fprintf(stdout, " The packet is belong to Reverse ARP \r\n");
    } else
    {
        fprintf(stdout, " the upper layer protocol is 0x%x; to be supported in future \r\n", 
            (u_short)sProtocol);
    }  
}

/*
    capture given count of packets from given device, eg:
    100 eth0
*/
int tst_pcap_given_port(
    int cap_count, 
    char* given_device)
{
    pcap_t *handle;
    char error_buffer[PCAP_ERRBUF_SIZE];
    char *device = "em1";  // default device
    int snapshot_len = 1028;
    int promiscuous = 0;
    int timeout = 1000;


    fprintf(stdout, "-------start tst_pcap_fixed_port: count %i \r\n", cap_count);

    if (NULL == given_device)
    {
        handle = pcap_open_live(device, snapshot_len, promiscuous, timeout, error_buffer);
    }else
    {
        handle = pcap_open_live(given_device, snapshot_len, promiscuous, timeout, error_buffer);
    }
    
    if (handle == NULL) {
        fprintf(stderr, "Couldn't find the device: %s\n", error_buffer);
        return(ERR_VAL);
    }
    
    pcap_loop(handle, cap_count, local_pcap_packet_handler, NULL);   
    pcap_close(handle);
    
    fprintf(stdout, "-------end tst_pcap_fixed_port\r\n");
    
    return 0;
}

/*
    capture given count of packets from given device, with filter. eg:
    100 eth0 "dst port 22"
    20 em1 "dst host 10.221.118.127 and dst port 22"
*/
int tst_pcap_with_filter(
    int cap_count, 
    char* given_device,
    char* filter)
{
    pcap_t *handle;			/* Session handle */
    char *pDev;			/* The device to CAP */
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    struct bpf_program fp_res;		/* The compiled filter */
    bpf_u_int32 mask;		/* NIC  netmask */
    bpf_u_int32 net;		/* NIC IP */

    fprintf(stdout, "-------start tst_pcap_with_filter\r\n");
    
    /* get a device if the user didn't give or it's empty */
    if (NULL == given_device || 0 == strcmp("", given_device))
    {
        pDev = pcap_lookupdev(errbuf);
        if (NULL == pDev) {
            fprintf(stderr, "Couldn't find default device: %s \r\n", errbuf);
            return(ERR_VAL);
        }
    }else
    {
        pDev = given_device;
    }
    
    /* Find the properties for the device */
    if (pcap_lookupnet(pDev, &net, &mask, errbuf) == -1) 
    {
        fprintf(stderr, "Couldn't get netmask for device %s: %s \r\n", pDev, errbuf);
        net = 0;
        mask = 0;
    }else
    {
        fprintf(stdout, "Dest device successfully found, name:%s: net:%x, mask:%x \r\n", pDev, net, mask);
    }
    
    /* Open the session in promiscuous mode */
    handle = pcap_open_live(pDev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) 
    {
        fprintf(stderr, "Couldn't open device %s: %s \r\n", pDev, errbuf);
        return(ERR_VAL);
    }else
    {
        fprintf(stdout, "Open device %s successfully \r\n", pDev);
    }
    
    
    /* Compile and apply the filter */
    if (ERR_VAL == pcap_compile(handle, &fp_res, filter, 0, net)) 
    {
        fprintf(stderr, "Parse filter fail: %s: %s \r\n", filter, pcap_geterr(handle));
        return(ERR_VAL);
    }
    
    if (ERR_VAL == pcap_setfilter(handle, &fp_res)) 
    {
        fprintf(stderr, "Install filter fail: %s: %s \r\n", filter, pcap_geterr(handle));
        return(ERR_VAL);
    }

    
    pcap_loop(handle, cap_count, local_pcap_packet_handler, NULL);    
    pcap_close(handle);    
    
    fprintf(stdout, "-------end tst_pcap_with_filter\r\n");

    return(OK_VAL);
}




/*
usage:
    ./xxx packet_count interface_name filter_condition
eg:
    ./tst 30 lo
    ./tst 20 em1 "dst host 10.221.118.127 and dst port 22"    
*/

int main(int argc, char **argv) 
{
    pcap_t *handle;
    char *device = NULL;

    int cap_count = 30;
    int i = 0;
    for(i=0; i<argc; i++)
    {
        fprintf(stdout, "  Arg:%i, value:%s\r\n", i, argv[i]);
    }
    
    if (argc>1)
    {
        /* get packet count, max 1000 */
        i = atoi(argv[1]);
        if (i>0 && i<1000)
            cap_count = i;
    }

    if (argc>2)
    {
        /* get port name */
        device = argv[2];
    }

    /* with filter */
    if (argc == 3 || argc == 2)  
    {
        // capture the given port and given count packets
        tst_pcap_given_port(cap_count, device);
    } else if (argc == 4)
    {
        tst_pcap_with_filter(cap_count, device, argv[3]);
    }
    

    return OK_VAL;
}




/*

compile:
    gcc -o tst test-libpcap.c -lpcap

run:   
    ./tst 100 lo 

*/




#if 0
/* for coding of IPv4 pakcet parse reference */

/* netinet/ip.h */
/*
 * Structure of an internet header, naked of options.
 *
 * We declare ip_len and ip_off to be short, rather than u_short
 * pragmatically since otherwise unsigned comparisons can result
 * against negative integers quite easily, and fail in subtle ways.
 */
struct ip {
#if BYTE_ORDER == LITTLE_ENDIAN 
	u_char	ip_hl:4,		/* header length */
		ip_v:4;			/* version */
#endif
#if BYTE_ORDER == BIG_ENDIAN 
	u_char	ip_v:4,			/* version */
		ip_hl:4;		/* header length */
#endif
	u_char	ip_tos;			/* type of service */
	short	ip_len;			/* total length */
	u_short	ip_id;			/* identification */
	short	ip_off;			/* fragment offset field */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
	u_char	ip_ttl;			/* time to live */
	u_char	ip_p;			/* protocol */
	u_short	ip_sum;			/* checksum */
	struct	in_addr ip_src,ip_dst;	/* source and dest address */
};
#endif












