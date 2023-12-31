
/*  강사님원본 0809   */

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
//#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/time.h>
#include <time.h>
#include <math.h>

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <linux/tcp.h>
#include <netdb.h>

#define SUPPORT_OUTPUT

// global variables ...
//char if_bind_global[] = "enp0s3" ;
char if_bind_global[] = "lo" ;
//int if_bind_global_len = 6 ;
int if_bind_global_len = 2 ;

int sendraw_mode = 1;

// for mariadb .
//#include <mariadb/my_global.h>
//#include <mariadb/mysql.h>

// for mysql .
#include <mysql/mysql.h>

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
	u_char ip_vhl;		/* version << 4 | header length >> 2 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* don't fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
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

// global variables .
int g_ret = 0 ;
MYSQL *connection = NULL;
MYSQL conn;
MYSQL_RES *sql_result;
MYSQL_ROW sql_row;

struct pseudohdr {
        u_int32_t   saddr;
        u_int32_t   daddr;
        u_int8_t    useless;
        u_int8_t    protocol;
        u_int16_t   tcplength;
};

//int gbl_debug = 0;
int gbl_debug = 1;

//gbl_debug = 1;
//gbl_debug = 2;

int print_chars(char print_char, int nums);

void
print_payload(const u_char *payload, int len);

void
print_payload_right(const u_char *payload, int len);

void
print_hex_ascii_line(const u_char *payload, int len, int offset);

void
print_hex_ascii_line_right(const u_char *payload, int len, int offset);

unsigned short in_cksum ( u_short *addr , int len );

int sendraw( u_char* pre_packet , int mode ) ;

void got_packet(u_char *args, const struct pcap_pkthdr *header,
    const u_char *packet);


///////////////////////////////////////
//                                   //
// begin MAIN FUNCTION !!!    //
//                                   //
///////////////////////////////////////
int main(int argc, char *argv[])
{
	pcap_t *handle;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[] = "port 80";	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */
	struct pcap_if *devs;
	
	/* Define the device */
	//dev = pcap_lookupdev(errbuf);
	//if (dev == NULL) {
	//	fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
	//	return(2);
	//}
	pcap_findalldevs(&devs, errbuf);
	printf("INFO: dev name = %s .\n" , (*devs).name );
	dev = (*devs).name ;
	strcpy(dev,"lo");
	//pcap_freealldevs(devs);
	
	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}
	/* Open the session in promiscuous mode */
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	
	if ( 0 ) {
	for ( int i = 0 ; i < 10 ; i++ ) {
		/* Grab a packet */
		packet = pcap_next(handle, &header);
		/* Print its length */
		printf("Jacked a packet with "
			"length of [%d]\n", header.len);
	}
	} // if for comment out .
	
	mysql_init(&conn);
	connection = mysql_real_connect(
			&conn,		// mariadb/mysql handler
			"192.168.111.51",		// host address
			"ubuntu",		// db id
			"1234",	// db pass
			"project_db",	// db_name
			3306,			// port
			(char*)NULL,		// 
			0			//
	);
	
	if ( connection == NULL ) {
		fprintf ( stderr , "ERROR: mariadb connection error: %s\n",
					mysql_error(&conn)
			);
		return 1;
	} else { 
		fprintf ( stdout , "INFO: mariadb connection OK\n" );
	}
	
	int result = 0 ;
	//result = pcap_loop(handle, 10, got_packet, NULL) ;
	result = pcap_loop(handle, 0, got_packet, NULL) ;
	
	if ( result != 0 ) {
		fprintf(stderr, "ERROR: pcap_loop end with error !!!!\n");
	} else {
		fprintf(stdout, "INFO: pcap_loop end without error .\n");
	}
	
	/* And close the session */
	pcap_close(handle);
	return(0);
}
// end of main function.


void got_packet(u_char *args, const struct pcap_pkthdr *header,
    const u_char *packet) {

	/* ethernet headers are always exactly 14 bytes */
	#define SIZE_ETHERNET 14

	u_int size_ip;
	u_int size_tcp;

	const struct sniff_ethernet *ethernet; /* The ethernet header */
	const struct sniff_ip *ip; /* The IP header */
	const struct sniff_tcp *tcp; /* The TCP header */
	const char *payload; /* Packet payload */

	ethernet = (struct sniff_ethernet*)(packet);
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	
	unsigned short int  payload_len = 0;
	payload_len = ntohs(ip->ip_len) - size_ip - size_tcp ;
	//printf("INFO: payload_len = %u .\n", payload_len);

	//printf("Jacked a packet with "
	//		"length of [%d]\n", header->len);
	
	// print Ethernet address .
	if ( 0 ) {
	printf("DATA: dest MAC : %02x:%02x:%02x:%02x:%02x:%02x\n" ,
				ethernet->ether_dhost[0],
				ethernet->ether_dhost[1],
				ethernet->ether_dhost[2],
				ethernet->ether_dhost[3],
				ethernet->ether_dhost[4],
				ethernet->ether_dhost[5] 
		);
	
	printf("DATA: src MAC : %02x:%02x:%02x:%02x:%02x:%02x\n" ,
				ethernet->ether_shost[0],
				ethernet->ether_shost[1],
				ethernet->ether_shost[2],
				ethernet->ether_shost[3],
				ethernet->ether_shost[4],
				ethernet->ether_shost[5] 
		);
	}
	
	char *IPbuffer, *IPbuffer2;
	char IPbuffer_str[16];
	char IPbuffer2_str[16];
	
	IPbuffer = inet_ntoa(ip->ip_src);
	strcpy(IPbuffer_str, IPbuffer);

	IPbuffer2 = inet_ntoa(ip->ip_dst);
	strcpy(IPbuffer2_str, IPbuffer2);
		
	//printf("DATA: IP src : %s\n", IPbuffer_str);
	//printf("DATA: IP dst : %s\n", IPbuffer2_str);
	
	// print tcp port number .
	unsigned short tcp_src_port = 0 ;
	unsigned short tcp_dst_port = 0 ;
	
	tcp_src_port = ntohs(tcp->th_sport);
	tcp_dst_port = ntohs(tcp->th_dport);
	
	//printf("DATA : src Port : %u\n" , tcp_src_port );
	//printf("DATA : dst Port : %u\n" , tcp_dst_port );
	
	u_char *domain = NULL;
	u_char *domain_end = NULL;
	u_char domain_str[256] = { 0x00 };
	
	int domain_len = 0 ;
	
	domain = strstr(payload , "Host: ");
	if ( domain != NULL ) {
		domain_end = strstr(domain , "\x0d\x0a") ;
		if ( domain_end != NULL ) {
			// print ip , port info .
			//printf("DATA: IP src : %s\n", IPbuffer_str);
			//printf("DATA: IP dst : %s\n", IPbuffer2_str);
			//printf("DATA : src Port : %u\n" , tcp_src_port );
			//printf("DATA : dst Port : %u\n" , tcp_dst_port );
			
			// print domain name .
			domain_len = domain_end - domain - 6 ;
			strncpy(domain_str , domain + 6 , domain_len );
			//printf("INFO: Domain = %s .\n" , domain_str ) ;
		}
	} else {
		//printf("INFO: Host string not found \n");
	}
	
	struct check_domain_struct {
		char domain[256];
	};
	
	//struct check_domain_struct check_domain_str[100] = { 0x00 };
	//struct check_domain_struct check_domain_str[100];
	
	// define variable with malloc .
	int check_domain_str_count = 10000 ;
	struct check_domain_struct *check_domain_str = NULL;
	check_domain_str = malloc ( 
				sizeof( struct check_domain_struct ) * 
					check_domain_str_count
			       );
	if ( check_domain_str == NULL ) {
		fprintf(stderr, "ERROR: malloc fail (line=%d) !!!\n",
				__LINE__);
	} else {
		//fprintf(stdout, "INFO: malloc OK (line=%d) !!!\n",
		//		__LINE__);
	}
	
	memset ( check_domain_str , 
		0x00 , 
		sizeof(struct check_domain_struct) * 
			 check_domain_str_count
	);
	
	
	//for ( int i = 0 ; i < 100 ; i++ ) {
	//	strcpy ( check_domain_str[i].domain , "" );
	//}
	
	//char check_domain[256] = "naver.com" ;
	char *check_domain_ptr[100] = { NULL } ;
	for ( int i = 0 ; i < 100 ; i++ ) {
		check_domain_ptr[i] = malloc(256);
		if ( check_domain_ptr[i] == NULL ) {
			fprintf(stderr, "ERROR: malloc fail !!\n");
		}
	}
	
	//strcpy(check_domain_ptr[0] , "naver.com" );
	//strcpy(check_domain_ptr[1] , "kakao.com" );
	//strcpy(check_domain_ptr[2] , "mail.naver.com" );
	
	strcpy(check_domain_str[0].domain , "naver.com" );
	strcpy(check_domain_str[1].domain , "kakao.com" );
	strcpy(check_domain_str[2].domain , "mail.naver.com" );
	strcpy(check_domain_str[3].domain , "astalavista.com" );
	
	if ( domain_len ) {
		int cmp_ret = 0;
		
		cmp_ret = 1;
		// for loop 1 .
		for ( int i = 0 ; i < 100 ; i++ ) {
			//cmp_ret = strcmp ( check_domain , domain_str ) ;
			//cmp_ret = strcmp ( check_domain_ptr[i] ,
			int str1_len = 
				strlen ( check_domain_str[i].domain );

			int str2_len = 
				strlen ( domain_str );
			
			if ( str1_len != str2_len ) {
				continue; // check next array value .
			}
			
			cmp_ret = strcmp ( check_domain_str[i].domain ,  
						domain_str ) ;
			printf("DEBUG: domain name check result : %d\n" , 
								cmp_ret );
			if ( cmp_ret == 0 ) {
				break; // stop for loop 1 .
			}
			
			// break if meet null data array .
			if ( strlen(check_domain_str[i].domain) == 0 ) {
				break; // stop for loop 1 .
			}
			
		} // end for loop 1 .
		
		// print ip , port info .
		printf("DATA: IP src : %s\n", IPbuffer_str);
		printf("DATA: IP dst : %s\n", IPbuffer2_str);
		printf("DATA : src Port : %u\n" , tcp_src_port );
		printf("DATA : dst Port : %u\n" , tcp_dst_port );
		
		// print domain name .
		printf("INFO: Domain = %s .\n" , domain_str ) ;

		if ( cmp_ret == 0 ) {
			printf("DEBUG: domain blocked .\n");
			int sendraw_ret = sendraw(packet , sendraw_mode);
		} else { 
			printf("DEBUG: domain allowed .\n");		
		} // end if cmp_ret .
	
		// begin insert log to db .
		int query_stat = 0;
		char query_str[1048576] = { 0x00 };
	
		sprintf(query_str , "INSERT INTO tb_packet_log ( src_ip , src_port , dst_ip , dst_port , "
									" domain , result ) VALUES "
					"( '%s' , %u , '%s' , %u , '%s' , %d )" ,
			IPbuffer_str , 	// src_ip .
			tcp_src_port	,	// src_port .
			IPbuffer2_str ,	// dst_ip .
			tcp_dst_port ,	// dst_port .
			domain_str ,		// domain .
			cmp_ret		// result .
			 );
	
		query_stat = mysql_query( connection , query_str );
		if ( query_stat != 0 ) {
			fprintf ( stderr , "ERROR: mariadb query error: %s\n", mysql_error(&conn) );
			return;
		} else {
			fprintf ( stdout , "INFO: mariadb query OK\n" );
		}
	
		// end insert log to db .
		
		if ( check_domain_str != NULL ) {
			free(check_domain_str);
			check_domain_str = NULL;
		} else {
			fprintf(stderr, "CRIT: check_domain_str"
					" was already free (line=%d)\n",
						__LINE__) ;
		}
	
	} // end if domain_len .
		
	//printf("\n");			
	
} // end of got_packet function .

unsigned short in_cksum(u_short *addr, int len)
{
        int         sum=0;
        int         nleft=len;
        u_short     *w=addr;
        u_short     answer=0;
        while (nleft > 1){
            sum += *w++;
            nleft -= 2;
        }

        if (nleft == 1){
            *(u_char *)(&answer) = *(u_char *)w ;
            sum += answer;
        }

        sum = (sum >> 16) + (sum & 0xffff);
        sum += (sum >> 16);
        answer = ~sum;
        return(answer);
}
// end in_cksum function .


int sendraw( u_char* pre_packet, int mode)
{
		const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */

		u_char packet[1600];
        int raw_socket, recv_socket;
        int on=1, len ;
        char recv_packet[100], compare[100];
        struct iphdr *iphdr;
        struct tcphdr *tcphdr;
        struct in_addr source_address, dest_address;
        struct sockaddr_in address, target_addr;
        struct pseudohdr *pseudo_header;
        struct in_addr ip;
        struct hostent *target;
        int port;
        int loop1=0;
        int loop2=0;
        int pre_payload_size = 0 ;
		u_char *payload = NULL ;
		int size_vlan = 0 ;
		int size_vlan_apply = 0 ;
		int size_payload = 0 ;
        int post_payload_size = 0 ;
        int sendto_result = 0 ;
	    int rc = 0 ;
	    //struct ifreq ifr ;
		char * if_bind ;
		int if_bind_len = 0 ;
		int setsockopt_result = 0 ;
		int prt_sendto_payload = 0 ;
		char* ipaddr_str_ptr ;

		int warning_page = 1 ;
		int vlan_tag_disabled = 0 ;

		int ret = 0 ;

		#ifdef SUPPORT_OUTPUT
		print_chars('\t',6);
		printf( "\n[raw socket sendto]\t[start]\n\n" );

		if (size_payload > 0 || 1) {
			print_chars('\t',6);
			printf("   pre_packet whole(L2-packet-data) (%d bytes only):\n", 100);
			print_payload_right(pre_packet, 100);
		}
		//m-debug
		printf("DEBUG: (u_char*)packet_dmp ( in sendraw func ) == 0x%p\n", pre_packet);
		#endif

        for( port=80; port<81; port++ ) {
			#ifdef SUPPORT_OUTPUT
			print_chars('\t',6);
			printf("onetime\n");
			#endif
			// raw socket 생성
			raw_socket = socket( AF_INET, SOCK_RAW, IPPROTO_RAW );
			if ( raw_socket < 0 ) {
				print_chars('\t',6);
				fprintf(stderr,"Error in socket() creation - %s\n", strerror(errno));
				fprintf(stderr,"Error in socket() creation - %s\n", strerror(errno));
				return -2;
			}

			setsockopt( raw_socket, IPPROTO_IP, IP_HDRINCL, (char *)&on, sizeof(on));

			if ( if_bind_global != NULL ) {
				setsockopt_result = setsockopt( raw_socket, SOL_SOCKET, SO_BINDTODEVICE, if_bind_global, if_bind_global_len );

				if( setsockopt_result == -1 ) {
					print_chars('\t',6);
					fprintf(stderr,"ERROR: setsockopt() - %s\n", strerror(errno));
					return -2;
				}
				#ifdef SUPPORT_OUTPUT
				else {
					print_chars('\t',6);
					fprintf(stdout,"OK: setsockopt(%s)(%d) - %s\n", if_bind_global, setsockopt_result, strerror(errno));
				}
				#endif

			}

			ethernet = (struct sniff_ethernet*)(pre_packet);
			if ( ethernet->ether_type == (unsigned short)*(unsigned short*)&"\x81\x00" ) {
				#ifdef SUPPORT_OUTPUT
				printf("vlan packet\n");
				#endif
				size_vlan = 4;
				//memcpy(packet, pre_packet, size_vlan);
				memcpy(packet, pre_packet+14, size_vlan);//vlan사용시 이더넷 뒤에 vlan파트를 넣어줌 
//captured packet nor	//<eht_header><ip header> <tcp>
//captured packet vlan	//<eht_header> <vlan data(4b)><ip header> <tcp>
//blocking packet 		//<vlan><ipheader><tcp_header>

			} else if (ethernet->ether_type == (unsigned short)*(unsigned short*)&"\x08\x00" ) {
				#ifdef SUPPORT_OUTPUT
				printf("normal packet\n");
				#endif
				size_vlan = 0;
			} else {
				fprintf(stderr,"NOTICE: ether_type diagnostics failed .......... \n");
			}

			vlan_tag_disabled = 1 ;
			if ( vlan_tag_disabled == 1 ) {
				size_vlan_apply = 0 ;
				memset (packet, 0x00, 4) ;
			} else {
				size_vlan_apply = size_vlan ;
			}
                // TCP, IP 헤더 초기화
                iphdr = (struct iphdr *)(packet + size_vlan_apply) ;
                memset( iphdr, 0, 20 );
                tcphdr = (struct tcphdr *)(packet + size_vlan_apply + 20);
                memset( tcphdr, 0, 20 );

				#ifdef SUPPORT_OUTPUT
                // TCP 헤더 제작
                tcphdr->source = htons( 777 );
                tcphdr->dest = htons( port );
                tcphdr->seq = htonl( 92929292 );
                tcphdr->ack_seq = htonl( 12121212 );
				#endif

				source_address.s_addr = 
				((struct iphdr *)(pre_packet + size_vlan + 14))->daddr ;
				// twist s and d address
				dest_address.s_addr = ((struct iphdr *)(pre_packet + size_vlan + 14))->saddr ;		// for return response
				iphdr->id = ((struct iphdr *)(pre_packet + size_vlan + 14))->id ;
				int pre_tcp_header_size = 0;
				char pre_tcp_header_size_char = 0x0;
				pre_tcp_header_size = ((struct tcphdr *)(pre_packet + size_vlan + 14 + 20))->doff ;
				pre_payload_size = ntohs( ((struct iphdr *)(pre_packet + size_vlan + 14))->tot_len ) - ( 20 + pre_tcp_header_size * 4 ) ;

				tcphdr->source = ((struct tcphdr *)(pre_packet + size_vlan + 14 + 20))->dest ;		// twist s and d port
				tcphdr->dest = ((struct tcphdr *)(pre_packet + size_vlan + 14 + 20))->source ;		// for return response
				tcphdr->seq = ((struct tcphdr *)(pre_packet + size_vlan + 14 + 20))->ack_seq ;
				tcphdr->ack_seq = ((struct tcphdr *)(pre_packet + size_vlan + 14 + 20))->seq  + htonl(pre_payload_size - 20)  ;
				tcphdr->window = ((struct tcphdr *)(pre_packet + size_vlan + 14 + 20))->window ;

                tcphdr->doff = 5;

                tcphdr->ack = 1;
                tcphdr->psh = 1;

                tcphdr->fin = 1;
                // 가상 헤더 생성.
                pseudo_header = (struct pseudohdr *)((char*)tcphdr-sizeof(struct pseudohdr));
                pseudo_header->saddr = source_address.s_addr;
                pseudo_header->daddr = dest_address.s_addr;
                pseudo_header->useless = (u_int8_t) 0;
                pseudo_header->protocol = IPPROTO_TCP;
                pseudo_header->tcplength = htons( sizeof(struct tcphdr) + post_payload_size);

				#ifdef SUPPORT_OUTPUT
				// m-debug
				printf("DEBUG: &packet == \t\t %p \n" , &packet);
				printf("DEBUG: pseudo_header == \t %p \n" , pseudo_header);
				printf("DEBUG: iphdr == \t\t\t %p \n" , iphdr);
				printf("DEBUG: tcphdr == \t\t\t %p \n" , tcphdr);
				#endif

				#ifdef SUPPORT_OUTPUT
                strcpy( (char*)packet + 40, "HAHAHAHAHOHOHOHO\x0" );
				#endif

				// choose output content
				warning_page = 5;
				if ( warning_page == 5 ){
					// write post_payload ( redirecting data 2 )
					//post_payload_size = 201 + 67  ;   // Content-Length: header is changed so post_payload_size is increased.
					post_payload_size = 230 + 65  ;   // Content-Length: header is changed so post_payload_size is increased.
                    //memcpy ( (char*)packet + 40, "HTTP/1.1 200 OK" + 0x0d0a + "Content-Length: 1" + 0x0d0a + "Content-Type: text/plain" + 0x0d0a0d0a + "a" , post_payload_size ) ;
					memcpy ( (char*)packet + 40, "HTTP/1.1 200 OK\x0d\x0a"
							"Content-Length: 230\x0d\x0a"
							"Content-Type: text/html"
							"\x0d\x0a\x0d\x0a"
							"<html>\r\n"
							"<head>\r\n"
							"<meta charset=\"UTF-8\">\r\n"
							"<title>\r\n"
							"CroCheck - WARNING - PAGE\r\n"
        						"SITE BLOCKED - WARNING - \r\n"
							"</title>\r\n"
							"</head>\r\n"
							"<body>\r\n"
							"<center>\r\n"
		"<img   src=\"http://127.0.0.1:3000/warning.jpg\" alter=\"*WARNING*\">\r\n"
        "<h1>SITE BLOCKED</h1>\r\n"
							"</center>\r\n"
							"</body>\r\n"
							"</html>", post_payload_size ) ;
                }
				pseudo_header->tcplength = htons( sizeof(struct tcphdr) + post_payload_size);

                tcphdr->check = in_cksum( (u_short *)pseudo_header,
                                sizeof(struct pseudohdr) + sizeof(struct tcphdr) + post_payload_size);

                iphdr->version = 4;
                iphdr->ihl = 5;
                iphdr->protocol = IPPROTO_TCP;
                //iphdr->tot_len = 40;
                iphdr->tot_len = htons(40 + post_payload_size);

				#ifdef SUPPORT_OUTPUT
				//m-debug
				printf("DEBUG: iphdr->tot_len = %d\n", ntohs(iphdr->tot_len));
				#endif

				iphdr->id = ((struct iphdr *)(pre_packet + size_vlan + 14))->id + htons(1);
				
				memset( (char*)iphdr + 6 ,  0x40  , 1 );
				
                iphdr->ttl = 60;
                iphdr->saddr = source_address.s_addr;
                iphdr->daddr = dest_address.s_addr;
                // IP 체크섬 계산.
                iphdr->check = in_cksum( (u_short *)iphdr, sizeof(struct iphdr));

                address.sin_family = AF_INET;

				address.sin_port = tcphdr->dest ;
				address.sin_addr.s_addr = dest_address.s_addr;

				prt_sendto_payload = 0;
				#ifdef SUPPORT_OUTPUT
				prt_sendto_payload = 1 ;
				#endif

				if( prt_sendto_payload == 1 ) {

				print_chars('\t',6);
				printf("sendto Packet data :\n");

				print_chars('\t',6);
				printf("       From: %s(%hhu.%hhu.%hhu.%hhu)\n",
								inet_ntoa( source_address ),
								((char*)&source_address.s_addr)[0],
								((char*)&source_address.s_addr)[1],
								((char*)&source_address.s_addr)[2],
								((char*)&source_address.s_addr)[3]
						);
				print_chars('\t',6);
				printf("         To: %s(%hhu.%hhu.%hhu.%hhu)\n",
								inet_ntoa( dest_address ),
								((char*)&dest_address.s_addr)[0],
								((char*)&dest_address.s_addr)[1],
								((char*)&dest_address.s_addr)[2],
								((char*)&dest_address.s_addr)[3]
						);

				switch(iphdr->protocol) {
					case IPPROTO_TCP:
						print_chars('\t',6);
						printf("   Protocol: TCP\n");
						break;
					case IPPROTO_UDP:
						print_chars('\t',6);
						printf("   Protocol: UDP\n");
						return -1;
					case IPPROTO_ICMP:
						print_chars('\t',6);
						printf("   Protocol: ICMP\n");
						return -1;
					case IPPROTO_IP:
						print_chars('\t',6);
						printf("   Protocol: IP\n");
						return -1;
					case IPPROTO_IGMP:
						print_chars('\t',6);
						printf("   Protocol: IGMP\n");
						return -1;
					default:
						print_chars('\t',6);
						printf("   Protocol: unknown\n");
						//free(packet_dmp);
						return -2;
				}

				print_chars('\t',6);
				printf("   Src port: %d\n", ntohs(tcphdr->source));
				print_chars('\t',6);
				printf("   Dst port: %d\n", ntohs(tcphdr->dest));

				payload = (u_char *)(packet + sizeof(struct iphdr) + tcphdr->doff * 4 );

				size_payload = ntohs(iphdr->tot_len) - ( sizeof(struct iphdr) + tcphdr->doff * 4 );

				printf("DEBUG: sizeof(struct iphdr) == %lu \t , \t tcphdr->doff * 4 == %hu \n",
								sizeof(struct iphdr) , tcphdr->doff * 4);

				if (size_payload > 0 || 1) {
					print_chars('\t',6);
					printf("   PACKET-HEADER(try1) (%d bytes):\n", ntohs(iphdr->tot_len) - size_payload);
					//print_payload(payload, size_payload);
					print_payload_right((const u_char*)&packet, ntohs(iphdr->tot_len) - size_payload);
				}

				if (size_payload > 0 || 1) {
					print_chars('\t',6);
					printf("   PACKET-HEADER(try2) (%d bytes):\n", 40);
					//print_payload(payload, size_payload);
					print_payload_right((const u_char*)&packet, 40);
				}

				if (size_payload > 0) {
					print_chars('\t',6);
					printf("   Payload (%d bytes):\n", size_payload);
					//print_payload(payload, size_payload);
					print_payload_right(payload, size_payload);
				}
			} // end -- if -- prt_sendto_payload = 1 ;
				if ( mode == 1 ) {
                    sendto_result = sendto( raw_socket, &packet, ntohs(iphdr->tot_len), 0x0,
                                            (struct sockaddr *)&address, sizeof(address) ) ;
					if ( sendto_result != ntohs(iphdr->tot_len) ) {
						fprintf ( stderr,"ERROR: sendto() - %s\n", strerror(errno) ) ;
						ret = -10 ;
					} else {
						ret = 1 ;
					}
		        } // end if(mode)
                //} // end for loop

				if ( (unsigned int)iphdr->daddr == (unsigned int)*(unsigned int*)"\xCB\xF6\x53\x2C" ) {
					printf("##########################################################################################################################\n");
					printf("##########################################################################################################################\n");
					printf("##########################################################################################################################\n");
					printf("##########################################################################################################################\n");
					printf("##########################################################################################################################\n");
					printf("##########################################################################################################################\n");
					printf("##########################################################################################################################\n");
					printf( "address1 == %hhu.%hhu.%hhu.%hhu\taddress2 == %X\taddress3 == %X\n",
							*(char*)((char*)&source_address.s_addr + 0),*(char*)((char*)&source_address.s_addr + 1),
							*(char*)((char*)&source_address.s_addr + 2),*(char*)((char*)&source_address.s_addr + 3),
							source_address.s_addr,	(unsigned int)*(unsigned int*)"\xCB\xF6\x53\x2C" );
				}
                close( raw_socket );
                
        } // end for loop
		#ifdef SUPPORT_OUTPUT
        printf( "\n[sendraw] end .. \n\n" );
		#endif
		//return 0;
		return ret ;
}
// end sendraw function .


int print_chars(char print_char, int nums)
{
	int i = 0;
	for ( i ; i < nums ; i++) {
		printf("%c",print_char);
	}
	return i;
}

void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);

	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");

	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
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

void
print_hex_ascii_line_right(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;
	int tabs_cnt = 6 ;  // default at now , afterward receive from function caller

	/* print 10 tabs for output to right area	*/
	for ( i = 0 ; i < tabs_cnt ; i++ ) {
		printf("\t");
	}

	/* offset */
	printf("%05d   ", offset);

	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");

	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
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

/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

	return;
}


/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload_right(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;


	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line_right(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line_right(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line_right(ch, len_rem, offset);
			break;
		}
		//m-debug
		if ( offset > 600 ) {
			print_chars('\t',6);
			printf("INFO: ..........    payload too long (print_payload_right func) \n");
			break;
		}
	}

    return;
}

