#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/time.h>
#include <time.h>
#include <math.h>

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <linux/tcp.h>
#include <netdb.h>
#include <mariadb/mysql.h>

// multi thread library h
#include <pthread.h>


#define SUPPORT_OUTPUT //프로그램이 컴파일될때 디버깅모드로 컴파일됨 

// global variables ...
//char if_bind_global[] = "enp0s3" ;
char if_bind_global[] = "lo" ;
//int if_bind_global_len = 6 ;
int if_bind_global_len = 2 ;

int sendraw_mode = 1;

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN  6
#define IP_STR_ADDR_LEN 16

/* Ethernet header */
struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
};
#define SIZE_ETHERNET 14

/* IP header */
struct sniff_ip {
    u_char ip_vhl;      /* version << 4 | header length >> 2 */
    u_char ip_tos;      /* type of service */
    u_short ip_len;     /* total length */
    u_short ip_id;      /* identification */
    u_short ip_off;     /* fragment offset field */
#define IP_RF 0x8000        /* reserved fragment flag */
#define IP_DF 0x4000        /* don't fragment flag */
#define IP_MF 0x2000        /* more fragments flag */
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
    u_char ip_ttl;      /* time to live */
    u_char ip_p;        /* protocol */
    u_short ip_sum;     /* checksum */
    struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)       (((ip)->ip_vhl) & 0x0f) 
#define IP_V(ip)        (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;
struct sniff_tcp {
    u_short th_sport;   /* source port */
    u_short th_dport;   /* destination port */
    tcp_seq th_seq;     /* sequence number */
    tcp_seq th_ack;     /* acknowledgement number */
    u_char th_offx2;    /* data offset, rsvd */
#define TH_OFF(th)  (((th)->th_offx2 & 0xf0) >> 4) // 논리곱  시프트 
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
    u_short th_win;     /* window */
    u_short th_sum;     /* checksum */
    u_short th_urp;     /* urgent pointer */
};

/* SQL  */ 
int g_ret = 0 ;
MYSQL *conn;
MYSQL_RES *res=NULL;
MYSQL_ROW row={0};
MYSQL_FIELD *field;
#define host_ip "192.168.111.51"
#define user_name "ubuntu"
#define passwd  "1234"
#define dbname  "project"
#define port_num 3306

// DB 도메인 목록을 저장할 구조체 와 전역 구조체 포인터 설정

//----------------------------------------------------

/* 패킷프로토콜 파트별 전역변수 */
struct sniff_ethernet *ethernet;
struct sniff_ip *ip;
struct sniff_tcp *tcp;
char *payload;
u_int size_ip;
u_int size_tcp;

/* 가상헤더 구조체 */
struct pseudohdr {
        u_int32_t   saddr;
        u_int32_t   daddr;
        u_int8_t    useless;
        u_int8_t    protocol;
        u_int16_t   tcplength;
};


int gbl_debug = 1; 

/* get value func*/
struct sniff_ethernet* get_ethernet() ;
struct sniff_ip* get_ip();
struct sniff_tcp* get_tcp();
char* get_payload();
u_int get_size_ip();
u_int get_size_tcp();


/* set value func*/
void set_ethernet(struct sniff_ethernet *new_ethernet) ;
void set_ip(struct sniff_ip *new_ip) ;
void set_tcp(struct sniff_tcp *new_tcp) ;
void set_payload(char *new_payload);
void set_size_ip(u_int new_size_ip);
void set_size_tcp(u_int new_size_tcp);

/*change functions addr = ethernet->ether_dhost, ether_shost*/ 
char* ethernet_address_to_string(const u_char* addr);

/* print net data */
int print_chars(char print_char, int nums);
void print_payload(const u_char *payload, int len); 
void print_payload_right(const u_char *payload, int len);
void print_hex_ascii_line(const u_char *payload, int len, int offset);
void print_hex_ascii_line_right(const u_char *payload, int len, int offset);
unsigned short in_cksum ( u_short *addr , int len );

int sendraw( u_char* pre_packet , int mode ) ;

/* sql func */
typedef struct {
    char** domains;
    size_t size;
} DYNAMIC_DOMAIN_LIST;
static DYNAMIC_DOMAIN_LIST* global_list = NULL;
DYNAMIC_DOMAIN_LIST* get_dynamic_domain_list();
char* get_dynamic_domain(size_t index);
void set_dynamic_domain_list(MYSQL_RES* result); 
void free_dynamic_domain_list();
void sql_query_insert(u_char [256]);

/*print net data */
void print_ethdata();
void print_ipdata();
void print_tcpdata();
void print_packet_info(const struct iphdr *, const struct tcphdr *, const u_char *, int);
void print_ip_protocol(struct iphdr*);

void got_packet(u_char *args, const struct pcap_pkthdr *header,const u_char *packet);

/////////////////////////////////////////////
//                                         //
//       MAIN START                        //
/////////////////////////////////////////////


int main(){

    pcap_t *handle;         /* Session handle */
    char *dev;          /* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];  /* Error string */
    struct bpf_program fp;      /* The compiled filter */
    char filter_exp[] = "port 80";  /* The filter expression */
    bpf_u_int32 mask;       /* Our netmask */
    bpf_u_int32 net;        /* Our IP */
    struct pcap_pkthdr header;  /* The header that pcap gives us */
    const u_char *packet;       /* The actual packet */
    struct pcap_if *devs;
    
    /* Define the device */
    pcap_findalldevs(&devs, errbuf);
    printf("INFO: dev name = %s .\n" , (*devs).name );
    dev = (*devs).name ;
    
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
    /* SQL Connect */
    conn=mysql_init(NULL);
    
    if(conn==NULL) {
        printf("ERROR: SQL Init fail %s",mysql_error(conn) );        
    }   
    if(mysql_real_connect(conn,host_ip,user_name,passwd,dbname,port_num,NULL,0)==NULL){
            printf("ERROR: SQL connect fail %s",mysql_error(conn) );        
    }else{printf("Connect sql\n");}
    /* SQL Connect end */

    char query[]="select harmful_domain from harmful_domain_index";
       
    if(mysql_query(conn,query)){
        printf("ERROR: SQL query fail %s",mysql_error(conn) );        
    }
    // 조회한 DB 값 Set
    res=mysql_store_result(conn);
    set_dynamic_domain_list(res);
    //도메인을 따로 셋한후 res해제    
    mysql_free_result(res);

    int result = 0 ;
    result = pcap_loop(handle, 0, got_packet, NULL) ;
    
    if ( result != 0 ) {
        fprintf(stderr, "ERROR: pcap_loop end with error !!!!\n");
    } else {
        fprintf(stdout, "INFO: pcap_loop end without error .\n");
    }
    
    /* And close the session */
    pcap_close(handle);

    free_dynamic_domain_list();
    
    return 0;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header,const u_char *packet){

    set_ethernet((struct sniff_ethernet*)(packet));
    set_ip((struct sniff_ip*)(packet + SIZE_ETHERNET));
    set_size_ip(IP_HL(get_ip())*4);
    u_char domain_str[256]={0x00};
        
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", get_size_ip());
        return;
    }
    set_tcp((struct sniff_tcp*)(packet + SIZE_ETHERNET + get_size_ip()));
    set_size_tcp(TH_OFF(get_tcp())*4);
        
    if (size_tcp < 20) {
        printf("   * Invalid TCP header length: %u bytes\n", get_size_tcp());
        return;
    }
    set_payload((u_char *)(packet + SIZE_ETHERNET + get_size_ip() + get_size_tcp()));
        
    unsigned short int payload_len = 0;
    payload_len=ntohs(ip->ip_len)-get_size_ip()-get_size_tcp();

    /* 페이로드의 도메인 처리 */
    u_char *domain = NULL;
    u_char *domain_end=NULL;
        
    int domain_len = 0;
    domain=strstr(payload,"Host: ");
        
    if(domain!=NULL){
        domain_end=strstr(domain,"\x0d\x0a");
        if(domain_end!=NULL){
            domain_len=domain_end-domain-6; 
            strncpy(domain_str , domain + 6 , domain_len );
        }
    }
   
    /* DB에서 차단할 도메인을 가져옴 */

    DYNAMIC_DOMAIN_LIST *check_domain_str = get_dynamic_domain_list();
    if ( domain_len ) {
        printf("domainlen\n");
        int cmp_ret = 0;
        
        cmp_ret = 1;
        // for loop 1 .
        
        // 도메인 함수 get_dynamic_domain_list()->size로 100 대신 
        for ( int i = 0 ; i < check_domain_str->size ; i++ ) {
            
            int str1_len = strlen ( check_domain_str->domains[i] );
            int str2_len = strlen ( domain_str );

            if ( str1_len != str2_len ) { continue; }
            
            cmp_ret = strcmp ( check_domain_str->domains[i], domain_str ) ;
            printf("DEBUG: domain name check result : %d\n", cmp_ret );
            if ( cmp_ret == 0 ) { break; }
            
            // break if meet null data array .
            if ( strlen(check_domain_str->domains[i]) == 0 ) {
                break; 
            }

        } 
            
            if ( cmp_ret == 0 ) {
                print_ethdata();
                print_ipdata();
                print_tcpdata();
                printf("INFO : domain blocked .\n");
                int sendraw_ret = sendraw(packet , sendraw_mode);
            } else { 
                printf("INFO : domain allowed .\n");        
            }
            int query_stat = 0;
            char query_str[1048576] = { 0x00 };
            sql_query_insert(domain_str);
        
    } 
}   


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
		const struct sniff_ethernet *ethernet;  

		u_char packet[1600]; 
        int raw_socket, recv_socket;
        int on=1, len ;
        struct iphdr *iphdr;
        struct tcphdr *tcphdr;
        struct in_addr source_address, dest_address;
        struct sockaddr_in address, target_addr;
        struct pseudohdr *pseudo_header;
        struct in_addr ip;
        struct hostent *target;
        int port;
        int pre_payload_size = 0 ;
		u_char *payload = NULL ;
		int size_vlan = 0 ;
		int size_vlan_apply = 0 ;
		int size_payload = 0 ;
        int post_payload_size = 0 ;
        int sendto_result = 0 ;
	    int rc = 0 ;
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

		printf("DEBUG: (u_char*)packet_dmp ( in sendraw func ) == 0x%p\n", pre_packet);
		#endif

        for( port=80; port<81; port++ ) {
			#ifdef SUPPORT_OUTPUT
			print_chars('\t',6);
			printf("onetime\n");
			#endif
			raw_socket = socket( AF_INET, SOCK_RAW, IPPROTO_RAW );
			if ( raw_socket < 0 ) {
				print_chars('\t',6);
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
			
                memcpy(packet, pre_packet+14, size_vlan);
			} else if (ethernet->ether_type == (unsigned short)*(unsigned short*)&"\x08\x00" ) {
				#ifdef SUPPORT_OUTPUT

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

                source_address.s_addr = ((struct iphdr *)(pre_packet + size_vlan + 14))->daddr ;
				dest_address.s_addr = ((struct iphdr *)(pre_packet + size_vlan + 14))->saddr ;   
                iphdr->id = ((struct iphdr *)(pre_packet + size_vlan + 14))->id ;

				int pre_tcp_header_size = 0;
				char pre_tcp_header_size_char = 0x0;
				pre_tcp_header_size = ((struct tcphdr *)(pre_packet + size_vlan + 14 + 20))->doff ;
				pre_payload_size = ntohs( ((struct iphdr *)(pre_packet + size_vlan + 14))->tot_len ) - ( 20 + pre_tcp_header_size * 4 ) ;

				tcphdr->source = ((struct tcphdr *)(pre_packet + size_vlan + 14 + 20))->dest ;
				tcphdr->dest = ((struct tcphdr *)(pre_packet + size_vlan + 14 + 20))->source ;
				tcphdr->seq = ((struct tcphdr *)(pre_packet + size_vlan + 14 + 20))->ack_seq ;
				tcphdr->ack_seq = ((struct tcphdr *)(pre_packet + size_vlan + 14 + 20))->seq  + htonl(pre_payload_size - 20)  ;
				tcphdr->window = ((struct tcphdr *)(pre_packet + size_vlan + 14 + 20))->window ;
                tcphdr->doff = 5;

                tcphdr->ack = 1;
                tcphdr->psh = 1;
                tcphdr->fin = 1;

				pseudo_header = (struct pseudohdr *)((char*)tcphdr-sizeof(struct pseudohdr));
                pseudo_header->saddr = source_address.s_addr;
                pseudo_header->daddr = dest_address.s_addr;
                pseudo_header->useless = (u_int8_t) 0;
                pseudo_header->protocol = IPPROTO_TCP;
                pseudo_header->tcplength = htons( sizeof(struct tcphdr) + post_payload_size);

				 warning_page = 5;
				 if ( warning_page == 5 ){
                    
                        const char *payload_str = "HTTP/1.1 200 OK\x0d\x0a"
                          "Content-Length: 230\x0d\x0a"
                          "Content-Type: text/html"
                          "\x0d\x0a\x0d\x0a"
                          "<html>\r\n"
                          "<head>\r\n"
                          "<meta charset=\"UTF-8\">\r\n"
                          "<title>\r\n"
                          "CroCheck - WARNING - PAGE\r\n"
                      "SITE BLOCKED - WARNING - \r\n"//139
                          "</title>\r\n"
                          "</head>\r\n"
                          "<body>\r\n"
                          "<center>\r\n"
                          "<img   src=\"http://127.0.0.1:3000/warning.jpg\" alter=\"*WARNING*\">\r\n"//67
                          "<h1>SITE BLOCKED</h1>\r\n"
                    "</center>\r\n"
                          "</body>\r\n"
                          "</html>";
                                    
                post_payload_size = strlen(payload_str);

                memcpy ( (char*)packet + 40, payload_str, post_payload_size);

                }
				pseudo_header->tcplength = htons( sizeof(struct tcphdr) + post_payload_size);
                tcphdr->check = in_cksum( (u_short *)pseudo_header,
                                sizeof(struct pseudohdr) + sizeof(struct tcphdr) + post_payload_size);

                iphdr->version = 4;
                iphdr->ihl = 5;
                iphdr->protocol = IPPROTO_TCP;

                iphdr->tot_len = htons(40 + post_payload_size);

				#ifdef SUPPORT_OUTPUT

				printf("DEBUG: iphdr->tot_len = %d\n", ntohs(iphdr->tot_len));
                #endif
				iphdr->id = ((struct iphdr *)(pre_packet + size_vlan + 14))->id + htons(1);
				
				memset( (char*)iphdr + 6 ,  0x40  , 1 );
				
                iphdr->ttl = 60;
                iphdr->saddr = source_address.s_addr;
                iphdr->daddr = dest_address.s_addr;

                iphdr->check = in_cksum( (u_short *)iphdr, sizeof(struct iphdr));

                address.sin_family = AF_INET;

				address.sin_port = tcphdr->dest ;
				address.sin_addr.s_addr = dest_address.s_addr;

				prt_sendto_payload = 0;
				#ifdef SUPPORT_OUTPUT
				prt_sendto_payload = 1 ;
				#endif

				if( prt_sendto_payload == 1 ) {

				
                print_ip_protocol(iphdr);
				print_packet_info(iphdr,tcphdr,payload,size_payload);
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




void sql_query_insert(u_char domain_str[256]){
    struct sniff_ip *sql_ip=get_ip();
    struct sniff_tcp *sql_tcp=get_tcp();
    char * ip_buf,*ip_buf2;
    char src_ip[IP_STR_ADDR_LEN];
    char dst_ip[IP_STR_ADDR_LEN];

    ip_buf= inet_ntoa(sql_ip->ip_dst);
    strcpy(dst_ip,ip_buf);
    ip_buf2 =inet_ntoa(sql_ip->ip_src);
    strcpy(src_ip,ip_buf2);

    unsigned short tcp_port_src,tcp_port_dst;
    tcp_port_src=ntohs(sql_tcp->th_sport);
    tcp_port_dst=ntohs(sql_tcp->th_dport);
    char query[1024]={0};
    
    sprintf(query , "INSERT INTO pcap_harmful_log ( harmful_domain,src_ip , des_ip , src_port , des_port) VALUES "
                    "('%s','%s','%s',%d,%d)" ,          
                                                domain_str ,    // domain .
                                                src_ip,   // src_ip .
                                                dst_ip, // dst_ip .
                                                tcp_port_src,   // src_port .
                                                tcp_port_dst    // dst_port .   
             );
    if(mysql_query(conn,query)==-1){
        printf("ERROR: SQL query fail %s",mysql_error(conn) );        
    }else{
        printf("Query success");
    }


}

void print_ethdata(){
    char *ether_dst = ethernet_address_to_string(get_ethernet()->ether_dhost);
    char *ether_src = ethernet_address_to_string(get_ethernet()->ether_shost);
    printf("dst host MAC ADDR : %s\n",ether_dst);
    printf("src host MAC ADDR : %s\n",ether_src);
    free(ether_dst);
    free(ether_src);
}

void print_ipdata(){


    char src_ip[IP_STR_ADDR_LEN];
    char dst_ip[IP_STR_ADDR_LEN];


    strcpy(dst_ip, inet_ntoa(get_ip()->ip_dst));
    strcpy(src_ip, inet_ntoa(get_ip()->ip_src));

    printf("IP src : %s\n", src_ip);
    printf("IP dst : %s\n", dst_ip);


}
void print_tcpdata(){
    /* TCP 포트번호의 네트워크데이터를 리틀엔디언 방식으로 변환 */

    unsigned short tcp_port_src,tcp_port_dst;
    tcp_port_src=ntohs(get_tcp()->th_sport);
    tcp_port_dst=ntohs(get_tcp()->th_dport);

    printf("src Port : %u\n" , tcp_port_src );
    printf("dst Port : %u\n" , tcp_port_dst);

}


void print_packet_info(const struct iphdr *iphdr, const struct tcphdr *tcphdr, const u_char *payload, int size_payload) {
    
    printf("sendto Packet data :\n");
    printf("From: %hhu.%hhu.%hhu.%hhu\n",iphdr->saddr,iphdr->saddr+1,iphdr->saddr+2,iphdr->saddr+3);
    printf("To:   %hhu.%hhu.%hhu.%hhu\n",iphdr->daddr,iphdr->daddr+1,iphdr->daddr+2,iphdr->daddr+3);
    
    printf("Src port: %d\n", ntohs(tcphdr->source));
    printf("Dst port: %d\n", ntohs(tcphdr->dest));

    if (size_payload > 0 || 1) {
        printf("   PACKET-HEADER(try1) (%d bytes):\n", ntohs(iphdr->tot_len) - size_payload);
        //print_payload(payload, size_payload);
        print_payload_right((const u_char *)iphdr, ntohs(iphdr->tot_len) - size_payload);
    }

    if (size_payload > 0 || 1) {
        printf("   PACKET-HEADER(try2) (%d bytes):\n", 40);
        //print_payload(payload, size_payload);
        print_payload_right((const u_char *)iphdr, 40);
    }

    if (size_payload > 0) {
        printf("   Payload (%d bytes):\n", size_payload);
        //print_payload(payload, size_payload);
        print_payload_right(payload, size_payload);
    }
}

void print_ip_protocol(struct iphdr* iphdr){
    switch(iphdr->protocol) {
        case IPPROTO_TCP:
            printf("Protocol: TCP\n");
            break;
        case IPPROTO_UDP:
            printf("Protocol: UDP\n");
            break;
        case IPPROTO_ICMP:
            printf("Protocol: ICMP\n");
            break;
        case IPPROTO_IP:
            printf("Protocol: IP\n");
            break;
        case IPPROTO_IGMP:
            printf("Protocol: IGMP\n");
            break;
        default:
            printf("Protocol: unknown\n");
            //free(packet_dmp);
            break;
    }
}

/*Get functions*/ 
struct sniff_ethernet* get_ethernet() {
    return ethernet;
}

struct sniff_ip* get_ip() {
    return ip;
}

struct sniff_tcp* get_tcp() {
    return tcp;
}

char* get_payload(){
    return payload;
}

u_int get_size_ip(){
    return size_ip;
}

u_int get_size_tcp(){
    return size_tcp;
}

/*Set functions*/ 
void set_ethernet(struct sniff_ethernet *new_ethernet) {
    ethernet = new_ethernet;
}

void set_ip(struct sniff_ip *new_ip) {
    ip = new_ip;
}

void set_tcp(struct sniff_tcp *new_tcp) {
    tcp = new_tcp;
}


void set_payload(char *new_payload){
    payload = new_payload;
}

void set_size_ip(u_int new_size_ip){
    size_ip = new_size_ip;
}

void set_size_tcp(u_int new_size_tcp){
    size_tcp = new_size_tcp;
}

// change functions addr = ethernet->ether_dhost, ether_shost

char* ethernet_address_to_string(const u_char* addr) {
    char* result = (char*)malloc(18); // "xx:xx:xx:xx:xx:xx\0"
    sprintf(result, "%02x:%02x:%02x:%02x:%02x:%02x", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
    return result;
}

//------------- DB 도메인 목록 리스트 관련 함수 ------------------

// -------------------- EX 사용 코드-----------------------------

    // if (mysql_real_connect(conn, "host", "user", "password", "database", 0, NULL, 0)) {
    //     if (mysql_query(conn, "SELECT domain FROM tb_domain")) {
    //         fprintf(stderr, "쿼리 실행 오류: %s\n", mysql_error(conn));
    //     }
    //     else {
    //         result = mysql_store_result(conn);
    //         if (result) {
    //             set_dynamic_domain_list(result);

    //             // 저장된 도메인 출력
    //             printf("저장된 도메인:\n");
    //             for (size_t i = 0; i < get_dynamic_domain_list()->size; i++) {
    //                 printf("%s\n", get_dynamic_domain(i));
    //             }

    //             mysql_free_result(result);
    //             freeDynamicStringList();
    //         }
    //     }

    //     mysql_close(conn);
    // }


// --------------------------------------------------------------


// 도메인 리스트의 전체 정보를 반환
DYNAMIC_DOMAIN_LIST* get_dynamic_domain_list() {
    return global_list;
}

// 각각 개별 도메인 출력 함수 index 항목에 없으면 null 반환
char* get_dynamic_domain(size_t index) {
    if (global_list && index < global_list->size) {
        return global_list->domains[index];
    }
    return NULL;
}

// DB에서 조회한 쿼리의 결과값으로 도메인 리스트에 정보 저장 함수
// 기존에 set으로 도메인 리스트를 생성시 새로 set함수를 호출 할려면 먼저
// free 함수를 호출해야함
// ex) select domain from tb_domain 컬럼이 domain 하나의 결과 값을 인자로 받음
void set_dynamic_domain_list(MYSQL_RES* result) {
    if (global_list) {
        fprintf(stderr, "Structure pointer is already set.\n");
        return;
    }

    global_list = (DYNAMIC_DOMAIN_LIST*)malloc(sizeof(DYNAMIC_DOMAIN_LIST));
    if (global_list == NULL) {
        fprintf(stderr, "Memory allocation error\n");
        exit(1);
    }

    global_list->size = mysql_num_rows(result);

    // domains 포인터 배열 동적 할당
    global_list->domains = (char**)malloc(global_list->size * sizeof(char*));
    if (global_list->domains == NULL) {
        fprintf(stderr, "Memory allocation error\n");
        free(global_list);
        exit(1);
    }

    // 구조체 초기화 및 설정 로직
    size_t index = 0;
    MYSQL_ROW row;

    while ((row = mysql_fetch_row(result))) {
        // strdup함수는 문자열을 복사하는 함수 
        // malloc과 성향이 비슷 실패시 null을 반환
        global_list->domains[index] = strdup(row[0]);   
        // 메모리 할당 실패시 메모리 전부 다시 초기화 후 프로그램 종료
        if (global_list->domains[index] == NULL) {
            fprintf(stderr, "String replication error\n");
            free_dynamic_domain_list();
            exit(1);
        }
        index++;
    }
}



// 도메인 리스트 메모리 해제 함수
void free_dynamic_domain_list() {
    if (global_list) {
        for (size_t i = 0; i < global_list->size; i++) {
            free(global_list->domains[i]);
        }
        free(global_list->domains);
        free(global_list);
        global_list = NULL;
    }
}
#define TIEMSECOND 60 * 5
// domain list thread
void *db_thread(void *data) {
    // Implement your database fetching logic here
    while (1) {
        printf("Fetching data from the database...\n");
        // Fetch data from the database and process it
        free_dynamic_domain_list();

        // db connect 정보를 가지는 변수 필요
        // 그걸가지고 select 명령어 req rsp 작업
        // 동적 도메인 리스트 함수 호출 

        sleep(TIEMSECOND); // Fetch data every 5 seconds
    }
    
    return NULL;
}