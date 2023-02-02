#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
// #include <pthread.h>

typedef struct IpHeader {
    unsigned char hl:4, ver:4;
    unsigned char tos;
    unsigned short total_len;
    unsigned short id;
    unsigned short fragment_offset:13, flags:3;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short checksum;
    u_int32_t source_addr;
    u_int32_t dest_addr;
} IpHeader;

typedef struct TcpHeader {
    unsigned short sport;
    unsigned short destport;
    u_int32_t seqnum;
    u_int32_t acknum;
    unsigned char reserved:4, dataoffset:4;
    unsigned char fin:1;
    unsigned char syn:1;
    unsigned char rst:1;
    unsigned char psh:1;
    unsigned char ack:1;
    unsigned char urg:1;
    unsigned char ece:1;
    unsigned char cwr:1;
    unsigned short window;
    unsigned short checksum;
    unsigned short urg_pointer;

} TcpHeader; 

typedef struct PseudoHeader {
    u_int32_t source_ip;
    u_int32_t dest_ip;
    unsigned char zero;
    unsigned char protocol;
    unsigned short total_len;
    TcpHeader tcp;
} PseudoHeader;

ushort in_cksum(unsigned short *addr, int len) {
    int sum = 0;
    u_short answer = 0;
    u_short *w = addr;
    int nleft = len;

    while (nleft > 1)  {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1) {
        *(u_char *)(&answer) = *(u_char *)w ;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
    sum += (sum >> 16);                     /* add carry */
    answer = ~sum;                          /* truncate to 16 bits */
    return(answer);
}

int packet_create_and_send(int socket, struct sockaddr_in* source, struct sockaddr_in* dest_addr, unsigned short dest_port) {
    char datagram[1000];
    memset(datagram, 0, 1000);
    dest_addr->sin_port = dest_port; /* set destination address port to scanning port */

    /* place TcpHeader in datagram */
    TcpHeader *tcp_hdr = (TcpHeader *)(datagram); 
    PseudoHeader ps_hdr;
    
    /* fill tcp header and pseudo header and calculate checksum */
    tcp_hdr->sport = source->sin_port;
    tcp_hdr->destport = htons(dest_port);
    tcp_hdr->seqnum = htonl(1);
    tcp_hdr->acknum = 0;
    tcp_hdr->dataoffset = 5;
    tcp_hdr->syn = 1; // send syn
    tcp_hdr->window= htons(5840);
    tcp_hdr->urg_pointer = 0;

    /* pseudo_header */
    ps_hdr.source_ip = source->sin_addr.s_addr;
    ps_hdr.dest_ip = dest_addr->sin_addr.s_addr;
    ps_hdr.zero = 0;
    ps_hdr.protocol = IPPROTO_TCP;
    ps_hdr.total_len = htons(sizeof(TcpHeader));
    ps_hdr.tcp = *tcp_hdr;
    tcp_hdr->checksum = in_cksum((unsigned short *)&ps_hdr, sizeof(struct PseudoHeader));

    int bytessent;
    if ((bytessent = sendto(socket, datagram, sizeof(TcpHeader), 0, (struct sockaddr *)dest_addr, sizeof(*dest_addr))) < 0) {
        return -1;
    }

    return 0;

}

/* TODO: Make the processing more thorough to identify whether or not port is filtered or closed */
/* TODO: Possibly run in a seperate thread */
int packet_recv_and_process(int socket, unsigned char *buffer, int buffer_size, struct sockaddr_in *source_addr, 
        unsigned short port_current, unsigned short ports_open[65535], unsigned short *ports_open_index) {

    memset(buffer, 0, buffer_size);
    struct sockaddr_in dest_addr;
    socklen_t dest_addr_len = sizeof(struct sockaddr_in);
    int bytesrecv;
    bytesrecv = recvfrom(socket, buffer, buffer_size, MSG_DONTWAIT, (struct sockaddr *)&dest_addr, &dest_addr_len);
    if (bytesrecv < 0) {
        /* if no data received then resend packet */
        if (errno == EWOULDBLOCK || errno == EAGAIN) {
            return 0; /* port could be filtered or packet could have not reached destination */
        }
        else {
            printf("error receiving packets %d", errno);
            return 0;
        }
    }
    IpHeader *ip_hdr = (IpHeader *)buffer;
    TcpHeader *tcp_hdr = (TcpHeader *)(buffer + sizeof(IpHeader)); // IpHeader and TcpHeader copied into response buffer

    /* if not our adress not our packet */
    if (ip_hdr->dest_addr != source_addr->sin_addr.s_addr) {
        return 0;
    }
    
    /* if not our port not our packet */
    if (tcp_hdr->destport != source_addr->sin_port) {
        return 0;
    }
     
    /* if syn and ack flag are set in the response then port is open */
    if (tcp_hdr->syn && tcp_hdr->ack) {
        ports_open[(*ports_open_index)++] = port_current;
    }
    
    return 1;
}

int main(int argc, char *argv[]) {
    /* TODO check if padding in struct matters when sending datagram */
    char packet_data[30]; /* packet should only be 20 bytes extra 10 bytes to account for padding */
    unsigned char incomingdatagram[65535];
    int error; /* for errno */

    /* TODO: Make array somewhat dynamic by allocating something small and then allocating more as needed */
    /* allocate an array equal to maximum number of ports that could be open (65535)
     * then keep an index that increments every time a port is added to the open ports list
     * this is a very rudimentary implementation of a dynamically sized array except its not really dynamic
     */


    unsigned short ports_open[65535];
    unsigned short ports_open_index = 0;
    memset(packet_data, 0, 20);
    memset(ports_open, 0, 65535);

    struct addrinfo hints = {}, *result;

    /* TODO make ports parametrisable in arguments, need to write a parser */
    unsigned short client_port = 50000;
    unsigned short port_current = 1; /* set current port to scan to start port */
    unsigned short end_port = 150;

    /* fill out hints to find ipv4 address from name */
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_RAW;
    hints.ai_protocol = IPPROTO_TCP;

    if ((error = getaddrinfo(argv[1], 0, &hints, &result)) < 0) {
        printf("couldnt find address error: %d\n", error);
        return 1;
    }

    int socket_scan;
    if((socket_scan = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
        printf("SOCKET_ERROR %d", errno);
        return 1;
    }

    struct sockaddr_in client_addr = {};
    socklen_t client_addr_size = sizeof(client_addr);
    struct sockaddr_in dns_server_addr = {};
    struct sockaddr_in *server_addr = &dns_server_addr;

    /* first make connection with google dns server to find host machine ip */
    dns_server_addr.sin_family = AF_INET;
    dns_server_addr.sin_addr.s_addr = inet_addr("8.8.8.8");
    dns_server_addr.sin_port = htons(53);
    
    int socket_find_local_ip = socket(AF_INET, SOCK_DGRAM, 0);
    int err = connect(socket_find_local_ip, (struct sockaddr *)server_addr, sizeof(*server_addr));
    err = getsockname(socket_find_local_ip, (struct sockaddr *)&client_addr, &client_addr_size); 
    close(socket_find_local_ip);

    /* change server_addr to point to the results of getaddrinfo instead of google dns server */
    server_addr = (struct sockaddr_in *)result->ai_addr;

    /* main scanning loop */
    for (;port_current <= end_port; port_current++) {  
        /* if couldnt recv packet then send again 3 times */
        for (int retry = 0; retry < 3; retry++) {
            printf("port %d closed\n", port_current);
            packet_create_and_send(socket_scan, &client_addr, server_addr, port_current);
            usleep(15000); /* waiting for response and gives kernel time to clear send buffer */
            if (packet_recv_and_process(socket_scan, incomingdatagram, 65535, &client_addr, port_current, ports_open, &ports_open_index)) {
                break;
            }
        }
    }

    for (int i = 0;i < sizeof(ports_open);i++) {
        if (ports_open[i] == 0) {
            break;
        }
        printf("port %d open\n", ports_open[i]);
    }
   
    return 0;
}
