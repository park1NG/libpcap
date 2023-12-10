#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> 
#include <netinet/ip.h> 
#include <netinet/tcp.h> 

void print_mac_address(u_char *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  struct ether_header *eth = (struct ether_header *)packet;

  if (ntohs(eth->ether_type) == ETHERTYPE_IP) { // Check if it is an IP packet
    printf("Src MAC: ");
    print_mac_address(eth->ether_shost);
    printf("Dst MAC: ");
    print_mac_address(eth->ether_dhost);

    struct iphdr *ip = (struct iphdr *)(packet + ETHER_HDR_LEN);
    
    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];
    
    inet_ntop(AF_INET, &(ip->saddr), src_ip_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip->daddr), dst_ip_str, INET_ADDRSTRLEN);

    printf("Src IP: %s\n", src_ip_str);
    printf("Dst IP: %s\n", dst_ip_str);

     /* determine protocol */
     switch(ip->protocol) {
        case IPPROTO_TCP:
            {
                struct tcphdr* tcp = (struct tcphdr*)(packet + ETHER_HDR_LEN + ip->ihl*4); // ihl is in 4-byte units

                printf("Src Port: %d\n", ntohs(tcp->source));
                printf("Dst Port: %d\n", ntohs(tcp->dest));

                // Print the message data (payload)
                int header_size = ETHER_HDR_LEN + ip->ihl*4 + tcp->doff*4;
                int data_length = ntohs(ip->tot_len) - ip->ihl*4 - tcp -> doff*4;
                
                if(data_length > 0){
                    u_char *data = (u_char *)(packet + header_size);
                    for(int i=0; i<data_length; i++) {
                        putchar(data[i]);
                    }
                    putchar('\n');
                 }
                
                break;
            }
        default:
            break;
     }
  }
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp";
  bpf_u_int32 net;

   // Step 1: Open live pcap session on NIC with name enp0s3
   handle = pcap_open_live("lo", BUFSIZ, 1, -1, errbuf); 

   // Step 2: Compile filter_exp into BPF psuedo-code
   pcap_compile(handle, &fp, filter_exp ,0 ,net);      
   if(pcap_setfilter(handle,&fp)==-1){ 
      fprintf(stderr,"Error setting filter :%s",pcap_geterr(handle));
      return 1;
   }

   // Step 3: Capture packets
   pcap_loop(handle, -1, got_packet, NULL);

   pcap_close(handle); //Close the handle 

   return 0;
}

