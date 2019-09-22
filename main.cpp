#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <string.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  uint16_t src_port, dest_port;
  unsigned char data[32];

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;


    //print mac address.
    unsigned char src_mac[6], dest_mac[6];

    memcpy(src_mac, packet+6, 6);
    memcpy(dest_mac, packet, 6);
    printf("Source mac is %x:%x:%x:%x:%x:%x and destination mac is %x:%x:%x:%x:%x:%x\n", src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5], dest_mac[0], dest_mac[1], dest_mac[2], dest_mac[3], dest_mac[4], dest_mac[5]);


    //print ip address.
    unsigned char is_ip[2];
    unsigned char ip_check[2] = {0x08, 0x00};

    memcpy(is_ip, packet+12, 2);
    if(!memcmp(is_ip, ip_check, 2)) {
      unsigned char ip1[4], ip2[4];
      memcpy(ip1, packet+26, 4);
      memcpy(ip2, packet+30, 4);

      printf("Source ip is %d.%d.%d.%d and destination ip is %d.%d.%d.%d\n", ip1[0], ip1[1], ip1[2], ip1[3], ip2[0], ip2[1], ip2[2], ip2[3]);
    

      //print tcp port.
      unsigned char is_tcp[1];
      unsigned char tcp_check[1] = {0x06};

      memcpy(is_tcp, packet+23, 1);
      if(!memcmp(is_tcp, tcp_check, 1)) {
        unsigned char port1[2], port2[2];
        memcpy(port1, packet+34, 2);
        uint16_t* src_port = (uint16_t*) port1;
        memcpy(port2, packet+36, 2);
        uint16_t* dest_port = (uint16_t*) port2;
        printf("Source port is %d and destination port is %d", ntohs(*src_port), ntohs(*dest_port));    //network order to host order.


        //print real data.
        int ip_header = (int)(packet[14] & 0x0f) * 5;
        int tcp_header = (int)((packet[14 + ip_header + 12] & 0xf0) >> 4) * 5;
        if(header->len > tcp_header + 32) {
          int header_length = 14 + ip_header + tcp_header;
          unsigned char data[32];
          memcpy(data, packet+header_length, 32);
          for(int i = 0; i < 32; i++) {
            if(i == 0)
              printf("\nThe data from the first 32 bytes is %x", data[i]);
            else
              printf("%x", data[i]);
          }
        }
        printf("\n");
      }
    }
    printf("=============================================================================\n");
  }
  
  pcap_close(handle);
  return 0;
}

