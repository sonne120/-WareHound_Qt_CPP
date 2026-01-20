	#pragma once
#ifndef PACKAGES_H
#define PACKAGES_H

// Platform specific includes
#ifdef _WIN32
#include <WinSock2.h>
#include <windows.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <unistd.h>
typedef void* HANDLE;
#endif
#include <pcap.h>
#include <vector>
#include <string>
#include <atomic>
#include <mutex>
#include <list>
#include <iostream>
#include <cstdint>

#include "struct.h"
#include "ipc.h"
#include "handleProto.h"
#include "ether_ntoa.h"

#ifdef __APPLE__
// Ensure ETHER_HDR_LEN exists
#ifndef ETHER_HDR_LEN
#define ETHER_HDR_LEN 14
#endif
#endif

// Provide cross-platform aliases used in code
#ifndef SIZE_ETHERNET
#define SIZE_ETHERNET ETHER_HDR_LEN
#endif
#ifndef IPv4_ETHERTYPE
#define IPv4_ETHERTYPE ETHERTYPE_IP
#endif

// IP header helpers expected by code
#ifndef IP_HL
#define IP_HL(ip) ((ip)->ip_hl)
#endif
#ifndef IP_V
#define IP_V(ip) ((ip)->ip_v)
#endif

// Some code uses ip_vhl (Linux/Windows). On BSD/macOS map to ip_hl
#ifdef __APPLE__
#ifndef ip_vhl
#define ip_vhl ip_hl
#endif
#endif

// Portable TCP/UDP header definitions to avoid platform-specific field names
struct sniff_tcp {
    uint16_t th_sport;   // source port
    uint16_t th_dport;   // destination port
    uint32_t th_seq;
    uint32_t th_ack;
    uint8_t  th_offx2;   // data offset, rsvd
    uint8_t  th_flags;
    uint16_t th_win;
    uint16_t th_sum;
    uint16_t th_urp;
};

struct sniff_udp {
    uint16_t uh_sport;   // source port
    uint16_t uh_dport;   // destination port
    uint16_t uh_len;
    uint16_t uh_sum;
};

#ifdef _WIN32
#pragma warning(disable:4996)
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "Packet.lib")
#endif

#define buff_max 5
#define mod %

extern std::mutex mtx;

class Packages
{
public:
	Packages();
	Packages(handleProto p);
	~Packages();
	// void* producer(std::atomic<bool>& on); // Removed deprecated
	// void* consumer(std::atomic<bool>* running = nullptr); // Removed deprecated 
	void setHandler(HANDLE eventHandle);
	void addToStruct(char proto[22], char packet_srcip[22], char packet_dstip[22], char source_mac[32], char dest_mac[32], int packet_id, int dst_port, int src_port,const char* host_names,tagSnapshot& item);
	void defaultToStruct(tagSnapshot& item);
	handleProto _proto;

private:
	HANDLE _eventHandles;
	char proto;
	char* protoh;
	char new_proto[22];
public:
	int  src_port;
	int  dst_port;
	int* src_porth;
	int* dst_porth;
};

// Inline implementations
inline Packages::Packages():src_port(0),dst_port(0),src_porth(&src_port),dst_porth(&dst_port), _eventHandles(nullptr), protoh(&proto),proto('\0')
{
	_proto.p = &_proto;
	_proto._src_port = &src_port;
	_proto._dst_port = &dst_port;
	_proto.protoStr = &proto;
	_proto.initialize();
}

inline Packages::Packages(handleProto pp) :_proto(&_proto) {
	_proto._dst_port = &dst_port;
	_proto._src_port = &src_port;
	_proto.protoStr = &proto;
	src_porth = &src_port;
	dst_porth = &dst_port;
	protoh = &proto;
};

inline Packages ::~Packages() {
	_eventHandles = NULL;
};

inline void Packages::setHandler(HANDLE eventHandle) {
	_eventHandles = eventHandle;
}

// Legacy functions removed. New architecture uses Sniffer.h/Sniffer.cpp

inline void Packages::addToStruct(char proto[22], char packet_srcip[22], char packet_dstip[22], char source_mac[32],
	char dest_mac[32], int packet_id, int dst_port, int src_port, const char* host_names, tagSnapshot& item)
{
	strcpy(item.proto, proto);
	strcpy(item.source_ip, packet_srcip);
	strcpy(item.dest_ip, packet_dstip);
	strcpy(item.source_mac, source_mac);
	strcpy(item.dest_mac, dest_mac);
	item.id = packet_id;
	item.dest_port = dst_port;
	item.source_port = src_port;
	strcpy(item.host_name, host_names);
};
inline void Packages::defaultToStruct(tagSnapshot& item) {

	item.id = 1000;
	strcpy(item.source_ip, "192.168.1.1");
	strcpy(item.dest_ip, "192.168.1.100");
	strcpy(item.source_mac, "ff:ff:ff:ff:ff:ff");
	strcpy(item.dest_mac, "ff:ff:ff:ff:ff:ff");
	item.dest_port = 8080;
	item.source_port = 8081;
	strcpy(item.host_name, "no found");
};

#endif // PACKAGES_H
