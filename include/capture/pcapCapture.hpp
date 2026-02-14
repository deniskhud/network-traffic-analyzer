#ifndef PCAPCAPTURE_HPP
#define PCAPCAPTURE_HPP
#include <memory>
#include <queue>
#include <pcap/pcap.h>
#include <thread>
extern "C" {
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/if_ether.h>  // ether_header
#include <netinet/ip.h>        // struct ip
#include <netinet/tcp.h>       // struct tcphdr
#include <netinet/udp.h>       // struct udphdr
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/igmp.h>
#define SNAP_LEN 1518
}
#include "../packet/IP.hpp"
#include "../../include/stats/protocolStats.hpp"
#include "../packet/packet.hpp"
#include <deque>

class PacketLog {
public:
	void push(const Packet& p) {
		std::lock_guard<std::mutex> lock(mtx);
		packets.push_back(p);
		if (packets.size() > max_packets)
			packets.pop_front();
	}

	std::vector<Packet> snapshot() {
		std::lock_guard<std::mutex> lock(mtx);
		return { packets.begin(), packets.end() };
	}

private:
	std::deque<Packet> packets;
	std::mutex mtx;
	size_t max_packets = 20; // сколько пакетов показываем
};


class PcapCapture {
private:

	char errbuf[PCAP_ERRBUF_SIZE];

	std::string filter_exp = "ip or ip6 ";
	struct bpf_program fp;			/* compiled filter program (expression) */
	pcap_t *handle = nullptr;

	bpf_u_int32 mask = 0;			/* subnet mask */
	bpf_u_int32 net = 0;			/* ip */
	uint32_t num_packets = 0;

	pcap_if_t *interfaces = nullptr;

	std::string interface;

	static void callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
	void got_packet(const struct pcap_pkthdr *header, const u_char *packet);
	std::thread thread;
	std::atomic<bool> running;

public:
	void print_interfaces();
	PacketLog packet_log;
	bool isRunning() {
		return running;
	}
	Stats stats;
	void set_capabilities(std::string& interface, int num_packets, std::string& filter_exp, int packets_limit);
	void initialize();
	void start();
	void start_offline(std::string fpath);



	void stop();
};


#endif //PCAPCAPTURE_HPP
