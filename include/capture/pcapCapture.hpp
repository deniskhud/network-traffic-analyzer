#ifndef PCAPCAPTURE_HPP
#define PCAPCAPTURE_HPP

#include <memory>
#include <queue>
#include <pcap/pcap.h>
#include <thread>
#include <deque>

//include C libraries
extern "C" {
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/igmp.h>
#define SNAP_LEN 1518
}

#include "../packet/IP.hpp"
#include "../../include/stats/protocolStats.hpp"
#include "../packet/packet.hpp"

/* our class for capture packets using PCap library */
class PcapCapture {
private:

	char errbuf[PCAP_ERRBUF_SIZE];

	std::string filter_exp = " ";
	struct bpf_program fp;			/* compiled filter program (expression) */
	pcap_t *handle = nullptr;

	bpf_u_int32 mask = 0;			/* subnet mask */
	bpf_u_int32 net = 0;			/* ip */
	int num_packets = 0;

	pcap_if_t *interfaces = nullptr;

	std::string interface;
	/* we create a static callback function because C libraries cant work with class methods, then
	 * we use a static function(its just a function with namespace)
	 */
	static void callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
	// packet processing logic
	void got_packet(const struct pcap_pkthdr *header, const u_char *packet);
	// separate thread for capture
	std::thread thread;
	std::atomic<bool> running{false};

public:
	void print_interfaces();

	bool isRunning() {
		return running;
	}
	void setRunning(bool running) {
		this->running = running;
	}

	Stats* stats;

	void set_capabilities(std::string& interface, int num_packets, std::string& filter_exp, int packets_limit, Stats* stats);
	void initialize();
	void start();
	void start_offline(std::string fpath);
	void stop();
};


#endif //PCAPCAPTURE_HPP
