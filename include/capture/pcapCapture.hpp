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

/**
 * Packet capture engine based on libpcap
 *
 * Supports:
 *  - Live capture from network interface
 *  - Offline capture from .pcap file
 *  - BPF filtering
 *  - Separate capture thread (for live mode)
 *
 * Workflow:
 *  initialize()      -> load interfaces
 *  set_capabilities()-> configure capture parameters
 *  start()           -> start live capture (threaded)
 *  start_offline()   -> process file synchronously
 *  stop()            -> stop capture and cleanup
 */

class PcapCapture {
private:
	/* libpcap error buffer */
	char errbuf[PCAP_ERRBUF_SIZE];

	/* filter expression (compiled before capture) */
	std::string filter_exp = "";
	/* compiled filter program (expression) */
	struct bpf_program fp = {};
	/* Active pcap handle */
	pcap_t *handle = nullptr;

	/* Network mask and IP */
	bpf_u_int32 mask = 0;
	bpf_u_int32 net = 0;

	/* Number of packets to capture */
	int num_packets = 0;

	/* Linked list of available interfaces */
	pcap_if_t *interfaces = nullptr;

	/* Selected network interface */
	std::string interface;
	/**
	 * Static wrapper required by C-style libpcap callback.
	 *
	 * Since libpcap expects a C function pointer,
	 * we use a static function and forward the call
	 * to the class instance.
	*/
	static void callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
	// packet processing logic
	void got_packet(const struct pcap_pkthdr *header, const u_char *packet);

	/* Separate thread used for live capture */
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
	/* Pointer to statistics engine */
	Stats* stats;

	void set_capabilities(std::string& interface, int num_packets, std::string& filter_exp, int packets_limit, Stats* stats);
	void initialize();


	void start();
	void start_offline(std::string fpath);
	void stop();
};


#endif //PCAPCAPTURE_HPP
