#include "../../include/capture/pcapCapture.hpp"
#include "../../include/stats/protocolStats.hpp"


/* get a list of all available network interfaces */
void PcapCapture::initialize() {
	/*	find all devs available in network, save them to pcap_if_t struct (interfaces) */
	if (pcap_findalldevs(&interfaces, errbuf) == -1) {
		fprintf(stderr, "Error: pcap_findalldevs has been failed - %s\n", errbuf);
	}
}
/**
	 * Start live packet capture.
	 *
	 * Steps:
	 *  1. Resolve network mask
	 *  2. Open device in promiscuous mode
	 *  3. Compile and apply BPF filter (if provided)
	 *  4. Start pcap_loop in a separate thread
	*/
void PcapCapture::start() {
	// getting the netmask of the interface
	if (pcap_lookupnet(interface.c_str(), &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
			interface.c_str(), errbuf);
		net = 0;
		mask = 0;
	}

	/* open capture device */
	handle = pcap_open_live(interface.c_str(), SNAP_LEN, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "Couldn't open device %s: %s\n", interface.c_str(), errbuf);
		exit(EXIT_FAILURE);
	}

	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", interface.c_str());
		exit(EXIT_FAILURE);
	}
	if (!filter_exp.empty()) {
		/* compile the filter expression */
		if (pcap_compile(handle, &fp, filter_exp.c_str(), 0, net) == -1) {
			fprintf(stderr, "Couldn't parse filter %s: %s\n",
				filter_exp.c_str(), pcap_geterr(handle));
			exit(EXIT_FAILURE);
		}


		/* apply the compiled filter */
		if (pcap_setfilter(handle, &fp) == -1) {
			fprintf(stderr, "Couldn't install filter %s: %s\n",
				filter_exp.c_str(), pcap_geterr(handle));
			exit(EXIT_FAILURE);
		}
		pcap_freecode(&fp);
	}



	/* start a separate thread */
	running = true;
	thread = std::thread([this]() {
		if (pcap_loop(handle, num_packets, &PcapCapture::callback, reinterpret_cast<u_char*>(this)) < 0) {
			//fprintf(stderr, "Error in pcap_loop: %s\n", pcap_geterr(handle));
			//pcap_close(handle);
		}
		running = false;
	});
	
}

void PcapCapture::stop() {
	if (interfaces) {
			pcap_freealldevs(interfaces);
	}
	if (handle) {
		if (running == true) pcap_breakloop(handle);
		pcap_close(handle);
		//handle = nullptr;
	}

	if (thread.joinable()) {
		thread.join();
	}
	/*if (!filter_exp.empty()) {
		pcap_freecode(&fp);
	}*/

}
/* print all available interfaces */
void PcapCapture::print_interfaces() {
	int i = 0;
	for (pcap_if_t *dev = interfaces; dev; dev = dev->next) {
		printf("%d. %s  ",++i,  dev->name);
		if (dev->description) {
			printf("(%s)\n", dev->description);
		}
		else {
			printf("\n");
		}
	}
}
/**
 * @brief Static wrapper required by libpcap C API.
 *
 * Since libpcap expects a C-style function pointer,
 * we forward the call to the current class instance.
 *
 * @param user   Pointer to PcapCapture instance
 * @param header Packet metadata
 * @param packet Raw packet bytes
 */
void PcapCapture::callback(
	u_char* user,
	const struct pcap_pkthdr* header,
	const u_char* packet
) {
	auto* self = reinterpret_cast<PcapCapture*>(user);
	if (!self->isRunning()) return;
	self->got_packet(header, packet);
}

/**
 * @brief Parses a single captured packet.
 *
 * Responsibilities:
 *  - Parse Ethernet header
 *  - Detect IP version (IPv4 / IPv6)
 *  - Extract transport & application protocols
 *  - Construct Packet abstraction
 *  - Forward packet to Stats engine
 *
 * Only IPv4 and IPv6 are currently processed.
 * Other Ethernet types are ignored.
 */
void PcapCapture::got_packet(const struct pcap_pkthdr *header, const u_char *packet) {
	if (!running) return;

    // --- Ethernet header ---
	const auto* ethernet = reinterpret_cast<const ether_header*>(packet);
	uint16_t ether_type = ntohs(ethernet->ether_type);

	Packet packetView;

	/* if we have a ipv4 type */
	if (ether_type == ETHERTYPE_IP) {
		IPv4 ip(packet + sizeof(struct ether_header));
		TransportProtocol prot = ip.get_protocol();

		packetView = Packet(v4, prot, ip.get_source(), ip.get_dest(), ip.get_src_port(), ip.get_dest_port(), header->len, ip.get_payload_len(), ip.get_payload_ptr());
		stats->add_packet(packetView);
		stats->push(packetView);

	}
	/* ipv6 type */
	if (ether_type == ETHERTYPE_IPV6) {
		IPv6 ip(packet + sizeof(struct ether_header));
		TransportProtocol prot = ip.get_protocol();
		packetView = Packet(v6, prot, ip.get_source(), ip.get_dest(), ip.get_src_port(), ip.get_dest_port(), header->len, ip.get_payload_len(), ip.get_payload_ptr());
		stats->add_packet(packetView);
		stats->push(packetView);

	}
	if (ether_type == ETHERTYPE_VLAN) {
		ethernet = (ether_header*)(packet + 4);

	}
	if (ether_type == ETHERTYPE_ARP) {

	}
}

void PcapCapture::set_capabilities(std::string& interface, int num_packets, std::string& filter_exp, int packets_limit, Stats* stats) {
	this->interface = interface;
	this->num_packets = num_packets;
	this->filter_exp = filter_exp;
	this->stats = stats;
	this->stats->set_packets_limit(packets_limit);

}
/**
 * @brief Processes packets from an offline .pcap file.
 *
 * Differences from live mode:
 *  - Runs synchronously
 *  - No additional thread is created
 *  - Blocks until entire file is processed
 *
 * Used for post-capture analysis and exporting results.
 */
void PcapCapture::start_offline(std::string fpath) {
	handle = pcap_open_offline(fpath.c_str(), errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "Error opening offline file: %s\n", errbuf);
		return;
	}

	running = true;

	pcap_loop(handle, num_packets,
			  &PcapCapture::callback,
			  reinterpret_cast<u_char*>(this));

	running = false;
}