#include "../../include/capture/pcapCapture.hpp"
#include "../../include/stats/protocolStats.hpp"
#include "../../include/cli/cli.hpp"

/* get a list of all available network interfaces */
void PcapCapture::initialize() {
	/*	find all devs available in network, save them to pcap_if_t struct (interfaces) */
	if (pcap_findalldevs(&interfaces, errbuf) == -1) {
		fprintf(stderr, "Error: pcap_findalldevs has been failed - %s\n", errbuf);
	}
}

void PcapCapture::start() {
	// getting the netmask of the interface
	if (pcap_lookupnet(interface.c_str(), &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
			interface, errbuf);
		net = 0;
		mask = 0;
	}

	/* open capture device */
	handle = pcap_open_live(interface.c_str(), SNAP_LEN, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
		exit(EXIT_FAILURE);
	}

	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", interface);
		exit(EXIT_FAILURE);
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp.c_str(), 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
			filter_exp.c_str(), pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}


	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
			filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
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

	if (handle) {
		if (running == true) pcap_breakloop(handle);
		pcap_close(handle);
		handle = nullptr;
	}

	if (thread.joinable()) {
		thread.join();
	}
	if (filter_exp != "") {
			pcap_freecode(&fp);
	}

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

void PcapCapture::callback(
	u_char* user,
	const struct pcap_pkthdr* header,
	const u_char* packet
) {
	auto* self = reinterpret_cast<PcapCapture*>(user);
	if (!self->isRunning()) return;
	self->got_packet(header, packet);
}

void PcapCapture::got_packet(const struct pcap_pkthdr *header, const u_char *packet) {
	if (!running) return;
	static int count = 1;



    // --- Ethernet header ---
    const struct ether_header* ethernet = (struct ether_header*)packet;
	uint16_t ether_type = ntohs(ethernet->ether_type);

	Packet packetView;

	/* if we have a ipv4 type */
	if (ether_type == ETHERTYPE_IP) {
		IPv4 ip((u_char*)(packet) + sizeof(struct ether_header));
		TransportProtocol prot = ip.get_protocol();

		packetView = Packet(v4, prot, ip.get_source(), ip.get_dest(), ip.get_src_port(), ip.get_dest_port(), header->len, ip.get_payload_len(), ip.get_payload_ptr());
		stats->add_packet(packetView);
		stats->push(packetView);

	}
	/* ipv6 type */
	if (ether_type == ETHERTYPE_IPV6) {
		IPv6 ip((u_char*)(packet) + sizeof(struct ether_header));
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

void PcapCapture::start_offline(std::string fpath) {
	running = true;
	handle = pcap_open_offline(fpath.c_str(), errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Error opening offline file: %s\n", errbuf);
		return;
	}
	thread = std::thread([this]() {
			if (pcap_loop(handle, num_packets, &PcapCapture::callback, reinterpret_cast<u_char*>(this)) < 0) {
				fprintf(stderr, "Error in pcap_loop: %s\n", pcap_geterr(handle));
				//pcap_close(handle);

			}
			running = false;
	});

}