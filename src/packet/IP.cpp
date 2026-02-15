#include "../../include/packet/IP.hpp"

#include <cstdio>
#include <arpa/inet.h>
#include <netinet/icmp6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

uint16_t IP_class::get_payload_len() {
	return payload_len;
}


/*** Ipv4 ***/
IPv4::IPv4(u_char* data) {
	ip_hdr = reinterpret_cast<ip*>(data);
	ip_hdr_len = ip_hdr->ip_hl * 4;
	if (ip_hdr_len < 20) {
		fprintf(stderr, "Failed to initial IPv4 ");
	}


}

TransportProtocol IPv4::get_protocol() {

	switch (ip_hdr->ip_p) {
		case IPPROTO_TCP:
			handle_tcp();
			return TransportProtocol::TCP;

		case IPPROTO_UDP:
			handle_udp();
			return TransportProtocol::UDP;

		case IPPROTO_ICMP:
			handle_icmp();
			return TransportProtocol::ICMP;

		case IPPROTO_ICMPV6:
			handle_icmpv6();
			return TransportProtocol::ICMP6;

		case IPPROTO_IGMP:
			handle_igmp();
			return TransportProtocol::IGMP;

		default:
			return TransportProtocol::UNKNOWN;
	}
}
void IPv4::handle_tcp() {
	auto* tcp = reinterpret_cast<tcphdr*>((u_char*)ip_hdr + ip_hdr_len);

	src_port = ntohs(tcp->source);
	dest_port = ntohs(tcp->dest);

	payload_ptr = (u_char*)tcp + tcp->doff * 4;

	payload_len = ntohs(ip_hdr->ip_len) - (ip_hdr_len + tcp->doff * 4);
}
void IPv4::handle_udp() {
	auto* udp = reinterpret_cast<udphdr*>((u_char*)ip_hdr + ip_hdr_len);
	dest_port = ntohs(udp->dest);
	src_port = ntohs(udp->source);

	payload_ptr = (u_char*)udp + sizeof(udphdr);
	payload_len = ntohs(udp->len) - sizeof(udphdr);
}
void IPv4::handle_icmp() {
	auto* icmp = reinterpret_cast<icmphdr*>((u_char*)ip_hdr + ip_hdr_len);


}
void IPv4::handle_icmpv6() {
	auto* icmp = reinterpret_cast<icmp6_hdr*>((u_char*)ip_hdr + ip_hdr_len);

}
void IPv4::handle_igmp() {
	auto* igmp = reinterpret_cast<struct igmp*>((u_char*)ip_hdr + ip_hdr_len);

}

std::string IPv4::get_source() {
	return std::string(inet_ntoa(ip_hdr->ip_src));
}
std::string IPv4::get_dest() {
	return std::string(inet_ntoa(ip_hdr->ip_dst));
}
uint16_t IPv4::get_src_port() {
	return src_port;
}
uint16_t IPv4::get_dest_port() {
	return dest_port;
}

/*** Ipv6 ***/

IPv6::IPv6(u_char* data) {
	ip_hdr = reinterpret_cast<ip6_hdr*>(data);

}

TransportProtocol IPv6::get_protocol() {
	uint8_t hdr = ip_hdr->ip6_nxt;

	ptr = reinterpret_cast<const uint8_t*>(ip_hdr + 1);
	while (true) {
		switch (hdr) {
			case IPPROTO_TCP:
				handle_tcp();
				return TransportProtocol::TCP;

			case IPPROTO_UDP:
				handle_udp();
				return TransportProtocol::UDP;

			case IPPROTO_ICMP:
				handle_icmp();
				return TransportProtocol::ICMP;

			case IPPROTO_ICMPV6:
				handle_icmpv6();
				return TransportProtocol::ICMP6;

			case IPPROTO_IGMP:
				handle_igmp();
				return TransportProtocol::IGMP;
				/* if we have an extension headers, dont leave from loop,
				 * keep find a protocol type
				 */
			case IPPROTO_HOPOPTS:
			case IPPROTO_ROUTING:
			case IPPROTO_DSTOPTS: {
				const auto* ext = reinterpret_cast<const ip6_ext*>(ptr);
				hdr = ext->ip6e_nxt;
				ptr += (ext->ip6e_len + 1) * 8;
				break;
			}
			case IPPROTO_FRAGMENT: {

				const auto* frag = reinterpret_cast<const ip6_frag*>(ptr);
				hdr = frag->ip6f_nxt;
				ptr += sizeof(ip6_frag);
				break;
			}
			default:
				return TransportProtocol::UNKNOWN;
		}
	}
	ptr = nullptr;
}

void IPv6::handle_tcp() {
	const auto tcp = reinterpret_cast<const tcphdr*>(ptr);
	dest_port = ntohs(tcp->dest);
	src_port = ntohs(tcp->source);
	/*printf("tcp dst %d\n", dest_port);
	printf("tcp src %d\n", src_port);*/
	payload_ptr = (const uint8_t*)tcp + tcp->doff * 4;
	payload_len = ntohs(ip_hdr->ip6_plen) - tcp->doff * 4;

	ptr = nullptr;

}
void IPv6::handle_udp() {
	const auto udp = reinterpret_cast<const udphdr*>(ptr);
	dest_port = ntohs(udp->dest);
	src_port = ntohs(udp->source);

	payload_ptr = (const uint8_t*)udp + sizeof(udphdr);
	payload_len = ntohs(udp->len) - sizeof(udphdr);

	ptr = nullptr;

}
void IPv6::handle_icmp() {

	ptr = nullptr;
}
void IPv6::handle_icmpv6() {
	payload_len = ntohs(ip_hdr->ip6_plen) - sizeof(icmp6_hdr);
	ptr = nullptr;
}
void IPv6::handle_igmp() {

	ptr = nullptr;
}

std::string IPv6::get_source() {
	char src[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &ip_hdr->ip6_src, src, sizeof(src));
	return std::string(src);
}

std::string IPv6::get_dest() {
	char dst[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &ip_hdr->ip6_dst, dst, sizeof(dst));
	return std::string(dst);
}

uint16_t IPv6::get_src_port() {
	return src_port;
}

uint16_t IPv6::get_dest_port() {
	return dest_port;
}



