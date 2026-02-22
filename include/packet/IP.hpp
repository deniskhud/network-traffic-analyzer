#ifndef IP_HPP
#define IP_HPP
#include <string>
#include <netinet/ip.h>
#include <netinet/igmp.h>
#include <netinet/ip6.h>
#include "packet.hpp"

/* virtual class for our IPv4, IPv6 classes */
class IP_class {
protected:
	virtual void handle_tcp() = 0;
	virtual void handle_udp() = 0;
	virtual void handle_icmp() = 0;
	virtual void handle_icmpv6() = 0;
	virtual void handle_igmp() = 0;
	uint16_t payload_len = 0;
public:
	//getters
	virtual std::string get_source() = 0;
	virtual std::string get_dest() = 0;
	virtual uint16_t get_src_port() = 0;
	virtual uint16_t get_dest_port() = 0;
	virtual TransportProtocol get_protocol() = 0;

	uint16_t get_payload_len();

	const uint8_t* payload_ptr = nullptr;
	const uint8_t* get_payload_ptr() const { return payload_ptr; }

	virtual ~IP_class() = default;

};
/*** ip4 ***/
class IPv4 : public IP_class {
private:
	const ip* ip_hdr = nullptr;
	int ip_hdr_len = 0;
	uint16_t src_port = 0;
	uint16_t dest_port = 0;
protected:
	void handle_tcp() override;
	void handle_udp() override;
	void handle_icmp() override;
	void handle_icmpv6() override;
	void handle_igmp() override;

public:
	TransportProtocol get_protocol() override;
	std::string get_source() override;
	std::string get_dest() override;
	uint16_t get_src_port() override;
	uint16_t get_dest_port() override;

	explicit IPv4(const u_char* data);
};



/*** ipv6 ***/
class IPv6 : public IP_class{
protected:
	void handle_tcp() override;
	void handle_udp() override;
	void handle_icmp() override;
	void handle_icmpv6() override;
	void handle_igmp() override;
private:
	const ip6_hdr* ip_hdr = nullptr;
	int ip_hdr_len = 40;

	in6_addr ip_source;
	in6_addr ip_dest;

	uint16_t src_port;
	uint16_t dest_port;

	const uint8_t* ptr = nullptr;

public:
	explicit IPv6(const u_char* data);

	TransportProtocol get_protocol() override;
	std::string get_source() override;
	std::string get_dest() override;
	uint16_t get_src_port() override;
	uint16_t get_dest_port() override;

};

#endif //IP_HPP
