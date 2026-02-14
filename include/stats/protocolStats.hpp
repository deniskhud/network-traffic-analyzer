#ifndef PROTOCOLSTATS_HPP
#define PROTOCOLSTATS_HPP
#include <chrono>
#include <cstdint>

#include "../packet/packet.hpp"
#include <unordered_map>
#include <filesystem>
#include <fstream>
#include <map>
#include <queue>

#include "ftxui/dom/elements.hpp"
using namespace ftxui;
struct protocolStats {
	uint32_t packets = 0;
	uint32_t bytes = 0;
};

struct trafficStats {
	uint32_t total_packets = 0;
	uint32_t total_bytes = 0;
};

struct IPStats {
	uint32_t bytes_sent = 0;
	uint32_t bytes_received = 0;

	uint32_t packets_sent = 0;
	uint32_t packets_received = 0;
};

struct BandwidthPoint {
	double timestamp;
	double bytes_per_sec;
};

class Stats {
private:
	std::mutex mtx;
	uint32_t total_p = 0, total_b = 0;

	uint32_t last_b = 0;

	std::chrono::steady_clock::time_point last_tick;


	std::unordered_map<TransportProtocol, protocolStats> transport_map;
	std::unordered_map<ApplicationProtocol, protocolStats> application_map;
	std::unordered_map<std::string, IPStats> ip_map;

	std::map<std::pair<std::string, std::string>, protocolStats> pairs;

	std::vector<BandwidthPoint> bandwidth_history;

	std::deque<Packet> packets;
	int limit_packets = 10;


public:
	void push(const Packet& p) {
		std::lock_guard<std::mutex> lock(mtx);
		if (packets.size() > limit_packets) {
			packets.pop_front();
		}
		packets.push_back(p);
	}
	double bandwidth = 0;

	void update_bandwidth();
	double smooth_value(size_t i, size_t start);
	double smooth_bandwidth = 0.0;

	void set_packets_limit(int limit) {
		limit_packets = limit;
	}

	void add_packet(Packet &packet);
	ftxui::Element print_stats();

	std::vector<std::vector<std::string>> transport_rows;
	void update_transport_stats();
	ftxui::Element print_transport_stats();

	std::vector<std::vector<std::string>> app_rows;
	void update_application_stats();
	ftxui::Element print_application_stats();

	std::vector<std::vector<std::string>> rows;
	void update_ip_stats(size_t limit);
	ftxui::Element print_ip_stats(size_t limit);

	std::vector<std::vector<std::string>> pairs_rows;
	void update_pairs(size_t limit = 10);
	ftxui::Element print_pairs(size_t limit = 10);
	Element print_bandwidth();
	Element print_packets();

	void export_csv(const std::string& filename);
	void export_json(const std::string& filename);

	std::vector<std::vector<std::string>> packets_rows;
	void update_packets();

	Stats();
};



#endif //PROTOCOLSTATS_HPP
