#include "../../include/stats/protocolStats.hpp"

#include "ftxui/dom/table.hpp"


Stats::Stats() {
	last_tick = std::chrono::steady_clock::now();
}

void Stats::update_bandwidth() {
	std::lock_guard<std::mutex> lock(mtx);
	using namespace std::chrono;

	auto now = steady_clock::now();
	double ts = duration_cast<duration<double>>(now.time_since_epoch()).count();
	double elapsed = duration_cast<duration<double>>(now - last_tick).count();

	if (elapsed >= 1.0) {

		uint32_t delta_bytes = total_b - last_b;

		bandwidth = delta_bytes / elapsed; // bytes per second

		last_b = total_b;
		last_tick = now;
		const double alpha = 0.2; // чем меньше — тем плавнее
		smooth_bandwidth =
			alpha * bandwidth + (1.0 - alpha) * smooth_bandwidth;

		bandwidth_history.push_back({ ts, smooth_bandwidth });
		//bandwidth_history.push_back({ ts, bandwidth });
	}
}




void Stats::add_packet(Packet &packet) {
	std::lock_guard<std::mutex> lock(mtx);

	++total_p;
	total_b += packet.total_len;

	auto& t = transport_map[packet.transport_protocol];
	t.packets++;
	t.bytes += packet.total_len;

	auto& a = application_map[packet.application_protocol];
	a.packets++;
	a.bytes += packet.payload_len;

	ip_map[packet.src].packets_sent++;
	ip_map[packet.src].bytes_sent += packet.total_len;

	ip_map[packet.dst].packets_received++;
	ip_map[packet.dst].bytes_received += packet.total_len;

	auto key = std::make_pair(packet.src, packet.dst);
	pairs[key].packets++;
	pairs[key].bytes += packet.total_len;

}


const char* transport_to_str(TransportProtocol p) {
	switch (p) {
		case TransportProtocol::TCP:   return "TCP";
		case TransportProtocol::UDP:   return "UDP";
		case TransportProtocol::ICMP:  return "ICMP";
		case TransportProtocol::ICMP6: return "ICMP6";
		case TransportProtocol::IGMP:  return "IGMP";
		default:                       return "UNKNOWN";
	}
}

const char* app_to_str(ApplicationProtocol p) {
	switch (p) {
		case ApplicationProtocol::HTTP:  return "HTTP";
		case ApplicationProtocol::HTTPS: return "HTTPS";
		case ApplicationProtocol::DNS:   return "DNS";
		case ApplicationProtocol::FTP:   return "FTP";
		case ApplicationProtocol::SSH:   return "SSH";
		case ApplicationProtocol::SMTP:  return "SMTP";
		case ApplicationProtocol::QUIC:  return "QUIC";
		case ApplicationProtocol::NTP:   return "NTP";
		default:                         return "UNKNOWN";
	}
}



ftxui::Element Stats::print_stats() {
	std::lock_guard<std::mutex> lock(mtx);
	return vbox({
		text("=== Traffic summary ===") | bold,
		text("Total packets: " + std::to_string(total_p)),
		text(std::format(
			"Total bytes  : {:.2f} MB",
			total_b / (1024.0 * 1024.0)
		))
	}) | flex;
}

void Stats::update_transport_stats() {
	std::lock_guard<std::mutex> lock(mtx);
	transport_rows.clear();
	transport_rows.push_back({ "Proto", "Packets", "Bytes", "%" });

	std::vector<std::pair<TransportProtocol, protocolStats>> tps(
		transport_map.begin(), transport_map.end()
	);
	std::sort(tps.begin(), tps.end(),
		[](auto& a, auto& b) {
			return a.second.packets > b.second.packets;
		});

	for (const auto& [proto, stats] : tps) {
		double percent = total_b ? stats.bytes * 100.0 / total_b : 0.0;
		transport_rows.push_back({
			transport_to_str(proto),
			std::to_string(stats.packets),
			std::format("{:.2f}", stats.bytes / (1024.0 * 1024.0)),
			std::format("{:.2f}", percent)
		});

	}
}

ftxui::Element Stats::print_transport_stats() {
	std::lock_guard<std::mutex> lock(mtx);

	Table table(transport_rows);
	table.SelectAll().Border(LIGHT);

	//table.SelectColumn(0).Border(LIGHT);
	table.SelectRow(0).Decorate(bold);
	table.SelectRow(0).SeparatorVertical(LIGHT);
	table.SelectRow(0).Decorate(bold);
	table.SelectRow(0).Border(DOUBLE);

	return vbox({
		text("=== Transport protocols === ") | bold,
		table.Render()
	}) | size(HEIGHT, EQUAL, 30);
	/*return vbox(rows) | border;*/
}

void Stats::update_application_stats() {
	std::lock_guard<std::mutex> lock(mtx);
	std::vector<std::pair<ApplicationProtocol, protocolStats>> apps(
		application_map.begin(), application_map.end()
	);

	std::sort(apps.begin(), apps.end(),
		[](auto& a, auto& b) {
			return a.second.packets > b.second.packets;
		});

	app_rows.clear();
	app_rows.push_back({ "Proto", "Packets", "Bytes (MB)", "%" });

	for (const auto& [proto, s] : apps) {
		double percent = total_b
			? s.bytes * 100.0 / total_b
			: 0.0;

		app_rows.push_back({
			app_to_str(proto),
			std::to_string(s.packets),
			std::format("{:.2f}", s.bytes / (1024.0 * 1024.0)),
			std::format("{:.2f}", percent)
		});
	}
}

ftxui::Element Stats::print_application_stats() {
	std::lock_guard<std::mutex> lock(mtx);

	Table table(app_rows);
	table.SelectAll().Border(LIGHT);

	//table.SelectColumn(0).Border(LIGHT);
	table.SelectRow(0).Decorate(bold);
	table.SelectRow(0).SeparatorVertical(LIGHT);
	table.SelectRow(0).Decorate(bold);
	table.SelectRow(0).Border(DOUBLE);

	//table.SelectAll().SeparatorVertical(EMPTY);
	return vbox({
		text("=== Application protocols ===") | bold,
		table.Render()
	})  | size(HEIGHT, EQUAL, 30) ;
}

void Stats::update_ip_stats(size_t limit) {
	std::lock_guard<std::mutex> lock(mtx);
	rows.clear();

	rows.push_back({"IP Address", "Packets TX", "Packets RX"});
	std::vector<std::pair<std::string, IPStats>> ips(
		ip_map.begin(), ip_map.end()
	);

	std::sort(ips.begin(), ips.end(),
		[](auto& a, auto& b) {
			return a.second.packets_sent > b.second.packets_sent;
		});

	size_t count = 0;
	for (const auto& [ip, s] : ips) {
		if (count++ >= limit) break;
		rows.push_back({ip,
			"TX: " + std::to_string(s.packets_sent),
			"RX: " + std::to_string(s.packets_received)}
		);

	}
}

Element Stats::print_ip_stats(size_t limit)  {
	std::lock_guard<std::mutex> lock(mtx);

	Table table(rows);
	table.SelectAll().Border(LIGHT);

	table.SelectRow(0).Decorate(bold);
	table.SelectRow(0).SeparatorVertical(LIGHT);
	table.SelectRow(0).Decorate(bold);
	table.SelectRow(0).Border(DOUBLE);

	return vbox({
		text("=== Top IP addresses ===") | bold,

		table.Render()
	});
}



void Stats::update_pairs(size_t limit) {
	std::lock_guard<std::mutex> lock(mtx);
	std::vector<std::pair<std::pair<std::string, std::string>, protocolStats>> vec(pairs.begin(), pairs.end());
	std::sort(vec.begin(), vec.end(),
		[](auto& a, auto& b) {
			return a.second.bytes > b.second.bytes;
		});

	pairs_rows.clear();
	pairs_rows.push_back({ "Source", "Destination", "bytes received", "%" });
	size_t count = 0;
	for (const auto& [pair, s] : vec) {

		if (count++ >= limit) break;
		double percent = total_b ? (s.bytes * 100.0 / total_b) : 0.0;
		pairs_rows.push_back({
			pair.first,
			pair.second,
			std::format("{:.0f}", s.bytes * 1.0),
			std::format("{:.2f}", percent),

		});

	}
}

ftxui::Element Stats::print_pairs(size_t limit) {
	std::lock_guard<std::mutex> lock(mtx);

	Table table(pairs_rows);
	table.SelectAll().Border(LIGHT);

	//table.SelectColumn(0).Border(LIGHT);
	table.SelectRow(0).Decorate(bold);
	table.SelectRow(0).SeparatorVertical(LIGHT);
	table.SelectRow(0).Decorate(bold);
	table.SelectRow(0).Border(DOUBLE);

	return vbox({
		text("=== Top communication pairs ===") | bold,
		table.Render()
	}) | flex;
}

void Stats::update_packets(){
	std::lock_guard lock(mtx);
	packets_rows.clear();
	packets_rows.push_back({ "IPVersion", "Transport protocol", "Source", "Destination", "Application protocol" });

	for (auto& packet : packets) {
		packets_rows.push_back({
			packet.ip_version == IPVersion::v4 ? "IPv4" : "IPv6",
			transport_to_str(packet.transport_protocol),
			packet.src,
			packet.dst,
			app_to_str(packet.application_protocol),

		});
	}
}
Element Stats::print_packets() {
	std::lock_guard lock(mtx);

	Table table(packets_rows);
	table.SelectAll().Border(LIGHT);

	//table.SelectColumn(0).Border(LIGHT);
	table.SelectRow(0).Decorate(bold);
	table.SelectRow(0).SeparatorVertical(LIGHT);
	table.SelectRow(0).Decorate(bold);
	table.SelectRow(0).Border(DOUBLE);
	return vbox({
		text("=== Packets ===") | bold,

		table.Render() | flex
	}) | flex;
}

double Stats::smooth_value(size_t i, size_t start) {
	const int window = 3; // ширина сглаживания
	double sum = 0.0;
	int count = 0;

	for (int k = -window; k <= window; ++k) {
		long idx = (long)i + k;
		if (idx >= (long)start && idx < (long)bandwidth_history.size()) {
			sum += bandwidth_history[idx].bytes_per_sec;
			count++;
		}
	}
	return count ? sum / count : 0.0;
}



ftxui::Element Stats::print_bandwidth() {
	std::lock_guard<std::mutex> lock(mtx);
	using namespace ftxui;

	GraphFunction fn = [this](int width, int height) {
		std::vector<int> output(width, 0);

		if (bandwidth_history.size() < 2)
			return output;

		size_t n = bandwidth_history.size();
		size_t start = n > 50 ? n - 50 : 0;

		// максимум
		double max_bw = 1.0;
		for (size_t i = start; i < n; ++i)
			max_bw = std::max(max_bw, bandwidth_history[i].bytes_per_sec);

		for (int x = 0; x < width; ++x) {
			// нормализованная позиция
			double t = (double)x / (width - 1);

			// соответствующий индекс в данных
			double idx_f = start + t * (n - start - 1);
			size_t i0 = (size_t)idx_f;
			size_t i1 = std::min(i0 + 1, n - 1);

			// линейная интерполяция
			double frac = idx_f - i0;
			double bw =
				bandwidth_history[i0].bytes_per_sec * (1.0 - frac) +
				bandwidth_history[i1].bytes_per_sec * frac;

			double v = bw / max_bw;
			output[x] = static_cast<int>(v * (height - 1));
		}

		return output;
	};

	return vbox({
		text(std::format(" Bandwidth: {:.2f}", bandwidth)) | bold,
		graph(fn)
		| size(HEIGHT, EQUAL, 20) | size(WIDTH, EQUAL, 100)
		| border
		| color(Color::Green) ,
});
}

void Stats::export_csv(const std::string& filename) {
	std::ofstream file(filename);
	if (!file.is_open()) return;

	file << "summary\n";
	file << "total_packets,total_bytes,bandwidth\n";
	file << total_p << ","
		 << total_b << ","
		 << bandwidth << "\n\n";

	// ===== Transport protocols =====
	file << "transport_protocols\n";
	file << "protocol,packets,bytes,percent\n";

	for (const auto& [proto, s] : transport_map) {
		double percent = total_b ? (s.bytes * 100.0 / total_b) : 0.0;
		file << transport_to_str(proto) << ","
			 << s.packets << ","
			 << s.bytes << ","
			 << percent << "\n";
	}
	file << "\n";

	// ===== Application protocols =====
	file << "application_protocols\n";
	file << "protocol,packets,payload_bytes\n";

	for (const auto& [proto, s] : application_map) {
		file << static_cast<int>(proto) << ","
			 << s.packets << ","
			 << s.bytes << "\n";
	}
	file << "\n";

	// ===== IP stats =====
	file << "ip_stats\n";
	file << "ip,packets_sent,packets_received,bytes_sent,bytes_received\n";

	for (const auto& [ip, s] : ip_map) {
		file << ip << ","
			 << s.packets_sent << ","
			 << s.packets_received << ","
			 << s.bytes_sent << ","
			 << s.bytes_received << "\n";
	}


	//bandwidth
	file << "time,bandwidth\n";

	for (const auto& p : bandwidth_history) {
		file << p.timestamp << "," << p.bytes_per_sec << "\n";
	}

	file.close();

}
void Stats::export_json(const std::string& filename) {
	std::ofstream file(filename);
	if (!file.is_open()) return;

	file << "{\n";

	// ===== Summary =====
	file << "  \"summary\": {\n";
	file << "    \"total_packets\": " << total_p << ",\n";
	file << "    \"total_bytes\": " << total_b << ",\n";
	file << "    \"bandwidth\": " << bandwidth << "\n";
	file << "  },\n";

	// ===== Transport =====
	file << "  \"transport\": [\n";
	bool first = true;
	for (const auto& [proto, s] : transport_map) {
		if (!first) file << ",\n";
		first = false;

		double percent = total_b ? (s.bytes * 100.0 / total_b) : 0.0;

		file << "    {\n";
		file << "      \"protocol\": \"" << transport_to_str(proto) << "\",\n";
		file << "      \"packets\": " << s.packets << ",\n";
		file << "      \"bytes\": " << s.bytes << ",\n";
		file << "      \"percent\": " << percent << "\n";
		file << "    }";
	}
	file << "\n  ],\n";

	// ===== IP stats =====
	file << "  \"top_ips\": [\n";
	first = true;
	for (const auto& [ip, s] : ip_map) {
		if (!first) file << ",\n";
		first = false;

		file << "    {\n";
		file << "      \"ip\": \"" << ip << "\",\n";
		file << "      \"packets_sent\": " << s.packets_sent << ",\n";
		file << "      \"packets_received\": " << s.packets_received << ",\n";
		file << "      \"bytes_sent\": " << s.bytes_sent << ",\n";
		file << "      \"bytes_received\": " << s.bytes_received << "\n";
		file << "    }";
	}
	file << "\n  ]\n";

	file << ",\n  \"communication_pairs\": [\n";
	first = true;

	for (const auto& [pair, s] : pairs) {
		if (!first) file << ",\n";
		first = false;

		file << "    {\n";
		file << "      \"src\": \"" << pair.first << "\",\n";
		file << "      \"dst\": \"" << pair.second << "\",\n";
		file << "      \"packets\": " << s.packets << ",\n";
		file << "      \"bytes\": " << s.bytes << "\n";
		file << "    }";
	}

	file << "\n  ]";

	file << "}\n";
	file.close();
}
