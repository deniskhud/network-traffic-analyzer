#include "include/capture/pcapCapture.hpp"
#include <iostream>
#include <pcap/pcap.h>
#include <boost/program_options.hpp>
#include "include/cli/filter.hpp"
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/component/component.hpp>
#include <ftxui/dom/elements.hpp>
#define SNAP_LEN 1518

namespace po = boost::program_options;
void print_help(po::options_description& desc) {
	std::cout <<
		"Network Traffic Analyzer\n"
		"========================\n\n"
		"Usage:\n"
		"  netanalyze [options]\n\n"
		"Description:\n"
		"  Captures and analyzes network traffic from live interfaces or\n"
		"  offline pcap files. Provides protocol statistics, top talkers,\n"
		"  and bandwidth usage information.\n\n";

	std::cout << desc << "\n";

	std::cout <<
		"Examples:\n"
		"  netanalyze -i eth0 -v top-talkers -s bytes -n 5\n"
		"  netanalyze -i any --filter proto:dns\n"
		"  netanalyze --pcap traffic.pcap --json result.json\n";


}

int main(int argc, char **argv)
{
	PcapCapture capture;
	capture.initialize();
	//TODO добавь listener на esc при выходе из бесконечного цикла

	/////////
	po::options_description desc("Options");
	desc.add_options()
		("help,h", "Display this help message and exit")
		("interfaces, interfaces","Display all possible interfaces")
		("interface,i", po::value<std::string>()->default_value("wlan0"),
			"Network interface to capture packets from (e.g. eth0, wlan0, any)")

		("count,c", po::value<int>()->default_value(0),
			"Number of packets to capture (0 = unlimited)")
		("time, t", po::value<int>()->default_value(INT_MAX),"Working time (in seconds)")

		("offline,r", po::value<std::string>(),
			"Read packets from an offline pcap file")

		("filter,f", po::value<std::vector<std::string>>()->composing(),
			"Traffic filter (can be used multiple times)\n"
			"  proto:<name>   tcp | udp | icmp | dns\n"
			"  src:<ip>       Source IP address\n"
			"  dst:<ip>       Destination IP address\n"
			"  port:<number>  Source or destination port")

		("sort,s", po::value<std::string>()->default_value("bytes"),
			"Sort field: bytes | packets | ip")

		("order,o", po::value<std::string>()->default_value("desc"),
			"Sort order: asc | desc")

		("limit,n", po::value<int>()->default_value(43),
			"Limit number of displayed entries")

		("csv", po::value<std::string>(),
			"Export analysis results to CSV file")

		("json", po::value<std::string>(),
			"Export analysis results to JSON file");

	po::variables_map vm;
	po::store(po::parse_command_line(argc, argv, desc), vm);
	po::notify(vm);

	if (vm.count("help")) {
		print_help(desc);
		return 0;
	}
	if (vm.count("interfaces")) {
		capture.print_interfaces();
		return 0;
	}

	std::string interface = vm["interface"].as<std::string>();
	int count = vm["count"].as<int>();
	int limit = vm["limit"].as<int>();
	int time = vm["time"].as<int>();
	std::string filterString = "";
	////////////
	std::vector<filter> filters;
	//get the filters from map
	if (vm.count("filter")) {
		auto& f = vm["filter"].as<std::vector<std::string>>();
		for (auto& x : f) {
			filters.push_back(parse(x));
			filterString += x + " ";
		}
	}

	std::string expression = get_bpf_filter(filters);

	//printf("Network traffic analyzer\n\n");
	capture.set_capabilities(interface, count, expression, limit);

	//
	std::chrono::steady_clock::time_point begin;
	std::chrono::steady_clock::time_point end;
	std::chrono::seconds seconds;

	vm.count("offline") ? capture.start_offline(vm["offline"].as<std::string>()) : capture.start();
	//capture.start();

	std::atomic<bool> capture_finished = false;

	begin = std::chrono::steady_clock::now();
	using namespace ftxui;
	auto screen = ScreenInteractive::Fullscreen();

	auto renderer = Renderer([&] {
	return vbox({
		hbox({
			vbox({
				hbox({
					vbox({
						text("Network traffic analyzer") | bold,
						text("Interface: " + interface),
						text("Filter: " + filterString),
					}),
					separator(),
					capture.stats.print_stats(),
				}),

				separator(),
				hbox({
					capture.stats.print_transport_stats(),
					capture.stats.print_application_stats(),
					capture.stats.print_pairs(5),
				}) | flex,
				separator(),
				capture.stats.print_ip_stats(5),

				separator(),
				hbox({

					capture.stats.print_bandwidth(),
				}) | flex,

			}),
			vbox({
				capture.stats.print_packets(),

			}),

		}),
		//TODO сделай отображение а то сдвигается
		capture_finished
			? text("Capture finished. Press 'q' or Esc to exit.")
				| bold | color(Color::Yellow) | center
			: text("") | flex,


	});
});
	auto component = CatchEvent(renderer, [&](Event e) {
	if (capture_finished && (e == Event::Character('q') || e == Event::Escape)) {
		if (capture.isRunning()) {
			capture.stop();
		}
		screen.Exit();
		return true;
	}
	if (!capture_finished && (e == Event::Character('q') || e == Event::Escape)) {
		capture.stop();
		screen.Exit();
		return true;
	}
	return false;
});
	std::thread updater([&] {
		while (capture.isRunning()) {
			capture.stats.update_packets();
			capture.stats.update_application_stats();
			capture.stats.update_transport_stats();
			capture.stats.update_ip_stats(10);
			capture.stats.update_pairs();
			capture.stats.update_bandwidth();

			screen.PostEvent(Event::Custom);
			std::this_thread::sleep_for(std::chrono::milliseconds(300));


			auto current_time = std::chrono::steady_clock::now();
			auto s = std::chrono::duration_cast<std::chrono::seconds>(current_time - begin);
			if (s >= std::chrono::seconds(time)) {
				break;
			}
		}
		capture_finished = true;
		screen.PostEvent(Event::Custom);
	});

	screen.Loop(component);
	if (updater.joinable()) {
		updater.join();
	}

	end = std::chrono::steady_clock::now();
	seconds = std::chrono::duration_cast<std::chrono::seconds>(end - begin);
	std::cout << "time: " << seconds;

	if (vm.count("csv")) {
		capture.stats.export_csv(vm["csv"].as<std::string>());
	}
	if (vm.count("json")) {
		capture.stats.export_json(vm["json"].as<std::string>());
	}
return 0;
}

