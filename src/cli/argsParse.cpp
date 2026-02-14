#include "../../include/cli/argsParse.hpp"

argsParse::argsParse(int argc, char** argv) {
	po::options_description desc("Options");
	desc.add_options()
		("help,h", "Display this help message and exit")

		("interface,i", po::value<std::string>(),
			"Network interface to capture packets from (e.g. eth0, wlan0, any)")

		("count,c", po::value<int>()->default_value(0),
			"Number of packets to capture (0 = unlimited)")

		("pcap,r", po::value<std::string>(),
			"Read packets from an offline pcap file")

		("filter,f", po::value<std::vector<std::string>>()->composing(),
			"Traffic filter (can be used multiple times)\n"
			"  proto:<name>   tcp | udp | icmp | dns\n"
			"  src:<ip>       Source IP address\n"
			"  dst:<ip>       Destination IP address\n"
			"  port:<number>  Source or destination port")

		("view,v", po::value<std::string>()->default_value("top-talkers"),
			"Output view: protocol | top-talkers | bandwidth")

		("sort,s", po::value<std::string>()->default_value("bytes"),
			"Sort field: bytes | packets | ip")

		("order,o", po::value<std::string>()->default_value("desc"),
			"Sort order: asc | desc")

		("limit,n", po::value<int>()->default_value(10),
			"Limit number of displayed entries")

		("csv", po::value<std::string>(),
			"Export analysis results to CSV file")

		("json", po::value<std::string>(),
			"Export analysis results to JSON file");

	po::variables_map vm;
	po::store(po::parse_command_line(argc, argv, desc), vm);
	po::notify(vm);

	if (vm.count("help")) {
		print_help();

	}



}

void argsParse::print_help() {
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
