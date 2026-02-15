#include "include/capture/pcapCapture.hpp"
#include <iostream>
#include <pcap/pcap.h>
#include <boost/program_options.hpp>
#include "include/cli/filter.hpp"
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/component/component.hpp>
#include <ftxui/component/component_options.hpp>
#include <ftxui/dom/elements.hpp>

#include "include/cli/argsParse.hpp"
#define SNAP_LEN 1518

int main(int argc, char **argv)
{
	PcapCapture capture;
	capture.initialize();

	Stats stats;
	argsParser parser(argc, argv);


	if (parser.vm.count("help")) {
		parser.print_help();
		return 0;
	}
	if (parser.vm.count("interfaces")) {
		capture.print_interfaces();
		return 0;
	}

	std::string interface = parser.vm["interface"].as<std::string>();
	int count = parser.vm["count"].as<int>();
	int limit = parser.vm["limit"].as<int>();
	int time = parser.vm["time"].as<int>();
	std::string filterString = "";
	////////////
	std::vector<filter> filters;
	//get the filters from map
	if (parser.vm.count("filter")) {
		auto& f = parser.vm["filter"].as<std::vector<std::string>>();
		for (auto& x : f) {
			filters.push_back(parse(x));
			filterString += x + " ";
		}
	}

	std::string expression = get_bpf_filter(filters);


	capture.set_capabilities(interface, count, expression, limit, &stats);

	std::chrono::steady_clock::time_point begin;
	std::chrono::seconds timer;

	parser.vm.count("offline") ? capture.start_offline(parser.vm["offline"].as<std::string>()) : capture.start();

	std::atomic<bool> capture_finished = false;

	begin = std::chrono::steady_clock::now();
	using namespace ftxui;
	auto screen = ScreenInteractive::Fullscreen();

	auto renderer = Renderer([&] {

	  auto header =
		  hbox({
			  vbox({
				  text("Network Traffic Analyzer") | bold,
				  text("Interface: " + interface),
				  text("Filter: " + filterString),
			  }) | flex,
			  separator(),
			  stats.print_stats() | flex,
		  }) | border;

	  auto transport_section =
		  hbox({
			  stats.print_transport_stats() | flex,
			  separator(),
			  stats.print_application_stats() | flex,
			  separator(),
			  stats.print_pairs(5) | flex,
		  }) | border;

	  auto ip_section =
	  	hbox({
	  		stats.print_ip_stats(5)
		  | border
		  | size(HEIGHT, LESS_THAN, 10)
		  | frame
		  | vscroll_indicator,

	  		stats.print_bandwidth()
		  | border
		  | flex
	  	});

	  auto left_panel =
		  vbox({
			  transport_section,
			  separator(),
			  ip_section,
		  }) | flex_grow;

	  auto right_panel =
		  stats.print_packets()
		  | border
		  | size(WIDTH, EQUAL, 100)
		  | frame
		  | vscroll_indicator;

	  auto body =
		  hbox({
			  left_panel,
			  separator(),
			  right_panel,
		  }) | flex;

	  auto footer =

		  capture_finished
			  ? text("Capture finished (" + std::format("{}", timer) + "). Press 'q' or Esc to exit.")
					| bold | color(Color::Yellow) | center
			  : text("time: " + std::format("{}", timer)) | center
					| size(HEIGHT, EQUAL, 1);

	  return vbox({
		  header,
		  separator(),
		  body,
		  separator(),
		  footer,
	  });
});

	auto component = CatchEvent(renderer, [&](Event e) {
		if (e == Event::Character('q') || e == Event::Escape) {
			capture.stop();
			screen.Exit();
		}
		return true;

});
	std::thread updater([&] {
		while (capture.isRunning()) {
			stats.update_packets();
			stats.update_application_stats();
			stats.update_transport_stats();
			stats.update_ip_stats(10);
			stats.update_pairs();
			stats.update_bandwidth();

			screen.PostEvent(Event::Custom);
			std::this_thread::sleep_for(std::chrono::milliseconds(300));


			auto current_time = std::chrono::steady_clock::now();
			timer = std::chrono::duration_cast<std::chrono::seconds>(current_time - begin);
			if (timer >= std::chrono::seconds(time)) {
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



	if (parser.vm.count("csv")) {
		stats.export_csv(parser.vm["csv"].as<std::string>());
	}
	if (parser.vm.count("json")) {
		stats.export_json(parser.vm["json"].as<std::string>());
	}
return 0;
}

