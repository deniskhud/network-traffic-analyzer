#include "include/capture/pcapCapture.hpp"
#include <iostream>
#include <pcap/pcap.h>
#include <boost/program_options.hpp>
#include "include/cli/filter.hpp"
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/component/component.hpp>
#include <ftxui/component/component_options.hpp>


#include "include/cli/argsParse.hpp"
#include "include/TUI/view.hpp"
#define SNAP_LEN 1518

int main(int argc, char **argv)
{
	/* initialize capture */
	PcapCapture capture;
	capture.initialize();

	/* initialize stats */
	Stats stats;

	/* initializing the command line parser */
	argsParser parser(argc, argv);

	/* check helper flags */
	if (parser.vm.contains("help")) {
		parser.print_help();
		return 0;
	}
	if (parser.vm.contains("interfaces")) {
		capture.print_interfaces();
		return 0;
	}
	/* take the arguments of the flags into variables */
	std::string interface = parser.vm["interface"].as<std::string>();
	int count = parser.vm["count"].as<int>();
	int limit = parser.vm["limit"].as<int>();
	int time = parser.vm["time"].as<int>();
	std::string filterString = "";

	/* get a filter, use vector for multiple  */
	std::vector<filter> filters;
	if (parser.vm.contains("filter")) {
		auto& f = parser.vm["filter"].as<std::vector<std::string>>();
		for (auto& x : f) {
			filters.push_back(parse(x));
			filterString += x + " ";
		}
	}
	/* converting the filter to a pcap readable string */
	std::string expression = get_bpf_filter(filters);

	bool isOffline = parser.vm.contains("offline");

	/* set the flags to capture engine */
	capture.set_capabilities(interface, count, expression, limit, &stats);


	std::atomic<bool> capture_finished = false;

	/* if we capture packets offline, we read the file in full, then print the result */
	if (isOffline) {

        capture.start_offline(parser.vm["offline"].as<std::string>());

        /* full recalculation of statistics after file processing */
        stats.update_packets();
        stats.update_application_stats();
        stats.update_transport_stats();
        stats.update_ip_stats(10);
        stats.update_pairs();
        stats.update_bandwidth();
    }
	/* otherwise start live capture */
    else {
        capture.start();
    }

    /* UI */
    using namespace ftxui;
    auto screen = ScreenInteractive::Fullscreen();
	/* our class for UI */
    View view;

	/* timer */
	std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();
	std::chrono::seconds timer{0};

    auto renderer = Renderer([&] {
        auto snapshot = stats.snapshot;
        return view.render(snapshot,
                           interface,
                           filterString,
                           capture_finished,
                           timer);
    });

    auto component = CatchEvent(renderer, [&](Event e) {
        if (e == Event::Character('q') || e == Event::Escape) {
            capture.stop();
            screen.Exit();
        }
        return true;
    });


    std::thread updater;

    if (!isOffline) {
        updater = std::thread([&] {
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
                timer = std::chrono::duration_cast<std::chrono::seconds>(
                        current_time - begin);

                if (timer >= std::chrono::seconds(time))
                    break;
            }

            capture_finished = true;
            screen.PostEvent(Event::Custom);
        });
    }

    screen.Loop(component);

    if (updater.joinable())
        updater.join();

    /* check export flags */
    if (parser.vm.contains("csv")) {
        stats.export_csv(parser.vm["csv"].as<std::string>());
    }
    if (parser.vm.contains("json")) {
        stats.export_json(parser.vm["json"].as<std::string>());
    }

    return 0;
}

