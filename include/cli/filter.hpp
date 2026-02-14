#ifndef FILTER_HPP
#define FILTER_HPP
#include <string>
#include <vector>
#include <map>
enum filter_type {
	PROTOCOL,
	PORT,
	IP_TYPE,
	IP_SRC,
	IP_DEST,
	NONE
};

struct filter {
	filter_type type;
	std::string val;
};


filter parse(std::string str);
std::string get_bpf_filter(std::vector<filter>& f);



#endif //FILTER_HPP
