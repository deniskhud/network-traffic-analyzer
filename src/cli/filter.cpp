#include "../../include/cli/filter.hpp"

#include <map>

filter parse(std::string str) {
	auto pos = str.find(':');
	if (pos == std::string::npos) {

	}

	std::string type = str.substr(0, pos);
	std::string value = str.substr(pos + 1);

	if (type == "protocol") return {PROTOCOL, value};
	if (type == "port") return {PORT, value};
	if (type == "dest") return {IP_DEST, value};
	if (type == "src") return {IP_SRC, value};
	if (type == "ip") return {IP_TYPE, value};
	return {NONE, value};
}

std::string get_bpf_filter(std::vector<filter>& f) {
	std::map<filter_type, std::vector<std::string>> groups;

	for (const auto& x : f) {
		switch (x.type) {
			case PROTOCOL:
				if (x.val == "dns")
					groups[PROTOCOL].push_back("port 53");
				else
					groups[PROTOCOL].push_back(x.val);
				break;

			case IP_DEST:
				groups[IP_DEST].push_back("dst host " + x.val);
				break;

			case IP_SRC:
				groups[IP_SRC].push_back("src host " + x.val);
				break;

			case PORT:
				groups[PORT].push_back("port " + x.val);
				break;
			case IP_TYPE:
				groups[IP_TYPE].push_back(x.val);
				break;

			default:
				break;
		}
	}

	std::string result;
	bool first_group = true;

	for (auto& [type, parts] : groups) {
		if (!first_group)
			result += " and ";
		first_group = false;

		if (parts.size() > 1)
			result += "(";

		for (size_t i = 0; i < parts.size(); ++i) {
			result += parts[i];
			if (i + 1 < parts.size())
				result += " or ";
		}

		if (parts.size() > 1)
			result += ")";
	}

	return result;
}

