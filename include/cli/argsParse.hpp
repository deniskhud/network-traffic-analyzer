#ifndef ARGSPARSE_HPP
#define ARGSPARSE_HPP
#include <boost/program_options.hpp>
/*using namespace boost;
class argsParse {
private:
	program_options::options_description description;

public:
	argsParse();
};*/
#include <iostream>
namespace po = boost::program_options;
struct argsParse {
	po::options_description desc;
	po::variables_map vm;
	void print_help();

	argsParse(int argc, char** argv);
};

#endif //ARGSPARSE_HPP
