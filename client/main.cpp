#include "mylib/client.hpp"

#define BOOST_BIND_GLOBAL_PLACEHOLDERS


int main(int argc, char** argv) {
	if (argc != 4) {
		std::cerr << "Usage: client <host> <port> <path_to_file>\n"
			<< "Example:\n"
			<< "client 127.0.0.1 443 ../../data/test0.json\n";
		return -1;
	}
	try {
		auto const host = argv[1];
		auto const port = argv[2];
		auto const path = argv[3];
		Client::get_response(host, port, path);
	}
	catch (const std::exception& ex) {
		std::cerr << ex.what() << endl;
		return -1;
	}
	std::cin.get();
	return 0;
}