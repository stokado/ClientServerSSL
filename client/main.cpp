#include "mylib/client.hpp"

int main(int argc, char** argv) {
	if (argc != 3) {
		std::cerr << "Usage: client <host> <port>\n"
			<< "Example:\n"
			<< "client 127.0.0.1 443\n";
		return -1;
	}
	try {
		auto const host = argv[1];
		auto const port = argv[2];
		Client::get_response(host, port);
	}
	catch (const std::exception& ex) {
		std::cerr << ex.what() << endl;
		return -1;
	}
	std::cin.get();
	return 0;
}