#include "mylib/client.hpp"

int main() {
	try {
		std::string response = Client::getResponse();

	}
	catch (const std::exception& ex) {
		std::cerr << ex.what() << endl;
		return -1;
	}
	return 0;
}