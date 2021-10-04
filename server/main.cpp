#include "mylib/server.hpp"

#ifdef _WIN32
#include <openssl/applink.c>
#endif

int main()
{
	try {
		auto const address = asio::ip::make_address("127.0.0.1");
		auto const port = static_cast <unsigned short> (std::atoi("443"));
		auto const max_connections = std::atoi("5");

		asio::io_context ioc { max_connections };
		ssl::context ctx{ ssl::context::tlsv12 };

		std::make_shared<Server>(
			ioc,
			ctx,
			tcp::endpoint{ address, port })->run();
		std::vector<std::thread> v;
		v.reserve(max_connections - 1);
		for (auto i = max_connections - 1; i > 0; --i) {
			v.emplace_back(
				[&ioc] {
					ioc.run();
				});
		}
		ioc.run();
	}
	catch (const std::exception& ex) {
		std::cerr << ex.what() << endl;
		return -1;
	}

	return 0;
}
