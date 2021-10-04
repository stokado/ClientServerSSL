#include "mylib/client.hpp"

std::string Client::getResponse() {
	
	auto const host = "127.0.0.1";
	auto const port = "443";
	auto const target = "/";

	cout << "Please enter server ip: " << host << endl;
	cout << "Please enter server port: " << port << endl;

	cout << "Connection to " << host << ":" << port << endl
		<< "target " << target << endl;

	asio::io_context ioc{ 1 };
	ssl::context ctx(ssl::context::tlsv12_client);
	
	ctx.set_verify_mode(ssl::verify_none);
	tcp::resolver resolver{ ioc };
	ssl::stream <tcp::socket> stream{ ioc, ctx };

	boost::system::error_code ec;
	auto const results = resolver.resolve(host, port);
	asio::connect(stream.next_layer(), results.begin(), results.end());

	stream.handshake(ssl::stream_base::client, ec);
	if (ec) {
		throw (std::exception{ "handshake" });
	}

	http::file_body::value_type body;
	auto const path = "..\\..\\data\\test0.json";
	body.open(path, beast::file_mode::read, ec);
	if (ec == boost::system::errc::no_such_file_or_directory) {
		throw (std::exception{ "open file" });
	}

	http::request<http::file_body> req{ http::verb::get, target, 11 };
	req.set(http::field::host, host);
	req.set(http::field::user_agent, "Client");
	req.set(http::field::content_type, "application/json");
	req.body() = std::move(body);
	req.prepare_payload();

	http::write(stream, req);

	std::string response;
	{
		boost::beast::flat_buffer buffer;
		http::response<http::dynamic_body> res;
		http::read(stream, buffer, res);
		response = beast::buffers_to_string(res.body().data());
	}

	SSL* native = stream.native_handle();
	handle_response(response, native);

	stream.shutdown(ec);
	if (ec == asio::error::eof) {
		ec = {};
	}
	return response;
}


std::string Client::handle_response(const std::string& response, SSL* native) {

	std::stringstream ss{ response };
	cout << "\n*** Answer begin ***\n"
		<< ss.str()
		<< "\n*** End of message ***\n";

	property_tree::ptree pt;
	property_tree::read_json(ss, pt);

	std::string signature = pt.get<std::string>("hex_signature");
	unsigned short status_value = pt.get<unsigned short>("status_value");
	double result_value = pt.get<double>("result_value");


	X509* cert = SSL_get_peer_certificate(native);
	EVP_PKEY* pubk = X509_get0_pubkey(cert);
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pubk, NULL);

	EVP_PKEY_verify_init(ctx);

	
		
	cout << "Success!\n" << "Exiting...\n";
	return "test";
}