#include "mylib/client.hpp"

void Client::get_response(char* host, char* port, char* path) {
	
	auto const target = "/";

	cout << "Connecting to: " << host << ":" << port << target << endl;

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
		throw (std::runtime_error{ "handshake" });
	}

	http::file_body::value_type body;
	
	body.open(path, beast::file_mode::read, ec);
	if (ec == boost::system::errc::no_such_file_or_directory) {
		throw (std::runtime_error{ "open file" });
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

	handle_response(response, stream.native_handle());

	stream.shutdown(ec);
	if (ec == asio::error::eof) {
		ec = {};
	}
	cout << "End of session\n";
}

void Client::handle_response(const std::string& response, SSL* native) {

	std::stringstream ss{ response };
	cout << "\n*** Answer begin ***\n"
		<< ss.str()
		<< "*** End of message ***\n";

	property_tree::ptree pt;
	property_tree::read_json(ss, pt);

	std::string signature = pt.get<std::string>("hex_signature");
	std::string status_value = pt.get<std::string>("status_value");
	std::string result_value = pt.get<std::string>("result_value");
	
	const std::string tover = status_value + result_value;

	X509* cert = NULL;
	if (!(cert = SSL_get_peer_certificate(native))) {
		throw (std::runtime_error{ "get peer cert" });
	}

	EVP_PKEY* pkey = NULL;
	if (!(pkey = X509_get_pubkey(cert))) {
		throw (std::runtime_error{ "get pub key" });
	}

	if (verify_message(pkey, tover, signature)) {
		cout << "Verified\n"
			<< "Answer: " << result_value << endl;
	}
	else {
		cout << "Could not verify signature\n";
	}

}

bool verify_message(EVP_PKEY* pkey, const std::string& tver, const std::string& sig) {
	
	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	if (ctx == NULL) {
		throw (std::runtime_error{ "md ctx new" });
	}
	if (!(EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey))) {
		throw (std::runtime_error{ "digest verify init" });
	}

	if (!EVP_DigestVerifyUpdate(ctx, (unsigned char*)&tver[0], tver.size())) {
		throw (std::runtime_error{ "digest sign update" });
	}

	if (!EVP_DigestVerifyFinal(ctx, (unsigned char*)&sig[0], sig.size())) {	
		return false;
	}
	return true;
}
