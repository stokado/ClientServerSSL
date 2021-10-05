#pragma once

#include <iostream>
#include <sstream>
#include <vector>

#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/foreach.hpp>

using std::cout;
using std::endl;

namespace beast = boost::beast;
namespace http = beast::http;
namespace asio = boost::asio;
namespace ssl = asio::ssl;
namespace property_tree = boost::property_tree;

using tcp = asio::ip::tcp;


class Session : public std::enable_shared_from_this<Session> {
public:
	explicit Session(tcp::socket&& socket,
		ssl::context& ctx,
		EVP_PKEY* pkey,
		X509* cert)
		: _stream(std::move(socket), ctx),
		_pkey(pkey), _cert(cert), _lambda(*this) 
	{};
	void run();
	void on_run();
	void on_handshake(beast::error_code ec);
	void do_read();
	void on_read(beast::error_code ec, std::size_t bytes_transferred);
	void on_write(bool close, beast::error_code ec, std::size_t bytes_transferred);
	void do_close();
	void on_shutdown(beast::error_code ec);
private:

private:
	// The function object is used to send an HTTP message.
	struct send_lambda {
		Session& _self;
		explicit send_lambda(Session& self) : _self(self) {};

		template <bool isRequest, class Body, class Fields>
		void operator()(http::message<isRequest, Body, Fields>&& msg) const;
	};

	beast::ssl_stream <beast::tcp_stream> _stream;
	beast::flat_buffer _buffer;
	http::request <http::string_body> _req;
	std::shared_ptr<void> _res;
	EVP_PKEY* _pkey;
	X509* _cert;
	send_lambda _lambda;
};

template<class Body, class Allocator, class Send>
void handle_request(
	http::request<Body, http::basic_fields<Allocator>>&& req,
	Send&& send, EVP_PKEY* pkey, X509* cert);


struct Result {
	Result(unsigned short new_status, double new_result) {
		this->status = new_status;
		this->result = new_result;
	};
	unsigned short status = 0;
	double result = 0;
};


Result perform_calculation(const std::string& operation,
	std::vector<double>& numbers);


std::string sign_message(EVP_PKEY* pkey, std::string plain_text);