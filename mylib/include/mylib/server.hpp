#pragma once

#include <iostream>
#include <sstream>
#include <algorithm>
#include <vector>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>

#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "mylib/session.hpp"


namespace beast = boost::beast;
namespace http = beast::http;
namespace asio = boost::asio;
namespace ssl = asio::ssl;
namespace property_tree = boost::property_tree;

using std::cout;
using std::endl;
using tcp = asio::ip::tcp;

class Server : public std::enable_shared_from_this<Server>{
public:
	Server(asio::io_context& ioc, ssl::context& ctx, tcp::endpoint ep);
	void run();
private:
	// setup ssl
	void init_pkey();
	void init_cert();
	bool add_ext(int nid, char* value);
	void setup_ssl();
	// server async operations
	void do_accept();
	void on_accept(beast::error_code ec, tcp::socket socket);
private:
	asio::io_context& _ioc;
	ssl::context& _ctx;
	tcp::acceptor _acceptor;

	EVP_PKEY* _pkey = nullptr;
	X509* _cert = nullptr;
};

