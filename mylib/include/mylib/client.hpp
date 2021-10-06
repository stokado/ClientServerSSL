#pragma once

#include <iostream>
#include <openssl/evp.h>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/property_tree/json_parser.hpp>


namespace asio = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;
namespace ssl = asio::ssl;
namespace property_tree = boost::property_tree;

using std::cout;
using std::endl;
using tcp = asio::ip::tcp;

class Client {
public:
	static void get_response(char* host, char* port, char* path);
	static void handle_response(const std::string& response, SSL* native);
};

bool verify_message(EVP_PKEY* pkey, const std::string& tver, const std::string& sig);
