#include "mylib/session.hpp"

template <bool isRequest, class Body, class Fields>
void Session::send_lambda::operator() (http::message<isRequest, Body, Fields>&& msg) const{
	auto sp = std::make_shared<http::message<isRequest, Body, Fields>>(std::move(msg));


	_self._res = sp;

	http::async_write(
		_self._stream,
		*sp,
		beast::bind_front_handler(
			&Session::on_write,
			_self.shared_from_this(),
			sp->need_eof()));

}

void Session::run() {
	asio::dispatch(
		_stream.get_executor(),
		beast::bind_front_handler(
			&Session::on_run,
			shared_from_this()));
}

void Session::on_run() {
	// set timeout
	beast::get_lowest_layer(_stream).expires_after(std::chrono::seconds(30));
	
	_stream.async_handshake(
		ssl::stream_base::server,
		beast::bind_front_handler(
			&Session::on_handshake,
			shared_from_this()));
}

void Session::on_handshake(beast::error_code ec) {
	if (ec) {
		throw (std::runtime_error{ "handshake" });
	}

	do_read();
}

void Session::do_read() {
	_req = {};
	beast::get_lowest_layer(_stream).expires_after(std::chrono::seconds(30));

	http::async_read(_stream, _buffer, _req,
		beast::bind_front_handler(
			&Session::on_read,
			shared_from_this()));
}

void Session::on_read(beast::error_code ec, std::size_t bytes_transferred) {
	boost::ignore_unused(bytes_transferred);

	if (ec == http::error::end_of_stream) {
		return do_close();
	}

	if (ec) {
		throw (std::runtime_error{ "read" });
	}

	handle_request(std::move(_req), _lambda, _pkey, _cert);
}

void Session::on_write(bool close, beast::error_code ec, std::size_t bytes_transferred) {
	boost::ignore_unused(bytes_transferred);

	if (ec) {
		throw (std::runtime_error{ "write" });
	}

	if (close) {
		return do_close();
	}

	_res = nullptr;
	do_read();
}

void Session::do_close() {
	beast::get_lowest_layer(_stream).expires_after(std::chrono::seconds(30));

	_stream.async_shutdown(
		beast::bind_front_handler(
			&Session::on_shutdown,
			shared_from_this()));
}

void Session::on_shutdown(beast::error_code ec) {
	if (ec)
		throw (std::runtime_error{ "shutdown" });
}



template<class Body, class Allocator, class Send>
void handle_request(
	http::request<Body, http::basic_fields<Allocator>>&& req,
	Send&& send, EVP_PKEY* pkey, X509* cert) {

	std::stringstream ss;
	ss << req.body();
	cout << "\n*** Recieved message ***\n"
		<< ss.str()
		<< "\n*** End of message ***\n";

	property_tree::ptree pt;
	property_tree::read_json(ss, pt);

	std::string operation = pt.get<std::string>("operation");
	std::vector<double> numbers{};

	BOOST_FOREACH(property_tree::ptree::value_type& v, pt.get_child("numbers")) {
		assert(v.first.empty());
		numbers.push_back(std::stod(v.second.data()));
	}

	Result r = perform_calculation(operation, numbers);
	
	ss.str("");
	pt.clear();

	std::string status_value = std::to_string(r.status);
	std::string result_value = std::to_string(r.result);

	std::string tbs = status_value + result_value;

	EVP_PKEY* pubkey = NULL;
	if (!(pubkey = X509_get_pubkey(cert))) {
		throw (std::runtime_error{ "get pub key" });
	}

	std::string signature = sign_message(pkey, tbs);

	pt.put("status_value", status_value);
	pt.put("result_value", result_value);
	pt.put("hex_signature", signature);

	property_tree::write_json(ss, pt);

	cout << "\n*** Sending message ***\n"
		<< ss.str()
		<< "*** End of message ***\n";
	http::response<http::string_body> res{ http::status::ok, req.version() };
	res.set(http::field::server, "Server");
	res.set(http::field::content_type, "application/json");
	res.body() = ss.str();
	res.prepare_payload();
	return send(std::move(res));
};


Result perform_calculation(const std::string& operation,
	std::vector<double>& numbers) {
	sort(numbers.begin(), numbers.end());

	unsigned short status = 0;
	double value = 0;

	// if there are any numbers
	if (numbers.size()) {
		if (operation == "min") {
			value = numbers.front();
		}
		else if (operation == "max") {
			value = numbers.back();
		}
		else if (operation == "avg") {
			double sum = 0;
			for (const auto& cur : numbers) {
				sum += cur;
			}
			value = sum / numbers.size();
		}
		else if (operation == "median") {
			size_t size = numbers.size();
			if (size % 2) {
				value = numbers.at(size / 2);
			}
			else {
				value = (numbers.at(size / 2) + numbers.at((size - 1) / 2)) / 2.0;
			}
		}
		else {
			// error code 2 = unknown operation
			status = 2;
		}
	}
	else {
		// error code 1 = no numbers are given
		status = 1;
	}


	return { status, value };
};



std::string sign_message(EVP_PKEY* pkey, std::string msg) {
	
	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	if (ctx == NULL) {
		throw (std::runtime_error{ "md_ctx_new" });
	}
	EVP_PKEY_CTX* pkeyctx;
	if (!(pkeyctx = EVP_PKEY_CTX_new(pkey, NULL))) {
		throw (std::runtime_error{ "CTX new" });
	}

	if (!EVP_DigestSignInit(ctx, &pkeyctx, EVP_sha256(), NULL, pkey)) {
		throw (std::runtime_error{ "digest sign init" });
	}

	if (!EVP_DigestSignUpdate(ctx, (unsigned char*)&msg[0], msg.size())) {
		throw (std::runtime_error{ "digest sign update" });
	}

	size_t siglen = 0;

	if (!EVP_DigestSign(ctx, nullptr, &siglen, (unsigned char*)&msg, msg.size())) {
		throw (std::runtime_error{ "digest sign final" });
	}

	unsigned char* sig = new  unsigned char[siglen];

	if (!EVP_DigestSign(ctx, sig,
		&siglen,
		(unsigned char*)&msg,
		msg.size())) {
		throw (std::runtime_error{ "digest sign final" });
	}

	char* hexOut = OPENSSL_buf2hexstr(sig, siglen);
	std::string signature{ hexOut };

	EVP_MD_CTX_free(ctx);

	return signature;
}