#include "mylib/server.hpp"

Server::Server(asio::io_context& ioc, ssl::context& ctx, tcp::endpoint ep)
	: _ioc(ioc), _ctx(ctx), _acceptor(ioc) {

	cout << "Starting server...\n";
	// init server private key
	init_pkey();
	// init server certificate
	init_cert();
	// setup ssl
	setup_ssl();

	beast::error_code ec;

	// open acceptor
	_acceptor.open(ep.protocol(), ec);
	if (ec) {
		throw (std::runtime_error{ "open" });
		return;
	}

	// allow address reuse
	_acceptor.set_option(asio::socket_base::reuse_address(true), ec);
	if (ec) {
		throw (std::runtime_error{ "set_option" });
		return;
	}

	// bind server to the server address
	_acceptor.bind(ep, ec);
	if (ec) {
		throw (std::runtime_error{ "bind" });
		return;
	}

	// start listening for connections
	_acceptor.listen(asio::socket_base::max_listen_connections, ec);
	if (ec) {
		throw (std::runtime_error{ "listen" });
		return;
	}
}

void Server::setup_ssl() {
	cout << "Setup SSL context...\n";

	boost::system::error_code ec;

	_ctx.use_certificate_file("servcert.crt", ssl::context_base::file_format::pem, ec);
	if (ec) {
		throw (std::runtime_error{ "ERROR: read servcert.crt" });
	}
	_ctx.use_private_key_file("pkeyserv.key", ssl::context_base::file_format::pem, ec);
	if (ec) {
		throw (std::runtime_error{ "ERROR: read pkeyserv.key" });
	}
	cout << "Success!\n";


}

void Server::init_pkey() {
	cout << "Generating private key...\n";

	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);

	if (!ctx) {
		throw (std::runtime_error{ "ERROR: EVP_PKEY_CTX\n" });
	}

	if (!EVP_PKEY_keygen_init(ctx)) {
		throw (std::runtime_error{ "ERROR: EVP_PKEY_keygen_init\n" });
	}

	if (!EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1)) {
		throw (std::runtime_error{ "ERROR: EVP_PKEY_CTX_set_ec\n" });
	}

	if (!EVP_PKEY_keygen(ctx, &_pkey)) {
		throw (std::runtime_error{ "ERROR: EVP_PKEY_keygen\n" });
	}

	BIO* file = BIO_new_file("pkeyserv.key", "wb");
	if (!file) {
		throw (std::runtime_error{ "BIO_new_file" });
	}

	if (!PEM_write_bio_PrivateKey(
		file,
		_pkey,
		nullptr,
		nullptr,
		0,
		nullptr,
		nullptr)) {
		throw (std::runtime_error{ "ERROR: PEM_write_PrivateKey\n" });
	}

	BIO_free(file);
	EVP_PKEY_CTX_free(ctx);

	cout << "Success!\n";
}

void Server::init_cert() {
	cout << "Initializing certificate...\n";
	_cert = X509_new();
	X509_gmtime_adj(X509_get_notBefore(_cert), 0);
	X509_gmtime_adj(X509_get_notAfter(_cert), (long)60 * 60 * 24 * 365);
	X509_set_pubkey(_cert, _pkey);
	X509_NAME* name = X509_get_subject_name(_cert);
	X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char*)"RU", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char*)"Test", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)"server", -1, -1, 0);

	X509_set_issuer_name(_cert, name);
	X509_sign(_cert, _pkey, EVP_sha256());
	if (add_ext(NID_key_usage, "digitalSignature,keyCertSign,keyAgreement")) {
		throw (std::runtime_error{ "Couldn't add key usage\n" });
	}

	BIO* file = BIO_new_file("servcert.crt", "wb");
	if (!file) {
		throw (std::runtime_error{ "BIO_new_file" });
	}

	if (!PEM_write_bio_X509(
		file,
		_cert)) {
		throw (std::runtime_error{ "ERROR: PEM_write_X509\n" });
	}

	BIO_free(file);

	cout << "Success!\n";
}

bool Server::add_ext(int nid, char* value) {
	X509_EXTENSION* ex;
	X509V3_CTX ctx;

	X509V3_set_ctx_nodb(&ctx);

	X509V3_set_ctx(&ctx, _cert, _cert, NULL, NULL, 0);
	ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
	if (!ex) {
		return true;
	}
	X509_add_ext(_cert, ex, -1);
	X509_EXTENSION_free(ex);
	return false;
}

void Server::run() {
	try {
		do_accept();
	}
	catch (const std::exception& ex) {
		std::cerr << ex.what() << endl;
	}
}

void Server::do_accept() {
	_acceptor.async_accept(
		asio::make_strand(_ioc),
		beast::bind_front_handler(
			&Server::on_accept,
			shared_from_this()));
}

void Server::on_accept(beast::error_code ec, tcp::socket socket) {
	if (ec) {
		throw (std::runtime_error{ "accept" });
	}
	else {
		cout << "\nNew connection\n";
		std::make_shared<Session>(
			std::move(socket),
			_ctx,
			_pkey,
			_cert)->run();
	}

	do_accept();
}
