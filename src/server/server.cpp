#include "../../include/server/server.h"
#include "../../include/common/datagram.h"
#include "../../include/common/file_wrap.h"

#include <iostream>
#include <string>
#include <cstring>
#include <cstdlib>
#include <cerrno>
#include <vector>
#include <cstdint>
#include <stdexcept>
#include <map>
#include <utility>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/select.h>
#include <sys/types.h>   
#include <sys/time.h>    
#include <unistd.h>
#include <tuple>   
#include <fcntl.h>
#include <bitset>
#include <iomanip>
#include <algorithm>
#include <ctime>
#include <filesystem>
#include <shared_mutex>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <unistd.h>

#define MTU_MAX 32000

enum ErrorCheck {
    E_VALID = 10, // everything works as intended
    E_IP_RESBAD = 11, // ip resolved from getnameinfo() bad
    E_DOMAIN_RESBAD = 12, // domain resolved from getaddrinfo() bad
    E_FBID_REQ = 13, // forbidden request from client
    E_DISCONNECT = 14, // connection failed in communication
    E_ERROR = 15 // catch all error handle
};

namespace Debug{
    // debugging checks for proper request creation
    void print_with_special_chars(const std::string& s){
        for(char c : s){
            if(c == '\r') {std::cout<<"\\r";}  // show `\r`
            else if (c == '\n') {std::cout<< "\\n";}  // show `\n`
            else {std::cout<<c;}
        }
        std::cout << std::endl;
    }
}

namespace Resolve {
    // checks if destination server is given as ip address
    bool is_ip_address(const std::string& host) {
        struct sockaddr_in sa;
        return inet_pton(AF_INET, host.c_str(), &(sa.sin_addr)) == 1;
    }

    // DNS lookup
    std::string resolve_domain_to_ip(const std::string &domain){ 
        struct addrinfo filter{0}, *res;

        filter.ai_family = AF_INET;
        filter.ai_socktype = SOCK_STREAM;

        if(getaddrinfo(domain.c_str(), nullptr, &filter, &res) != 0){ // check if it exists
            std::cout<<"[ERROR] Domain could not be resolved to existing Ip address"<<std::endl;
            return "";
        }

        // grab mapping ip address
        char ip_str[INET_ADDRSTRLEN];
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)res->ai_addr;
        inet_ntop(AF_INET, &(ipv4->sin_addr), ip_str, INET_ADDRSTRLEN);
    
        freeaddrinfo(res); 
        return std::string(ip_str);
    }
}

namespace Log_handle {
    std::string timeStamp() {
        std::time_t now = std::time(nullptr);
        std::tm gmt = *std::gmtime(&now);  // Convert to UTC time
    
        std::ostringstream oss;
        oss<<std::put_time(&gmt, "%Y-%m-%dT%H:%M:%SZ");  // RFC 3339 format
    
        return oss.str();
    }

    void _log(const std::unique_ptr<Server::Connection>& t){
        std::string message = t->time_stamp + " " + t->client_ip + " " +
                            t->request + " " + t->code + " " + t->content_length;
        File::file_write_stream(message);
    }
}

Server::Server() : socket_p(-1){
    openssl_init();
};

Server::~Server(){
    if(socket_p >= 0) {close(socket_p);}
    if(ssl_ctx) {cleanup_openssl();}
}

void Server::socket_init(){
    socket_p = socket(AF_INET, SOCK_STREAM, 0);
    if(socket_p < 0){
        close(socket_p);
        throw std::runtime_error(std::string("server socket initialization failed: ") 
                + std::string(strerror(errno)));
    }
}

void Server::openssl_init(){
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    ssl_ctx = SSL_CTX_new(TLS_client_method()); // create a client SSL context

    if(!ssl_ctx){
        throw std::runtime_error(std::string("failed to create OpenSSL context: ")
                + std::string(strerror(errno)));
    }

    // load system CA certs
    if (!SSL_CTX_set_default_verify_paths(ssl_ctx)) {
        std::cerr << "[ERROR] Failed to load system CA certificates -- HTTPS connections may not be verified" << std::endl;
    }

    // allow self-signed cert servers
    if(allow_self_signed){
        SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, nullptr); // SSL_VERIFY_NONE ignores peer cert checking
        std::cout<<"[INFO] Self-signed certificates are allowed -- Certificate validation is disabled."<<std::endl;
    }else{
        SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, nullptr); // SSL_VERIFY_PEER checks peers cert
        std::cout<<"[INFO] Only CA-signed certificates are allowed -- Strict verification enabled"<<std::endl;
    }
}

void Server::cleanup_openssl(){
    if(ssl_ctx){
        SSL_CTX_free(ssl_ctx);
        ssl_ctx = nullptr;  // prevents dangling pointers
    }
    
    EVP_cleanup();
    ERR_free_strings();
    CRYPTO_cleanup_all_ex_data();
    std::cout<<"[INFO] OpenSSL cleanup completed"<<std::endl;
}

void Server::server_bind(struct sockaddr_in &srv_addr, const int& port){
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(port);
    srv_addr.sin_addr.s_addr = INADDR_ANY;

    int opt = 1;
    if((setsockopt(socket_p, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) < 0){
        close(socket_p);
        throw std::runtime_error(std::string("server SO_REAUSEADDR flag failed: ") + std::string(strerror(errno)));
    }

    if((bind(socket_p, (struct sockaddr*)&srv_addr, sizeof(srv_addr)) < 0)){
        close(socket_p);
        throw std::runtime_error(std::string("server bind failed: ") + std::string(strerror(errno)));
    }
}

void Server::_listen(int maxSize){
    if(listen(socket_p, maxSize) < 0){
        close(socket_p);
        throw std::runtime_error(std::string("server listen failed: ") + std::string(strerror(errno)));
    }
}

std::unique_ptr<Server::Connection> Server::accept_client(){
    struct sockaddr_in client;
    socklen_t client_size = sizeof(client);
    int fd = accept(socket_p, (struct sockaddr*)&client, &client_size);
    if(fd < 0) {
        if(errno == EINTR){ // signal interupt handling (blocking handling)
            std::cout<<"[ERROR] Signal interupt detected"<<std::endl;
        }else{
            std::cerr<<"[FATAL] Failed to connect to client: "<< strerror(errno) << std::endl;
        }
        return nullptr;
    }

    // thread safe conversion from bytes to char
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client.sin_addr, ip_str, INET_ADDRSTRLEN);

    // std::cout<<"[INFO] Client connection accepted ";
    // std::cout<<"- using fd: "<<fd<< std::endl;

    return std::make_unique<Connection>(fd, std::string(ip_str), std::ref(fsites));
}

bool Server::is_exist(const std::string &host){
    std::unordered_set<std::string> _fsites;
    { // smaller scope, copying updated fsites to use an instance of current snapshot
        std::shared_lock<std::shared_mutex> read_lock(fsites_mutex);
        _fsites = *fsites;
        //sleep(10);
        read_lock.unlock();
    }

    if(_fsites.find(host) != _fsites.end()){
        return true;
    }

    std::string ip_addr = Resolve::resolve_domain_to_ip(host);
    if(ip_addr == ""){ // invalid domain -- no ip
        errno = E_DOMAIN_RESBAD;
        return true;
    }
    if(_fsites.find(ip_addr) != _fsites.end()) {return true;}
    return false;
}

// creates connection between the proxy and the destination server
int Server::create_tcp_connection(const std::string &host, const std::string &request){
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_ADDRCONFIG;

    std::string port;
    if((port = Dgram::get_host_port(request)) == "") {port = "443";}
    std::cout<<"[DEBUG] Host using port: "<<port<<std::endl;
    if(getaddrinfo(host.c_str(), port.c_str(), &hints, &res) != 0){
        std::cerr<<"[ERROR] Failed to resolve host: "<<host<<std::endl;
        return -1;
    }
    int sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if(sockfd < 0){
        std::cerr<<"[ERROR] Failed to create socket"<<std::endl;
        freeaddrinfo(res);
        return -1;
    }

    struct timeval timeout;
    timeout.tv_sec = 30;
    timeout.tv_usec = 0;
    if(setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0){
        std::cerr<<"[ERROR] Failed to set send timeout"<<std::endl;
        freeaddrinfo(res);
        close(sockfd);
        return -1;
    }
    if(setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0){
        std::cerr<<"[ERROR] Failed to set receive timeout"<<std::endl;
        freeaddrinfo(res);
        close(sockfd);
        return -1;
    }

    if(connect(sockfd, res->ai_addr, res->ai_addrlen) < 0){
        std::cerr<<"[ERROR] Failed to connect to "<<host<<std::endl;
        close(sockfd);
        freeaddrinfo(res);
        return -1;
    }
    freeaddrinfo(res);
    return sockfd;
}

std::string Server::forward_https_request(const std::string &host, const std::string &request){
    // create tcp connection to server destination
    int sockfd = create_tcp_connection(host, request);
    if(sockfd < 0){
        return "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
    }

    // set up SSL pointer object to set up connection
    SSL *ssl = SSL_new(ssl_ctx);
    if(!ssl){
        std::cerr<<"[ERROR] Failed to create SSL structure"<<std::endl;
        close(sockfd);
        return "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
    }

    SSL_set_fd(ssl, sockfd);

    // SSL handshake
    if(SSL_connect(ssl) <= 0){
        std::cerr << "[ERROR] SSL handshake failed with " << host << std::endl;
        SSL_free(ssl);
        close(sockfd);
        return "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
    }

    // TODO: self cert/real cert checking based on allow_self_sign flag status dynamic checking
    std::cout<<"[INFO] SSL connection established with "<<host<<std::endl;

   // get the server's certificate chain
    STACK_OF(X509) *cert_chain = SSL_get_peer_cert_chain(ssl);
    if(!cert_chain || sk_X509_num(cert_chain) == 0){  // check if the chain exists and has at least one cert
        std::cerr << "[ERROR] No certificate chain presented by the server." << std::endl;
        SSL_free(ssl);
        close(sockfd);
        return "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
    }

    // extract servers cert from stack
    X509 *cert = sk_X509_value(cert_chain, 0);
    if(!cert){
        std::cerr<<"[ERROR] Failed to retrieve the first certificate from the chain"<<std::endl;
        SSL_free(ssl);
        close(sockfd);
        return "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
    }

    // Create a verification context
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    if(!ctx){
        std::cerr<<"[ERROR] Failed to create X509_STORE_CTX"<<std::endl;
        SSL_free(ssl);
        close(sockfd);
        return "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
    }

    X509_STORE *store = SSL_CTX_get_cert_store(ssl_ctx);  // Get system CA certs
    if(!X509_STORE_CTX_init(ctx, store, cert, cert_chain)){  // Pass full chain for validation
        std::cerr<<"[ERROR] Failed to initialize X509_STORE_CTX"<<std::endl;
        X509_STORE_CTX_free(ctx);
        SSL_free(ssl);
        close(sockfd);
        return "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
    }

    // Perform certificate verification
    if(X509_verify_cert(ctx) != 1){
        int error = X509_STORE_CTX_get_error(ctx);
        std::cerr<<"[ERROR] Certificate verification failed: "
                <<X509_verify_cert_error_string(error)<<std::endl;
        if(!allow_self_signed){  // reject if self-signed certs are not allowed
            std::cerr<<"[ERROR] Self-signed or untrusted certificate not accepted -- Closing connection." << std::endl;
            X509_STORE_CTX_free(ctx);
            SSL_free(ssl);
            close(sockfd);
            return "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
        }else{
            std::cerr<<"[WARNING] Accepting self-signed certificate due to configuration"<<std::endl;
        }
    }

    // Cleanup verification context
    X509_STORE_CTX_free(ctx);

    std::cout<<"[INFO] Certificate is valid. Proceeding with request"<<std::endl;

    if(SSL_write(ssl, request.c_str(), request.length()) <= 0){
        std::cerr<<"[ERROR] SSL_write failed"<<std::endl;
        SSL_free(ssl);
        close(sockfd);
        return "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
    }

    // reads response from server
    char buffer[8192];
    std::string response;
    int bytes_read;
    while((bytes_read = SSL_read(ssl, buffer, sizeof(buffer))) > 0){
        response.append(buffer, bytes_read);
    }
    if(bytes_read < 0){
        std::cerr<<"[ERROR] SSL_read failed"<<std::endl;
        response = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
    }
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    return response;
}

// handles sending responses back to the client
ssize_t Server::send_to_client(const std::unique_ptr<Connection>& t){
    int client_socket = t->client_fd;
    ssize_t bytes_sent = 0;
    ssize_t total_sent = 0;
    ssize_t response_size = t->response.size();
    std::string response = t->response;

    Log_handle::_log(t);

    while(total_sent < response_size){
        bytes_sent = send(client_socket, response.c_str() + total_sent, response_size - total_sent, 0);

        if(bytes_sent < 0){  // client disconnect/err
            std::cerr<<"[ERROR] Failed to send response to client: "<<strerror(errno)<<std::endl;
            return -1;
        }
        if(bytes_sent == 0){  // client closed connection
            std::cerr<<"[INFO] Client closed the connection before receiving full response."<<std::endl;
            return 0;
        }
        total_sent += bytes_sent;
    }

    return total_sent;
}

void Server::server_run(std::unique_ptr<Connection> t){
    
    std::string _recv = "";
    int send_ret = 0;
    char buffer[MTU_MAX];
    int client_socket = t->client_fd;

    // handling possible chunked client request
    t->time_stamp = Log_handle::timeStamp();
    while(_recv.find("\r\n\r\n") == std::string::npos){ // handles chunking
        int bytes_recv = recv(client_socket, buffer, sizeof(buffer), 0);
        _recv.append(buffer, bytes_recv);
    }
    std::cout<<"[INFO] Request: \n";
    Debug::print_with_special_chars(_recv);

    // method -> "GET/HEAD" | host entry | http version
    std::tuple<std::string, std::string, std::string> tp = Dgram::get_method_domain_version(_recv);
    std::string method = std::get<0>(tp);
    std::string host = std::get<1>(tp);
    std::string version = std::get<2>(tp);

    t->request = Dgram::get_request(_recv); // grabbing response for future logging
    std::string req_to_server = Dgram::convert_to_relative_request(_recv, t->client_ip); // formatting request to send to destination

    if((method != "GET" && method != "HEAD") || (version != "HTTP/1.1")){
        t->response = "HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\n\r\n";
        t->code = "501";
        send_ret = send_to_client(std::move(t));
        if(send_ret <= 0) {std::cerr<<"[ERROR] Connection malformed -- to client"<<std::endl;}
        return;
    }

    if(is_exist(host)){ 
        if(errno == E_DOMAIN_RESBAD){ // bad gateway (host doesn't exist)
            t->response = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
            t->code = "502";
            send_ret = send_to_client(std::move(t));
        }else{ // forbidden (in fsites)
            std::cout<<"Forbidden site"<<std::endl;
            t->response = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
            t->code = "403";
            send_ret = send_to_client(std::move(t));
        }
        if(send_ret <= 0) {std::cerr<<"[ERROR] Connection malformed to client"<<std::endl;}
        return;
    }
    std::cout<<"[INFO] Forwarded request: \n";
    Debug::print_with_special_chars(req_to_server);

    t->response = forward_https_request(host, req_to_server);// handle response back from server

    // rechecking with possibly updated forbidden sites
    if(is_exist(host)){
        if(errno == E_DOMAIN_RESBAD){ // bad gateway (host doesn't exist)
            std::cout<<"ERR HERE"<<std::endl;
            t->response = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
            t->code = "502";
            send_ret = send_to_client(std::move(t));
        }else{ // forbidden (in fsites)
            std::cout<<"Forbidden site"<<std::endl;
            t->response = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
            t->code = "403";
            send_ret = send_to_client(std::move(t));
        }
        if(send_ret <= 0) {std::cerr<<"[ERROR] Connection malformed to client"<<std::endl;}
        return;
    }

    // get status code and content length
    std::pair<std::string, std::string> p = Dgram::get_status_and_length(t->response);
    t->code = p.first;
    t->content_length = p.second;

    if((send_ret = send_to_client(std::move(t))) <= 0){
        std::cerr<<"[ERROR] Connection malformed to client"<<std::endl;
    }
    std::cout<<"[INFO] Thread ended"<<std::endl;
    return;
}