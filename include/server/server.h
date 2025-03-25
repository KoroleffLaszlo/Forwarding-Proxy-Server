#ifndef SERVER
#define SERVER

#include <iostream>
#include <cstdint>
#include <string>
#include <memory>
#include <unordered_set>
#include <mutex>
#include <shared_mutex>
#include <atomic>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <netinet/in.h>

class Server{
private:
    int socket_p;
    SSL_CTX* ssl_ctx;  // shared context used for secure session 
        
public:
    Server();
    ~Server();

    struct Connection { // maintains cross communication tracking
        int client_fd;
        std::string client_ip;
        std::shared_ptr<std::unordered_set<std::string>>& u_fsites; //passed by reference fsites
        std::string code; // status code
        std::string request; // client request -> "GET http://ucsc.edu/ HTTP/1.1"
        std::string response; // destination server response
        std::string content_length;
        std::string time_stamp;

        Connection(int fd, std::string ip, std::shared_ptr<std::unordered_set<std::string>>& set)
            : client_fd(fd), 
            client_ip(ip),
            u_fsites(set),
            code(""),
            request(""), 
            response(""),
            content_length("0"),
            time_stamp(""){}
    };

    std::string ffile = "";
    std::atomic<bool> signal_flag{false};
    std::shared_ptr<std::unordered_set<std::string>> fsites;
    std::shared_mutex fsites_mutex;
    
    std::string logFile;
    bool allow_self_signed;

    void socket_init();
    bool setup_ssl_certificates(SSL_CTX*);
    void openssl_init();
    void cleanup_openssl();
    void server_bind(struct sockaddr_in&, const int&);
    void _listen(int maxSize);
    std::unique_ptr<struct Connection> accept_client();
    bool is_exist(const std::string&);
    int create_tcp_connection(const std::string&, const std::string&);
    std::string forward_https_request(const std::string&, const std::string&);
    ssize_t send_to_client(const std::unique_ptr<Connection>&);
    void server_run(std::unique_ptr<Connection>);
};
#endif
