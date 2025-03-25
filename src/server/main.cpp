#include <unistd.h>
#include "../../include/server/server.h"
#include "../../include/common/thread.h"
#include "../../include/common/file_wrap.h"

#include <iostream>
#include <string>
#include <cstring>
#include <cstdlib>
#include <cerrno>
#include <vector>
#include <cstdint>
#include <stdexcept>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/select.h>
#include <sys/types.h>   
#include <sys/time.h>
#include <csignal>  
#include <fcntl.h>   

#define MAX_CLIENTS 50

Server server_handler;
_Thread thread_handler;

namespace Helper {
    std::tuple<std::string, std::string, std::string, bool> command_line_parse(int argc, char* argv[]) {
        std::string listen_port, forbidden_sites_file, log_file;
        int opt;
        bool u_flag = false;
        while((opt = getopt(argc, argv, "p:a:l:u")) != -1){
            switch(opt){
                case 'p':
                    listen_port = optarg;
                    break;
                case 'a':
                    forbidden_sites_file = optarg;
                    break;
                case 'l':
                    log_file = optarg;
                    break;
                case 'u':
                    u_flag = true;
                    break;
                default:
                    throw std::runtime_error("expected: -p <port> -a <forbidden_sites_path> -l <access_log_path> [-u]");
            }
        }

        return {listen_port, forbidden_sites_file, log_file, u_flag};
    }
}

void handle_signal(int signum){
    if(signum == SIGINT){
        std::cout<<"[INFO] Ctrl+C received -- updating forbidden sites"<<std::endl;
        server_handler.signal_flag.store(true, std::memory_order_relaxed);
    }
}

void setup_signal_handler(){
    struct sigaction sa;
    sa.sa_handler = handle_signal; // registers SIGINT handler
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0; // insures accept() restarts

    if(sigaction(SIGINT, &sa, NULL) < 0) {
        perror("[FATAL] sigaction failed");
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char* argv[]){

    setup_signal_handler();
    struct sockaddr_in srv_addr;

    try{
        std::tuple<std::string, std::string, std::string, bool> args = Helper::command_line_parse(argc, argv);
        server_handler.fsites = std::make_shared<std::unordered_set<std::string>>  // assigns forbidden sites to global set for threads to access
                                (File::file_read_stream(std::get<1>(args)));

        File::open_log_file(std::get<2>(args));
        server_handler.allow_self_signed = std::get<3>(args); // certification ignore flag
        server_handler.ffile = std::get<1>(args); // forbidden file
        int listen_port = std::stoi(std::get<0>(args)); // listening port: str -> int
        server_handler.socket_init();
        server_handler.openssl_init(); // initialize the secure socket for comms with server destination 
        server_handler.server_bind(srv_addr, listen_port);
        server_handler._listen(MAX_CLIENTS);

        std::cout<<"[INFO] Server running..."<<std::endl;
        
        while(true){
            // if SIGINT detected
            bool flag_value = server_handler.signal_flag.load(std::memory_order_relaxed); // Load atomic value
            if(flag_value == true){
                std::unique_lock write_lock(server_handler.fsites_mutex); // lock all reading threads for update
                auto updated_fsites = std::make_shared<std::unordered_set<std::string>>(File::file_read_stream(std::get<1>(args)));
                server_handler.fsites = updated_fsites; // stores updated set into server object
                server_handler.signal_flag.store(false, std::memory_order_relaxed); // lowers SIGINT flag
                flag_value = server_handler.signal_flag.load(std::memory_order_relaxed);
            }

            std::unique_ptr<Server::Connection> _conn = server_handler.accept_client();
            
            if(!_conn){
                continue; // no clients attempting to connect -> go back and wait 
            } 

            std::thread client_thread = thread_handler.thread_create(&Server::server_run,
                                                                    server_handler,
                                                                    std::move(_conn));
            //std::cout<<"[THREAD] "<<client_thread.get_id()<<std::endl;                                                   
            client_thread.detach(); // fire and forget
        }

    }catch(const std::exception &e){
        std::cerr<<"Error - "<< e.what() <<std::endl;
        server_handler.cleanup_openssl();
        File::close_log();
        return EXIT_FAILURE;
    }
    server_handler.cleanup_openssl();
    File::close_log();
    return EXIT_SUCCESS;
}