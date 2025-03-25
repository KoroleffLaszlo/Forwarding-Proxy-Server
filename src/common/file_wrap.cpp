#include "../../include/common/file_wrap.h"

#include <iostream>
#include <fstream>
#include <mutex>
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>
#include <string>
#include <filesystem>

namespace Helper{
    // removes leading and tailing whitespaces
    std::string trim(const std::string& str) {
        size_t start = str.find_first_not_of(" \t\r\n");
        size_t end = str.find_last_not_of(" \t\r\n");
        return (start == std::string::npos) ? "" : str.substr(start, end - start + 1);
    }
}

std::mutex File::log_mutex;
int File::log_fd = -1;
std::ofstream File::log_file;

void File::open_log_file(const std::string &filePath){
    std::filesystem::path path(filePath);
    if (!std::filesystem::exists(path.parent_path()) && !path.parent_path().empty()) {
        std::filesystem::create_directories(path.parent_path());
    }

    log_fd = open(filePath.c_str(), O_WRONLY | O_CREAT | O_APPEND, 0666);
    if(log_fd == -1){
        throw std::runtime_error(std::string("Failed to open log file -- log_fd: ") + std::string(strerror(errno)));
    }

    log_file.open(filePath, std::ios::app);
    if(!log_file){
        throw std::runtime_error(std::string("Failed to open log file -- log_file: ") + std::string(strerror(errno)));
    }
}

void File::close_log(){
    if (log_file.is_open()) {
        log_file.close();
    }
    if (log_fd != -1) {
        close(log_fd);
    }
}

// returns unordered_set containing forbidden domains (for faster look-up)
std::unordered_set<std::string> File::file_read_stream(const std::string& filePath){
    std::filesystem::path path(filePath);
    if(!std::filesystem::exists(path)){
        std::cerr << "[WARNING] File does not exist, creating: " << filePath << std::endl;
        std::ofstream newFile(filePath);
        if(!newFile) {throw std::runtime_error("[ERROR] Failed to create file: " + filePath);}
        return {};
    }

    std::ifstream file(filePath);
    if(!file){
        throw std::runtime_error(std::string("Failed to read from file: ") + std::string(strerror(errno)));
    }
    std::unordered_set<std::string> entries;
    std::string line;
    while(std::getline(file, line)){
        size_t comment = line.find('#');
        if(comment != std::string::npos) {line = line.substr(0, comment);} // remove ending comment
        
        line = Helper::trim(line);
        if(!line.empty()) {entries.insert(line);}
    }
    return entries;
}

void File::file_write_stream(const std::string &message) {
    std::lock_guard<std::mutex> lock(log_mutex);
    if(log_fd != -1){
        flock(log_fd, LOCK_EX);
        if(log_file.is_open()){
            log_file << message << std::endl;
            log_file.flush();
        }
        flock(log_fd, LOCK_UN);
    }
}