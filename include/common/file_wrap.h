#ifndef FILE_T
#define FILE_T

#include <iostream>
#include <string>
#include <cstring>
#include <cerrno>
#include <vector>
#include <cstdint>
#include <stdexcept>
#include <cstdlib>
#include <unistd.h>
#include <cstdint>
#include <fstream>
#include <unordered_set>
#include <mutex>

class File{
private:
    static std::mutex log_mutex;
    static std::ofstream log_file;
    static int log_fd;

public:
    static void open_log_file(const std::string&);
    static void close_log();
    static std::unordered_set<std::string> file_read_stream(const std::string&);
    static void file_write_stream(const std::string &message);
};
#endif