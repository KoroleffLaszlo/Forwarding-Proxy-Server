#ifndef DGRAM
#define DGRAM

#include <iostream>
#include <string>
#include <utility>

class Dgram{
public:
    static std::tuple<std::string, std::string, std::string> get_method_domain_version(const std::string&);
    static std::string get_host_port(const std::string&);
    static std::string get_request(const std::string&);
    static std::pair<std::string, std::string> get_status_and_length(const std::string&);
    static std::string convert_to_relative_request(const std::string&, const std::string&);
};
#endif