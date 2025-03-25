#include "../../include/common/datagram.h"

#include <iostream>
#include <string>
#include <sstream>
#include <utility>
#include <algorithm>
#include <regex>

namespace _Debug{
    // debugging checks for proper request creation
    void print_with_special_chars(const std::string& s){
        for(char c : s){
            if(c == '\r') {std::cout << "\\r";}  // show `\r`
            else if (c == '\n') {std::cout << "\\n";}  // show `\n`
            else {std::cout << c;}
        }
        std::cout << std::endl;
    }
}

// returns the client request method host and http version
std::tuple<std::string, std::string, std::string> Dgram::get_method_domain_version(const std::string& s){
    std::istringstream iss(s);
    std::string method, http_version, domain;

    if(!(iss >> method)) return {"", "", ""};  // Return empty values if extraction fails
    
    std::string url;  // temp string to parse to http version strtoken
    if (!(iss >> url >> http_version)) return {"", "", ""};

    std::regex url_regex(R"(^(?:https?:\/\/)?([^\/:]+))");
    std::smatch match;
    
    if (std::regex_search(url, match, url_regex) && match.size() > 1) {
        domain = match[1].str();
        return {method, domain, http_version};
    }else{
        return {"", "", ""};
    }
}

std::string Dgram::get_host_port(const std::string& s){
    std::istringstream iss(s);
    std::string host = "";
    std::string line;
    while (std::getline(iss, line) && line != "\r\n\r\n") {
        // std::cout<<"[DEBUG] line: "<<line<<std::endl;
        if (line.find("Host: ") == 0){
            host = line.substr(6); // extracts host
            host.erase(std::remove(host.begin(), host.end(), '\r'), host.end());
            host.erase(std::remove(host.begin(), host.end(), '\n'), host.end());
            break;
        }
    }
    // std::cout<<"[HOST] "<<host<<std::endl;
    size_t colonPos = host.rfind(':'); // last occurance of ':'
    if (colonPos == std::string::npos) {
        return "";
    }
    return host.substr(colonPos + 1); // Return the port as a string
}

std::string Dgram::get_request(const std::string& s){
    std::istringstream iss(s);
    std::string method, host, version;
    iss>>method>>host>>version;
    return (method + " " + host + " " + version);
}

std::pair<std::string, std::string> Dgram::get_status_and_length(const std::string& s){
    std::istringstream iss(s);
    std::string line;
    std::string status_code;
    std::string content_length;

    // Extract the status code from the first line
    if(std::getline(iss, line)){
        std::istringstream first_line(line);
        std::string http_version;
        first_line >> http_version >> status_code; // Skip HTTP version and grab status code
    }

    // Parse headers for Content-Length
    while(std::getline(iss, line) && !line.empty()){
        if(line.find("Content-Length: ") == 0){
            content_length = line.substr(16); // Extract the value after "Content-Length: "
            content_length.erase(content_length.find_last_not_of("\r\n") + 1); // Trim newlines
        }
    }

    return std::pair<std::string,std::string>(status_code, content_length);
}

// converts to appropriate request to be sent to server
std::string Dgram::convert_to_relative_request(const std::string& request, const std::string& client_ip){
    std::istringstream stream(request);
    std::string method, url, http_version;
    stream >> method >> url >> http_version;
    bool con_flag = false;

    // extract relative URL
    size_t pos = url.find("/", url.find("://") + 3);
    std::string relative_url = (pos != std::string::npos) ? url.substr(pos) : "/";
    std::string modified_request = method + " " + relative_url + " " + http_version;

    // preserve headers except for `Proxy-Connection`
    std::string line;
    while(std::getline(stream, line) && line != "\r\n\r\n"){
        if(line.find("Proxy-Connection") == std::string::npos){ //ignore adding proxy-conncect
            line.erase(std::remove(line.begin(), line.end(), '\r'), line.end());
            modified_request += line + "\r\n";
        }
        if(line.find("Connection") != std::string::npos){ // if connection: exists at all replace with blanked 
            con_flag = true;
            modified_request += "Connection: close\r\n";
        }
    }
    size_t pos_f = modified_request.find("\r\n\r\n");
    if(pos_f != std::string::npos){
        modified_request = modified_request.replace(pos_f, 4, "\r\n");
    }
    if(!con_flag) {modified_request += "Connection: close\r\n";} // if connection: dne add it
    modified_request += "X-Forward-For: " + client_ip + "\r\n\r\n";
    return modified_request;
}

// std::string Dgram::extract_port(const std::string& host){
//     size_t colonPos = host.rfind(':'); // last occurance of ':'
//     if (colonPos == std::string::npos) {
//         return "";
//     }
//     return host.substr(colonPos + 1); // Return the port as a string
// }