# INFO
Program intended for a Linux Environment, created and tested on Windows with WSL
# Forwarding Proxy Server 
A proxy server that forwards client requests to end servers and vice versa. On startup, it reads a _forbidden list_ file to determine how to handle incoming requests. The proxy uses OpenSSL’s API to validate end-server certificates, only allowing self-signed certificates when explicitly requested by the client. All proxy activity is logged to a file specified at program start.
# Running Program
Standard `make` to create executable
## Run Server
1. `cd bin`.
2. Run server with following line execution: `./myproxy -p <port> -a <forbidden site file> -l <logging file> [-u]`. The optional `-u` flag is used to allow proxy server to relay requests to self-signed host servers.
3. `Ctrl-C` updates proxy server's registered _forbidden list_.
4. `Ctrl-\` terminates program.

### Example Server Start
`./myproxy -p 9090 -a forbidden_sites.txt -l log.txt`

## Run Request
You can run basic _curl_ or _netcat_ commands
### Example Client Requests
- `curl -i -x http://127.0.0.1:9090/ http://www.example.com`, ensure Server is initialized with appropriate `-u` flag
- `curl -i -x http://127.0.0.1:9090/ http://httpbin.org/stream/100`
- `curl -i -x http://127.0.0.1:9090/ http://www.neverssl.com`
- `echo -e "GET http://www.example.com/ HTTP/1.1\r\nHost: www.example.com\r\nConnection: keep-alive\r\n\r\n" | nc 127.0.0.1 9090`

