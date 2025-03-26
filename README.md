# Forwarding Proxy Server 
A proxy server that forwards client requests to end servers and vice versa. On startup, it reads a _forbidden list_ file to determine how to handle incoming requests. The proxy uses OpenSSL’s API to validate end-server certificates, only allowing self-signed certificates when explicitly requested by the client. All proxy activity is logged to a file specified at program start.
# Running Program


