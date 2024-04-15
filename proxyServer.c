#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <ctype.h>
#include "threadpool.h"


#define MAX_LINE_LENGTH 1024

// Structure to hold filter data
struct FilterData {
    char **ip_addresses;
    int ip_count;
    char **domains;
    int domain_count;
};

// Structure to hold arguments for handle_client function
struct HandleClientArgs {
    int socket_client;
    struct FilterData *filter_data;
};

typedef struct {
    char *host;
    char *port;
} HostAndPort;

// Function declarations
int dispatch_to_handle_client(void *args);
void handle_client(int fd, struct FilterData*);
HostAndPort *parse_host(const char *request);
int check_request_format(const char *request);
int check_request_method(const char *request);
void construct_response(int client_socket, int status_code,const char* message ,const char *title);
int check_ip_in_filter(const char *ip, const struct FilterData *filter_data);
int check_ip_in_range(const char *ip, const char *network);
int domain_in_file(const struct FilterData*, const char *target);
void modifyConnectionHeader(char *request);
int forward_request(int client_fd,struct hostent*, const char *port, char *request);
int read_filter_file(const char *path, struct FilterData *filter_data);
void free_filter_data(struct FilterData *filter_data);
/**
 * Ignores the SIGPIPE signal to prevent program termination when writing to a closed socket.
 */
void ignore_sigpipe() {
    signal(SIGPIPE, SIG_IGN);
}
void printUsage(){
    fprintf(stderr, "Usage: proxyServer <port> <pool-size> <max-number-of-request> <filter>\n");
}

int main(int argc, char *argv[]) {
    // Check command line arguments
    if (argc != 5) {
        printUsage();
        return 0;
    }

    // Parse command line arguments
    int port = atoi(argv[1]);
    int pool_size = atoi(argv[2]);
    int max_requests = atoi(argv[3]);
    char *filter_file = argv[4];

    if(max_requests <= 0){
        printUsage();
        return 0;
    }
    
    if(port <= 0 || port > 65535){
        fprintf(stderr,"error: Invalid port number.\n");
        return 0;
    }

    struct FilterData* filter_data = (struct FilterData*) malloc(sizeof(struct FilterData));
    if(filter_data == NULL){
        fprintf(stderr,"error: malloc\n");
        exit(EXIT_FAILURE);
    }
    if(read_filter_file(filter_file, filter_data) != 0){
        free(filter_data);
        exit(EXIT_FAILURE);
    }

    // Initialize thread pool
    threadpool *pool = create_threadpool(pool_size);
    if (pool == NULL) {
        fprintf(stderr,"error: creating threadpool\n");
        free_filter_data(filter_data);
        free(filter_data);
        exit(EXIT_FAILURE);
    }

    // Initialize socket
    int server_socket = socket(PF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("error: socket\n");
        destroy_threadpool(pool);
        free_filter_data(filter_data);
        free(filter_data);
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in server_address;
    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = htonl(INADDR_ANY);
    server_address.sin_port = htons(port);

    // Bind socket
    if (bind(server_socket, (struct sockaddr *)&server_address, sizeof(server_address)) < 0) {
        perror("error: bind\n");
        close(server_socket);
        destroy_threadpool(pool);
        free_filter_data(filter_data);
        free(filter_data);
        exit(EXIT_FAILURE);
    }

    // Listen for incoming connections
    if (listen(server_socket, 5) < 0) {
        perror("error: listen\n");
        close(server_socket);
        destroy_threadpool(pool);
        free_filter_data(filter_data);
        free(filter_data);
        exit(EXIT_FAILURE);
    }

    //printf("Proxy server running on port %d\n", port);

    // Accept and handle incoming connections
    int client_socket;
    struct sockaddr_in client_address;
    socklen_t client_address_len = sizeof(client_address);

    ignore_sigpipe();
    int counter = 0;
    while (counter < max_requests) {
        // Accept connection
        client_socket = accept(server_socket, (struct sockaddr *)&client_address, &client_address_len);
        counter++;
        if (client_socket < 0) {
            perror("error: accept\n");
            continue;
        }
        //printf("%d\n",counter);
        // Handle connection in a new thread
        struct HandleClientArgs *args = (struct HandleClientArgs*)malloc(sizeof(struct HandleClientArgs));
        if (args == NULL) {
            fprintf(stderr, "error: malloc\n");
            continue;
        }
        args->socket_client = client_socket;
        args->filter_data = filter_data;
        //printf("New client with fd: %d\n",client_socket);
        dispatch(pool, dispatch_to_handle_client, args);
    }

    // Close server socket
    close(server_socket);

    // Destroy thread pool
    destroy_threadpool(pool);
    free_filter_data(filter_data);
    free(filter_data);
    return 0;
}


/**
 * Function that matches the dispatch_fn signature
 * Dispatches client handling tasks to a separate thread.
 * @param args
 * @return
 */
int dispatch_to_handle_client(void *args) {
    //printf("Thread dispatch_to_handle_client: %lu\n",pthread_self());
    struct HandleClientArgs *handleArgs = (struct HandleClientArgs*)args;
    handle_client(handleArgs->socket_client, handleArgs->filter_data);
    free(args); // Free memory allocated for arguments
    //printf("Thread finish: %lu\n",pthread_self());
    return 0;
}

/**
 * Handles a client connection.
 * @param fd: File descriptor for the client connection.
 * @param filter_file: Path to the file used for filtering requests.
 */
void handle_client(int fd, struct FilterData* filter_file) {
    //printf("Thread in handle_client: %lu\n",pthread_self());
    // Allocate initial memory for request and host
    size_t buffer_size = 1024;
    char *request = (char *)malloc(buffer_size * sizeof(char));

    if (request == NULL) {
        perror("error: malloc\n");
        close(fd);
        return;
    }

    // Read HTTP request from client
    ssize_t total_bytes_received = 0;
    ssize_t bytes_received;
    memset(request, '\0', buffer_size * sizeof(char));
    while (1) {
        bytes_received = read(fd, request + total_bytes_received, buffer_size - total_bytes_received - 1);
        if (bytes_received < 0) {
            perror("error: read\n");
            free(request);
            construct_response(fd,500,"Some server side error.", NULL);
            close(fd);
            return;
        } else if (bytes_received == 0) {
            // Client closed connection
            break;
        }

        total_bytes_received += bytes_received;
        request[total_bytes_received] = '\0';  // Null-terminate the request string

        // Check for end of headers
        char *end_of_headers = strstr(request, "\r\n\r\n");
        if (end_of_headers != NULL) {
            // End of headers found
            break;
        }

        // Resize buffer if needed
        if (total_bytes_received >= buffer_size - 1) {
            buffer_size *= 2;
            request = (char *)realloc(request, buffer_size);
            if (request == NULL) {
                perror("error: malloc\n");
                construct_response(fd,500,"Some server side error.", NULL);
                close(fd);
                return;
            }
        }
    }

    if(!check_request_format(request)){
        // tokens not exists. return 400 bad request.
        //printf("check request format - in!\n");
        free(request);
        construct_response(fd,400,"Bad Request.", "Bad request");
        close(fd);
        return;
    }

    if(!check_request_method(request)){
        // Method is not Get. return 501 Not Implemented.
        //printf("check request method - in!\n");
        free(request);
        construct_response(fd,501,"Method is not supported.", NULL);
        close(fd);
        return;
    }

    HostAndPort *hostAndPort = parse_host(request);
    if(hostAndPort == NULL){
        free(request);
        construct_response(fd,500,"Some server side error.", NULL);
        close(fd);
        return;
    }
    char* host = hostAndPort->host;

    struct hostent *hp; /*ptr to host info for remote*/
    hp = gethostbyname(host);
    if(hp == NULL){
        //return NOT FOUND 404
        herror("error: gethostbyname\n");
        construct_response(fd,404,"File not found.", NULL);
        close(fd);
        free(request);
        free(host);
        free(hostAndPort->port);
        free(hostAndPort);
        return;
    }

    char ip[100];
    struct in_addr ** addr_list = (struct in_addr **)hp->h_addr_list;
    strcpy(ip, inet_ntoa(*addr_list[0])); // Convert IP address to string

    if(domain_in_file(filter_file,host) || check_ip_in_filter(ip,filter_file)) {
        // host/ip is blocked. return 403 Forbidden.
        construct_response(fd,403,"Access denied.", NULL);
        close(fd);
        free(request);
        free(host);
        free(hostAndPort->port);
        free(hostAndPort);
        return;
    }

    if(forward_request(fd,hp,hostAndPort->port,request) < 0){
        //printf("Error with forward thread %lu",pthread_self());
        construct_response(fd,500,"Some server side error.", NULL);
    }
    //printf("thread %lu return from forward\n", pthread_self());
    // Close client socket
    close(fd);

    // Free dynamically allocated memory
    free(request);
    free(host);
    free(hostAndPort->port);
    free(hostAndPort);
}

/**
 * Checks the format of an HTTP request.
 * @param request
 * @return value indicating whether the request format is valid or not.
 */
int check_request_format(const char *request) {
    // Create a copy of the request string
    if (request != NULL && request[0] == '\0') {
        return 0;
    }

    char *request_copy = strdup(request);
    if (request_copy == NULL) {
        perror("error: strdup\n");
        return 0;  // Unable to create copy, treat as invalid format
    }

    // Check if request contains method, path, and protocol
    char *method = strtok(request_copy, " ");
    char *url = strtok(NULL, " ");
    char *protocol = strtok(NULL, "\r\n");

    if (method == NULL || url == NULL || protocol == NULL) {
        // Invalid request format
        free(request_copy);
        return 0;
    }


    // Check if Host header exists
    const char *host_header = "Host:";
    if (strstr(request, host_header) == NULL) {
        // Host header not found
        free(request_copy);
        return 0;
    }

    // Check if the protocol is one of the http versions
    const char *http_versions[] = {"HTTP/1.0", "HTTP/1.1", "HTTP/2.0"};
    int num_versions = sizeof(http_versions) / sizeof(http_versions[0]);
    int valid_protocol = 0;

    for (int i = 0; i < num_versions; i++) {
        if (strcmp(protocol, http_versions[i]) == 0) {
            valid_protocol = 1;
            break;
        }
    }

    free(request_copy);
    return valid_protocol;
}

/**
 * Checks the HTTP request method.
 * @param request The HTTP request string.
 * @return Return value indicating whether the request method is valid or not.
 */
int check_request_method(const char *request) {
    // Find the first space to extract the method
    char *request_copy = strdup(request);
    const char *method = strtok(request_copy, " ");

    if (method == NULL || strcmp(method, "GET") != 0) {
        // Invalid or unsupported method
        free(request_copy);
        return 0;
    }
    free(request_copy);
    return 1;  // Method is valid (GET)
}

/**
 * Constructs an HTTP response.
 * @param client_socket
 * @param status_code
 * @param message
 * @param title
 */
void construct_response(int client_socket, int status_code,const char* message ,const char *title) {
    const char *status_text = "";

    // Determine status text based on status code
    switch (status_code) {
        case 400:
            status_text = "Bad Request";
            break;
        case 403:
            status_text = "Forbidden";
            break;
        case 404:
            status_text = "Not Found";
            break;
        case 500:
            status_text = "Internal Server Error";
            break;
        case 501:
            status_text = "Not supported";
            break;
        default:
            break;
    }

    // Get the current date and time in GMT format
    time_t raw_time;
    struct tm *time_info;
    char date_str[80];
    time(&raw_time);
    time_info = gmtime(&raw_time);
    strftime(date_str, sizeof(date_str), "%a, %d %b %Y %H:%M:%S GMT", time_info);

    // Construct HTTP response body
    char response_body[1024];
    snprintf(response_body, sizeof(response_body), "<HTML><HEAD><TITLE>%d %s</TITLE></HEAD>\r\n<BODY><H4>%d %s</H4>\r\n%s\r\n</BODY></HTML>",
             status_code, status_text, status_code, title ? title : status_text, message);

    // Calculate the length of the response body
    size_t body_length = strlen(response_body);

    // Construct HTTP response header
    char response_header[1024];
    snprintf(response_header, sizeof(response_header), "HTTP/1.1 %d %s\r\nServer: webserver/1.0\r\nDate: %s\r\nContent-Type: text/html\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",
             status_code, status_text, date_str, body_length);

    // Construct final response including header and body
    char response[2048];
    snprintf(response, sizeof(response), "%s%s", response_header, response_body);

    // Send response to client
    write(client_socket, response, strlen(response));
}

/**
 * Function to read filter data from a file into memory.
 * @param path Path to the filter file.
 * @param filter_data Pointer to a struct to hold filter data.
 * @return 0 on success, -1 on failure.
 */
int read_filter_file(const char *path, struct FilterData *filter_data) {
    FILE *file = fopen(path, "r");
    if (!file) {
        perror("error: fopen\n");
        return -1;
    }

    // Initialize counts
    filter_data->ip_count = 0;
    filter_data->domain_count = 0;
    filter_data->ip_addresses = NULL;
    filter_data->domains = NULL;

    // Read lines from the filter file
    char line[MAX_LINE_LENGTH];
    while (fgets(line, sizeof(line), file) != NULL) {
        // Remove newline character if present
        line[strcspn(line, "\n")] = '\0';

        // Check if the line is empty or too short
        if (line[0] == '\0' || strlen(line) < 3) {
            continue;  // Skip empty or too short lines
        }

        // Check if the line is an IP address or domain
        if (isdigit(line[0])) {
            // IP address
            filter_data->ip_addresses = realloc(filter_data->ip_addresses, (filter_data->ip_count + 1) * sizeof(char*));
            filter_data->ip_addresses[filter_data->ip_count] = strdup(line);
            filter_data->ip_count++;
        } else {
            // Domain
            filter_data->domains = realloc(filter_data->domains, (filter_data->domain_count + 1) * sizeof(char*));
            filter_data->domains[filter_data->domain_count] = strdup(line);
            filter_data->domain_count++;
        }
    }

    fclose(file);
    return 0;
}

void free_filter_data(struct FilterData *filter_data) {
    if (filter_data->ip_addresses) {
        for (int i = 0; i < filter_data->ip_count; ++i) {
            free(filter_data->ip_addresses[i]);
        }
        free(filter_data->ip_addresses);
    }

    if (filter_data->domains) {
        for (int i = 0; i < filter_data->domain_count; ++i) {
            free(filter_data->domains[i]);
        }
        free(filter_data->domains);
    }
}

/**
 * Parses the host and port from an HTTP request string.
 * @param request The HTTP request string.
 * @return HostAndPort*: Pointer to a structure containing the parsed host and port.
 */
HostAndPort *parse_host(const char *request) {
    // Find the position of the Host header in the request
    const char *host_header_start = strstr(request, "Host:");
    if (host_header_start == NULL) {
        return NULL; // Host header not found
    }

    // Move the pointer to the start of the host name
    host_header_start += strlen("Host:");

    // Skip leading whitespace characters
    while (*host_header_start == ' ' || *host_header_start == '\t') {
        host_header_start++;
    }

    // Find the end of the host name (indicated by a newline)
    const char *host_header_end = strpbrk(host_header_start, "\r\n");
    if (host_header_end == NULL) {
        return NULL; // End of header not found
    }

    // Calculate the length of the host name
    size_t host_len = host_header_end - host_header_start;

    // Allocate memory for the host name
    char *host = malloc(host_len + 1); // Add 1 for null terminator
    if (host == NULL) {
        return NULL; // Memory allocation failed
    }

    // Copy the host name into the allocated memory
    strncpy(host, host_header_start, host_len);
    host[host_len] = '\0'; // Null terminate the string

    // Check if a port number is specified after the host name
    char *colon_ptr = strchr(host, ':');
    char *port = NULL;
    if (colon_ptr != NULL) {
        // Port number found, extract the port number
        port = strdup(colon_ptr + 1);
        if (port == NULL) {
            free(host);
            return NULL; // Memory allocation failed
        }

        // Null terminate the host name at the colon
        *colon_ptr = '\0';
    } else {
        // No port specified, assign default port 80 for HTTP
        port = strdup("80");
        if (port == NULL) {
            free(host);
            return NULL; // Memory allocation failed
        }
    }

    // Allocate memory for HostAndPort structure
    HostAndPort *hostAndPort = malloc(sizeof(HostAndPort));
    if (hostAndPort == NULL) {
        free(host);
        free(port);
        return NULL; // Memory allocation failed
    }

    // Assign host and port to HostAndPort structure
    hostAndPort->host = host;
    hostAndPort->port = port;

    return hostAndPort;
}

/**
 * Checks if a domain is present in a file.
 * @param filter_data
 * @param target
 * @return
 */
int domain_in_file(const struct FilterData *filter_data, const char *target) {
    // Check if target is in the domain array
    for (int i = 0; i < filter_data->domain_count; ++i) {
        if (strcmp(filter_data->domains[i], target) == 0) {
            return 1; // Target domain found in filter data
        }
    }
    return 0; // Target domain not found in filter data
}

/**
 * Function to check if an IP falls within a network range
 * @param ip
 * @param network
 * @return
 */
int check_ip_in_range(const char *ip, const char *network) {
    struct in_addr addr, net, mask;
    char cidr[MAX_LINE_LENGTH];
    int prefix;

    // Check if CIDR notation is present
    if (strstr(network, "/") != NULL) {
        // Extract network and prefix
        sscanf(network, "%[^/]/%d", cidr, &prefix);

        // Parse network address
        if (inet_pton(AF_INET, cidr, &net) != 1) {
            return 0;
        }

        // Create network mask
        mask.s_addr = htonl((0xffffffff << (32 - prefix)));
    } else {
        // Parse network address without subnet mask
        if (inet_pton(AF_INET, network, &net) != 1) {
            return 0;
        }

        // Set default subnet mask (all ones for /32)
        mask.s_addr = 0xffffffff;
        prefix = 32; // Set prefix to 32 for /32 subnet
    }

    // Parse IP address
    if (inet_pton(AF_INET, ip, &addr) != 1) {
        return 0;
    }

    // Check if IP falls within network range
    return ((addr.s_addr & mask.s_addr) == (net.s_addr & mask.s_addr));
}



/**
 * Function to read network ranges from a filter data and check if an IP falls within any of them.
 * @param ip IP address to check.
 * @param filter_data Pointer to the filter data.
 * @return 1 if IP is in a network range, 0 otherwise.
 */
int check_ip_in_filter(const char *ip, const struct FilterData *filter_data) {
    // Iterate through each line in the filter data
    for (int i = 0; i < filter_data->ip_count; ++i) {
        // Check if IP is in the network range
        if (check_ip_in_range(ip, filter_data->ip_addresses[i])) {
            return 1; // IP is in the network range
        }
    }
    return 0; // IP is not in any network range in the filter data
}

/**
 * Forwards an HTTP request from a client to a specified host and port.
 * @param client_fd
 * @param hp
 * @param port
 * @param request
 * @return int: value indicating success or failure.
 */
int forward_request(int client_fd,struct hostent* hp, const char *port, char *request) {
    //printf("forward_request: %lu\n",pthread_self());
    // Step 2: Create a socket to connect to the origin server
    int sockfd;
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_in peeraddr;
    peeraddr.sin_family = AF_INET;
    peeraddr.sin_addr.s_addr = ((struct in_addr*)(hp->h_addr))->s_addr;

    struct sockaddr_in srv;		/* used by connect() */

    /* connect: use the Internet address family */
    srv.sin_family = AF_INET;
    /* connect: socket ‘fd’ to port */
    srv.sin_port = htons(atoi(port));
    /* connect: connect to IP Address */
    srv.sin_addr.s_addr = peeraddr.sin_addr.s_addr;

    if(connect(sockfd, (struct sockaddr*) &srv, sizeof(srv)) < 0) {
        perror("error: connect\n");
        close(sockfd);
        return -1;
    }

    modifyConnectionHeader(request);

    // Send HTTP request to the server using write()
    int nbytes; // used by write()
    if ((nbytes = write(sockfd, request, strlen(request))) < 0) {
        close(sockfd);
        perror("error: write\n");
        return -1;
    }

    // Step 5: Read the response from the origin server
    //printf("\nforward_request_read responsed: %lu\n",pthread_self());
    unsigned char buffer[1024];
    ssize_t bytes_received;

    while ((bytes_received = read(sockfd, buffer, sizeof(buffer))) > 0) {
        // Step 6: Send the response back to the client
        if((nbytes = write(client_fd, buffer, bytes_received)) < 0) {
            perror("error: write\n");
            close(sockfd);
            return -1;
        }
    }

    close(sockfd);
    return 0;
}

/**
 * Modifies the value of the "Connection" header in an HTTP request to "close".
 * @param request
 */
void modifyConnectionHeader(char *request) {
    // Find the position of the "Connection" header in the request
    const char *connectionHeader = "Connection: ";
    const char *connectionValue = "close";
    char *connectionPos = strstr(request, connectionHeader);

    if (connectionPos != NULL) {
        // Find the end of the "Connection" header line
        char *headerEnd = strchr(connectionPos, '\r');
        if (headerEnd != NULL) {
            // Calculate the length of the part after "Connection" header
            size_t suffixLength = strlen(headerEnd);

            // Shift the remaining content to make space for the new header value and line endings
            memmove(connectionPos + strlen(connectionHeader) + strlen(connectionValue), headerEnd, suffixLength + 1); // +1 for null terminator

            // Copy modified "Connection" header value
            memcpy(connectionPos + strlen(connectionHeader), connectionValue, strlen(connectionValue));
        }
    } else {
        // Connection header not found, append it before the terminating sequence
        char *terminatorPos = strstr(request, "\r\n\r\n");
        if (terminatorPos != NULL) {
            // Shift the remaining content to make space for the new header value and line endings
            size_t suffixLength = strlen(terminatorPos);
            memmove(terminatorPos + strlen("\r\nConnection: close"), terminatorPos, suffixLength + 1); // +1 for null terminator

            // Copy modified "Connection" header value
            memcpy(terminatorPos, "\r\nConnection: close", strlen("\r\nConnection: close"));
        }
    }
}


