# Proxy Server

The `proxyServer` is a simple multithreaded proxy server written in C, designed to handle HTTP requests. It acts as an intermediary between clients and destination servers, forwarding requests and responses while providing filtering capabilities based on IP addresses and domains.

## Features

- **Multithreaded:** Utilizes a thread pool to handle multiple client connections concurrently, improving performance and responsiveness.
- **Filtering:** Allows filtering of requests based on IP addresses and domain names, blocking access to specified destinations.
- **Dynamic Port Binding:** Binds to a specified port on the local machine, enabling clients to connect and send HTTP requests to the proxy server.
- **Error Handling:** Includes error checking and handling mechanisms to ensure robustness and reliability, providing appropriate error responses to clients.

## Prerequisites

- **C Compiler:** The code is written in C and requires a C compiler (e.g., GCC) to compile and build the executable.
- **Linux/Unix Environment:** The code is designed to run on Unix-like operating systems such as Linux. It may require modifications to run on Windows.

## Usage

To compile and run the `proxyServer`, follow these steps:

1. **Clone the Repository:** Clone the repository containing the `proxyServer` code to your local machine.
   
   ```bash
   git clone https://github.com/yonatanhb/proxy-server.git
   ```

2. **Compile the Code:** Navigate to the directory containing the `proxyServer.c` file and compile the code using a C compiler.
   
   ```bash
   gcc -o proxyServer proxyServer.c threadpool.c -lpthread
   ```

3. **Run the Server:** Execute the compiled binary to start the proxy server, specifying the required command-line arguments.
   
   ```bash
   ./proxyServer <port> <pool-size> <max-number-of-requests> <filter-file>
   ```

   - `<port>`: The port number on which the proxy server will listen for incoming connections.
   - `<pool-size>`: The size of the thread pool used to handle client requests concurrently.
   - `<max-number-of-requests>`: The maximum number of requests the server will handle before shutting down.
   - `<filter-file>`: The path to the file containing filtering rules for IP addresses and domains.

## Configuration

The `proxyServer` can be configured by adjusting the following parameters:

- **Port:** Choose a port number to listen for incoming connections. Ensure that the port is not in use by other applications.
- **Thread Pool Size:** Determine the number of threads in the thread pool based on the expected workload and system resources.
- **Maximum Requests:** Set a limit on the number of requests the server will handle before shutting down. This prevents resource exhaustion and ensures server stability.
- **Filter Rules:** Specify filtering rules in the filter file to control access based on IP addresses and domain names.

## Contributing

Contributions to the `proxyServer` project are welcome! If you find any issues or have suggestions for improvements, please open an issue or submit a pull request on GitHub.

## License

The `proxyServer` is open-source software licensed under the [MIT License](LICENSE). You are free to use, modify, and distribute the code for any purpose. See the LICENSE file for details.

---
