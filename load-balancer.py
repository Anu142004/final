import os
import socket
import threading
import time

class LoadBalancer:
    def __init__(self, backend_servers):
        self.backend_servers = backend_servers
        self.current_server_index = 0
        self.lock = threading.Lock()

    def get_next_server(self):
        with self.lock:
            server = self.backend_servers[self.current_server_index]
            self.current_server_index = (self.current_server_index + 1) % len(self.backend_servers)
            return server

    def handle_client(self, client_socket):
        backend_server_address = self.get_next_server()
        try:
            backend_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            backend_socket.connect(backend_server_address)

            # Forward request from client to backend
            request = client_socket.recv(4096)
            backend_socket.sendall(request)

            # Forward response from backend to client
            response = backend_socket.recv(4096)
            client_socket.sendall(response)

        except Exception as e:
            print(f"Error handling request: {e}")
        finally:
            client_socket.close()
            if 'backend_socket' in locals():
                backend_socket.close()

    def start(self, listen_port):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(('', listen_port))
        server_socket.listen(5)
        print(f"Load balancer listening on port {listen_port}")

        while True:
            client_socket, addr = server_socket.accept()
            print(f"Accepted connection from {addr}")
            client_handler = threading.Thread(target=self.handle_client, args=(client_socket,))
            client_handler.start()

if __name__ == "__main__":
    # Backend servers can be provided via the BACKEND_SERVERS environment variable
    # Format: host1:port1,host2:port2
    env_backends = os.environ.get('BACKEND_SERVERS')
    if env_backends:
        backend_servers = []
        for part in env_backends.split(','):
            host, port = part.split(':')
            backend_servers.append((host.strip(), int(port.strip())))
    else:
        # Default backends (use host.docker.internal if you want host services)
        backend_servers = [('localhost', 8001), ('localhost', 8002)]

    load_balancer = LoadBalancer(backend_servers)
    load_balancer.start(8000)  # Load balancer listens on port 8000