import socket
import argparse
from threading import Thread

def handle_request(client_socket):
    request_data = client_socket.recv(1024).decode('utf-8')
    if not request_data:
        return
    
    request_lines = request_data.split('\r\n')
    method, path, _ = request_lines[0].split()
    
    if method == 'GET':
        response_data = 'HTTP/1.1 200 OK\r\n\r\nHello, this is a simple HTTP server!'
    elif method == 'POST':
        content_length = int(request_lines[-1].split(': ')[-1])
        request_body = client_socket.recv(content_length).decode('utf-8')
        response_data = f'HTTP/1.1 200 OK\r\n\r\nReceived POST data: {request_body}'
    else:
        response_data = 'HTTP/1.1 400 Bad Request\r\n\r\nInvalid request method'
    
    client_socket.sendall(response_data.encode('utf-8'))
    client_socket.close()

def run_server(host, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f'Server listening on {host}:{port}')

    while True:
        client_socket, client_address = server_socket.accept()
        print(f'Accepted connection from {client_address}')
        client_handler = Thread(target=handle_request, args=(client_socket,))
        client_handler.start()

def main():
    parser = argparse.ArgumentParser(description='Simple HTTP Server')
    parser.add_argument('-i', '--host', default='localhost', help='Server host')
    parser.add_argument('-p', '--port', type=int, default=8080, help='Server port')
    args = parser.parse_args()

    run_server(args.host, args.port)

if __name__ == '__main__':
    main()
