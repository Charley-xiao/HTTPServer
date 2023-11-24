import socket
import argparse
from urllib.parse import urlparse, parse_qs
from threading import Thread
from queue import Queue
import base64
import os

def check_authorization(username, password):
    # TODO: change authorization logic
    if username == 'admin' and password == 'admin':
        return True
    else:
        return False

def worker(queue):
    while True:
        client_socket = queue.get()
        if client_socket is None:
            break  # Signal to exit the thread pool
        handle_request(client_socket)

def handle_request(client_socket):
    request_data = client_socket.recv(1024).decode('utf-8')
    if not request_data:
        return
    
    request_lines = request_data.split('\r\n')
    print(f'Request lines: {request_lines}')
    method, raw_path, _ = request_lines[0].split()
    print(f'Request method: {method}\nRequest path: {raw_path}')

    parsed_url = urlparse(raw_path)
    path = '/data' + parsed_url.path
    query_params = parse_qs(parsed_url.query)
    print(f'Parsed path: {path}\nQuery parameters: {query_params}')
    
    auth_header = None
    for line in request_lines:
        if line.startswith('Authorization: '):
            auth_header = line[len('Authorization: '):].strip()
            break
    print(f'Authorization header: {auth_header}')

    connection_header = None
    for line in request_lines:
        if line.startswith('Connection: '):
            connection_header = line[len('Connection: '):].strip()
            break
    print(f'Connection header: {connection_header}')

    range_header = None
    for line in request_lines:
        if line.startswith('Range: '):
            range_header = line[len('Range: '):].strip()
            break
    print(f'Range header: {range_header}')

    if 'q' in query_params: # TODO: change the logic
        query_value = query_params['q'][0]
        print(f'Query parameter q: {query_value}')

    if auth_header and auth_header.startswith('Basic '):
        encoded_credentials = auth_header[len('Basic '):]
        decoded_credentials = base64.b64decode(encoded_credentials).decode('utf-8')
        username, password = decoded_credentials.split(':')
        print(f'Username: {username}\nPassword: {password}')
        
        if check_authorization(username,password):
            print('Authorized')
            if range_header and method == 'GET': # TODO: support multirange requests
                try:
                    range_start, range_end = map(int, range_header[len('bytes='):].split('-'))
                except ValueError:
                    response_data = 'HTTP/1.1 400 Bad Request\r\n\r\nInvalid Range header'
                    client_socket.sendall(response_data.encode('utf-8'))
                    # if connection_header and connection_header == 'close':
                    client_socket.close()
                    return

                request_file_path = path[1:]
                file_size = os.path.getsize(request_file_path)

                if 0 <= range_start < file_size and range_start <= range_end < file_size:
                    with open(request_file_path, 'rb') as file:
                        file.seek(range_start)
                        content = file.read(range_end - range_start + 1)
                        response_data = f'HTTP/1.1 206 Partial Content\r\nContent-Range: bytes {range_start}-{range_end}/{file_size}\r\n\r\n'
                        client_socket.sendall(response_data.encode('utf-8') + content)
                        # if connection_header and connection_header == 'close':
                        client_socket.close()
                        return
                else:
                    response_data = 'HTTP/1.1 416 Range Not Satisfiable\r\n\r\n'
                    
            if method == 'GET':
                print('GET')
                response_data = 'HTTP/1.1 200 OK\r\n\r\nHello, this is a simple HTTP server!'
            elif method == 'POST':
                content_length = int(request_lines[-1].split(': ')[-1])
                request_body = client_socket.recv(content_length).decode('utf-8')
                response_data = f'HTTP/1.1 200 OK\r\n\r\nReceived POST data: {request_body}'
            else:
                response_data = 'HTTP/1.1 400 Bad Request\r\n\r\nInvalid request method'
            
        else:
            print('Unauthorized')
            response_data = 'HTTP/1.1 401 Unauthorized\r\n\r\nInvalid username or password'
    else:
        response_data = 'HTTP/1.1 401 Unauthorized\r\n\r\nAuthorization header missing or invalid'

    print(f'Response data: {response_data}')
    client_socket.sendall(response_data.encode('utf-8'))
    # if connection_header and connection_header == 'close':
    client_socket.close()

def run_server(host, port, num_workers):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f'Server listening on {host}:{port}')

    # worker_queue = Queue()

    # workers = [Thread(target=worker, args=(worker_queue,)) for _ in range(num_workers)]
    # for worker_thread in workers:
    #     worker_thread.start()

    # try:
    #     while True:
    #         client_socket, client_address = server_socket.accept()
    #         print(f'Accepted connection from {client_address}')
    #         worker_queue.put(client_socket)
    # except KeyboardInterrupt:
    #     for _ in range(num_workers):
    #         worker_queue.put(None)

    #     for worker_thread in workers:
    #         worker_thread.join()

    while True:
        client_socket, client_address = server_socket.accept()
        print(f'Accepted connection from {client_address}')
        client_handler = Thread(target=handle_request, args=(client_socket,))
        client_handler.start()

def main():
    parser = argparse.ArgumentParser(description='Simple HTTP Server with Authorization')
    parser.add_argument('-i', '--host', default='localhost', help='Server host')
    parser.add_argument('-p', '--port', type=int, default=8080, help='Server port')
    parser.add_argument('-w', '--workers', type=int, default=4, help='Number of worker threads')
    args = parser.parse_args()

    run_server(args.host, args.port, args.workers)

if __name__ == '__main__':
    main()
