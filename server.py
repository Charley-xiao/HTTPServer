import socket
import argparse
from threading import Thread
from queue import Queue
import base64
import os
import hashlib
import datetime
import mimetypes
import sqlite3

session_storage = {}
DATABASE_FILE = 'users.db'

def initialize_database():
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT NOT NULL
        )
    ''')

    cursor.execute('INSERT OR REPLACE INTO users (username, password, email) VALUES (?, ?, ?)', ('admin', 'admin','admin@mail.sustech.edu.cn'))
    cursor.execute('INSERT OR REPLACE INTO users (username, password, email) VALUES (?, ?, ?)', ('client1', 'password1','client1@google.com'))

    conn.commit()
    conn.close()

def generate_session_id(username):
    timestamp = str(datetime.datetime.now())
    data = f"{username}{timestamp}"
    session_id = hashlib.sha256(data.encode('utf-8')).hexdigest()
    return session_id

def set_cookie_header(username, expiration_days=7):
    session_id = generate_session_id(username)
    print(f'Session ID generated from {username}: {session_id}')
    expiration_date = datetime.datetime.now() + datetime.timedelta(days=expiration_days)
    formatted_expiration_date = expiration_date.strftime("%a, %d-%b-%Y %H:%M:%S GMT")
    session_storage[session_id] = username 
    return f'Set-Cookie: session-id={session_id}; Expires={formatted_expiration_date}; Path=/; HttpOnly\r\n'

def get_username_from_cookie(cookie):
    cookie_parts = cookie.split(';')
    session_id = None
    for cookie_part in cookie_parts:
        if cookie_part.strip().startswith('session-id='):
            session_id = cookie_part.strip()[len('session-id='):]
            break
    print(f'Session ID from cookie: {session_id}')
    print(f'Session storage: {session_storage}')
    return session_storage.get(session_id, None)

def check_authorization(username, password):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username=? AND password=?', (username, password))
    user = cursor.fetchone()
    conn.close()
    return user is not None
    
def get_content_type(file_path):
    mime, encoding = mimetypes.guess_type(file_path)
    return mime if mime else 'application/octet-stream'

def handle_file_request(client_socket, path, auth_header):
    # Check if the client is authorized
    # if not auth_header or not auth_header.startswith('Basic '):
    #     response_data = 'HTTP/1.1 401 Unauthorized\r\n\r\nWWW-Authenticate: Basic realm="Authorization required"'
    #     client_socket.sendall(response_data.encode('utf-8'))
    #     return

    # encoded_credentials = auth_header[len('Basic '):]
    # decoded_credentials = base64.b64decode(encoded_credentials).decode('utf-8')
    # username, password = decoded_credentials.split(':')

    # if not check_authorization(username, password):
    #     response_data = 'HTTP/1.1 401 Unauthorized\r\n\r\nInvalid username or password'
    #     client_socket.sendall(response_data.encode('utf-8'))
    #     return

    file_path = f'./data{path}'

    if os.path.exists(file_path):
        if os.path.isfile(file_path):
            # Check if the file is a text file for preview
            text_file_extensions = ['.txt', '.html', '.css', '.js', '.py']
            _, file_extension = os.path.splitext(file_path)
            is_text_file = file_extension.lower() in text_file_extensions
            print(f'is_text_file for {file_path}: ', is_text_file)

            if is_text_file:
                # Preview text-based files
                with open(file_path, 'r') as file:
                    file_content = file.read()
                    content_length = len(file_content)
                    content_type = get_content_type(file_path)

                    response_data = f'HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {content_length}\r\n\r\n{file_content}'
                    client_socket.sendall(response_data.encode('utf-8'))
                    client_socket.close()
                return
            else:
                # Provide a link for non-text files
                download_link = f'<a href="{path}" download>Download {os.path.basename(file_path)}</a>'
                response_data = f'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {len(download_link)}\r\n\r\n{download_link}'
                client_socket.sendall(response_data.encode('utf-8'))
                client_socket.close()
                return
        elif os.path.isdir(file_path):
            # Handle directory listing
            files = os.listdir(file_path)
            files_list = '\n'.join(files)

            response_data = f'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {len(files_list)}\r\n\r\n{files_list}'
            client_socket.sendall(response_data.encode('utf-8'))
    else:
        # Handle file not found
        response_data = 'HTTP/1.1 404 Not Found\r\n\r\nFile not found'
        client_socket.sendall(response_data.encode('utf-8'))
    
    client_socket.close()

def worker(queue):
    while True:
        client_socket = queue.get()
        if client_socket is None:
            break  # Signal to exit the thread pool
        handle_request(client_socket)

def parse_url(raw_path):
    if "://" in raw_path:
        raw_path = raw_path.split("://", 1)[1]

    parts = raw_path.split("/", 1)
    path = '/data' + '/' + parts[-1]
    parts = path.split("?")
    path = path.split("?")[0]

    query_params = {}
    if len(parts) > 1:
        try:
            query_params = dict([p.split("=") for p in parts[1].split("&")])
        except ValueError:
            pass

    return path, query_params

def list_files_and_directories(path,username):
    files_and_dirs = []
    try:
        for entry in os.listdir(path):
            entry_path = os.path.join(path, entry)
            if os.path.isfile(entry_path):
                d_entry_path = entry_path.replace(f'/data','')
                files_and_dirs.append(f'<p class="file"><a href="{d_entry_path}" style="color: gold;">{entry}</a></p>')
            elif os.path.isdir(entry_path):
                files_and_dirs.append(f'<p class="dir" onclick="toggleFolder(\'{entry}\')" id="{entry}">{entry}</p>')
                nested_entries = list_files_and_directories(entry_path,username)
                files_and_dirs.append(f'<div class="nested" id="nested_{entry}">{"".join(nested_entries)}</div>')
        return ''.join(files_and_dirs)
    except FileNotFoundError:
        return ''

def handle_registration(client_socket, request_lines):
    content_length = None
    for line in request_lines:
        if 'Content-Length' in line:
            content_length = int(line.split(': ')[1])
            break
    print(f'Content length: {content_length}')
    # request_body = client_socket.recv(content_length).decode('utf-8')
    username, password, email = request_lines[-1].split('&')
    username = username.split('=')[1]
    password = password.split('=')[1]
    email = email.split('=')[1]
    print(f'Username: {username}\nPassword: {password}\nEmail: {email}')
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username=?', (username,))
    user = cursor.fetchone()
    if user is None:
        cursor.execute('INSERT INTO users (username, password, email) VALUES (?, ?, ?)', (username, password, email))
        conn.commit()
        conn.close()
        with open('login.html', 'r') as file:
            login_page = file.read()
            login_page = login_page.replace('<input type="submit" value="Login">', '<p style="color:green">Registration successful</p><input type="submit" value="Login">')
            response_data = 'HTTP/1.1 200 OK\r\n\r\n' + login_page
        client_socket.sendall(response_data.encode('utf-8'))
        # if connection_header and connection_header == 'close':
        client_socket.close()
        return
    else:
        conn.close()
        with open('register.html', 'r') as file:
            register_page = file.read()
            register_page = register_page.replace('<input type="submit" value="Register">', '<p style="color:red">Username already taken</p><input type="submit" value="Register">')
            response_data = 'HTTP/1.1 200 OK\r\n\r\n' + register_page
        client_socket.sendall(response_data.encode('utf-8'))
        # if connection_header and connection_header == 'close':
        client_socket.close()
        return

def handle_request(client_socket):
    request_data = client_socket.recv(1024).decode('utf-8')
    if not request_data:
        return
    
    request_lines = request_data.split('\r\n')
    print(f'Request lines: {request_lines}')
    method, raw_path, _ = request_lines[0].split()
    print(f'Request method: {method}\nRequest path: {raw_path}')

    path, query_params = parse_url(raw_path)
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

    cookie_header = None
    for line in request_lines:
        if line.startswith('Cookie: '):
            cookie_header = line[len('Cookie: '):].strip()
            break
    print(f'Cookie header: {cookie_header}')
    username_from_cookie = get_username_from_cookie(cookie_header) if cookie_header else None

    if 'q' in query_params: # TODO: change the logic
        query_value = query_params['q'][0]
        print(f'Query parameter q: {query_value}')

    if raw_path == '/favicon.svg':
        with open('favicon.svg', 'rb') as file:
            file_content = file.read()
            content_length = len(file_content)
            content_type = 'image/svg+xml'

            response_data = f'HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {content_length}\r\n\r\n'
            client_socket.sendall(response_data.encode('utf-8') + file_content)
            client_socket.close()
        return
    elif auth_header and auth_header.startswith('Basic '):
        encoded_credentials = auth_header[len('Basic '):]
        decoded_credentials = base64.b64decode(encoded_credentials).decode('utf-8')
        username, password = decoded_credentials.split(':')
        print(f'Username: {username}\nPassword: {password}')
        
        if check_authorization(username,password):
            print('Authorized')
            if cookie_header and username_from_cookie:
                print(f'User from cookie: {username_from_cookie}')
                response_data = f'HTTP/1.1 200 OK\r\n{set_cookie_header(username_from_cookie)}\r\n\r\nHello, {username_from_cookie}!'
            else:
                # Set a new session ID in the cookie for the user
                print('Setting new session ID in cookie')
                response_data = f'HTTP/1.1 200 OK\r\n{set_cookie_header(username)}\r\n\r\nHello, {username}!'

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
                handle_file_request(client_socket, raw_path, auth_header)
                return
            elif method == 'POST':
                content_length = int(request_lines[-1].split(': ')[-1])
                request_body = client_socket.recv(content_length).decode('utf-8')
                response_data = f'HTTP/1.1 200 OK\r\n\r\nReceived POST data: {request_body}'
            else:
                response_data = 'HTTP/1.1 400 Bad Request\r\n\r\nInvalid request method'
            
        else:
            print('Unauthorized')
            response_data = 'HTTP/1.1 401 Unauthorized\r\n\r\nInvalid username or password'
    elif raw_path == '/login' and method == 'GET':
        print('cookie_header: ', cookie_header)
        print('username_from_cookie: ', username_from_cookie)
        if cookie_header and username_from_cookie:
            print(f'User from cookie: {username_from_cookie}')
            response_data = f'HTTP/1.1 302 Found\r\nLocation: /index\r\n\r\n'
        else:
            # Return the login page
            with open('login.html', 'r') as file:
                login_page = file.read()
                response_data = 'HTTP/1.1 200 OK\r\n\r\n' + login_page
            client_socket.sendall(response_data.encode('utf-8'))
            # if connection_header and connection_header == 'close':
            client_socket.close()
            return
    elif raw_path == '/login' and method == 'POST':
        # Check the credentials
        content_length = None
        for line in request_lines:
            if 'Content-Length' in line:
                content_length = int(line.split(': ')[1])
                break
        print(f'Content length: {content_length}')
        # request_body = client_socket.recv(content_length).decode('utf-8')
        username, password = request_lines[-1].split('&')
        username = username.split('=')[1]
        password = password.split('=')[1]
        print(f'Username: {username}\nPassword: {password}')
        if check_authorization(username,password):
            print('Authorized')
            if cookie_header and username_from_cookie:
                print(f'User from cookie: {username_from_cookie}')
                response_data = f'HTTP/1.1 200 OK\r\n{set_cookie_header(username_from_cookie)}\r\n\r\nHello, {username_from_cookie}!'
            else:
                # Set a new session ID in the cookie for the user
                print('Setting new session ID in cookie')
                response_data = f'HTTP/1.1 302 Found\r\nLocation: /index\r\n{set_cookie_header(username)}\r\n\r\n'
                client_socket.sendall(response_data.encode('utf-8'))

            response_data = f'HTTP/1.1 302 Found\r\nLocation: /index\r\n\r\n'
        else:
            print('Unauthorized')
            with open('login.html', 'r') as file:
                login_page = file.read()
                login_page = login_page.replace('<input type="submit" value="Login">', '<p style="color:red">Invalid username or password</p><input type="submit" value="Login">')
                response_data = 'HTTP/1.1 401 Unauthorized\r\n\r\n' + login_page
            client_socket.sendall(response_data.encode('utf-8'))
            # if connection_header and connection_header == 'close':
            client_socket.close()
            return
    elif raw_path == '/index' and method == 'GET':
        if cookie_header and username_from_cookie:
            with open('index.html', 'r') as file:
                index_page = file.read()
                index_page = index_page.replace('insert_username',f'{username_from_cookie}')
                index_page = index_page.replace('<p class="file">1</p>',list_files_and_directories(f'./data/{username_from_cookie}',username_from_cookie))
                index_page = index_page.replace('<script></script>','''
                    <script>
                    function toggleFolder(folderId){
                        var x = document.getElementById(\'nested_\' + folderId);
                        if (x.style.display === "none" || x.style.display === \"\") {
                            x.style.display = "block";
                        } 
                        else {
                            x.style.display = "none";
                        }
                    }
                    </script>
                ''')
                response_data = 'HTTP/1.1 200 OK\r\n\r\n' + index_page
            client_socket.sendall(response_data.encode('utf-8'))
            # if connection_header and connection_header == 'close':
            client_socket.close()
            return
        else:
            response_data = 'HTTP/1.1 302 Found\r\nLocation: /login\r\n\r\n'
            client_socket.sendall(response_data.encode('utf-8'))
            client_socket.close()
            return
    elif raw_path == '/register' and method == 'GET':
        with open('register.html', 'r') as file:
            register_page = file.read()
            response_data = 'HTTP/1.1 200 OK\r\n\r\n' + register_page
        client_socket.sendall(response_data.encode('utf-8'))
        # if connection_header and connection_header == 'close':
        client_socket.close()
        return
    elif raw_path == '/register' and method == 'POST':
        handle_registration(client_socket, request_lines)
        return
    elif raw_path.startswith('/logout') and method == 'GET':
        with open('login.html', 'r') as file:
            login_page = file.read()
            response_data = 'HTTP/1.1 302 Found\r\nLocation: /login\r\nSet-Cookie: session-id=; Path=/; HttpOnly\r\n\r\n' + login_page
        client_socket.sendall(response_data.encode('utf-8'))
        # if connection_header and connection_header == 'close':
        client_socket.close()
        return
    elif path.startswith('/data'):
        # first check if authorized
        if cookie_header and username_from_cookie:
            handle_file_request(client_socket, raw_path, auth_header)
            return
        response_data = 'HTTP/1.1 401 Unauthorized\r\n\r\nWWW-Authenticate: Basic realm="Authorization required"'
    else:
        response_data = 'HTTP/1.1 401 Unauthorized\r\n\r\nWWW-Authenticate: Basic realm="Authorization required"'

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

    worker_queue = Queue()

    workers = [Thread(target=worker, args=(worker_queue,)) for _ in range(num_workers)]
    for worker_thread in workers:
        worker_thread.start()

    try:
        while True:
            client_socket, client_address = server_socket.accept()
            print(f'Accepted connection from {client_address}')
            worker_queue.put(client_socket)
    except KeyboardInterrupt:
        for _ in range(num_workers):
            worker_queue.put(None)

        for worker_thread in workers:
            worker_thread.join()

    # while True:
    #     client_socket, client_address = server_socket.accept()
    #     print(f'Accepted connection from {client_address}')
    #     client_handler = Thread(target=handle_request, args=(client_socket,))
    #     client_handler.start()

def main():
    parser = argparse.ArgumentParser(description='Simple HTTP Server with Authorization')
    parser.add_argument('-i', '--host', default='localhost', help='Server host')
    parser.add_argument('-p', '--port', type=int, default=8080, help='Server port')
    parser.add_argument('-w', '--workers', type=int, default=4, help='Number of worker threads')
    args = parser.parse_args()

    initialize_database()
    run_server(args.host, args.port, args.workers)

if __name__ == '__main__':
    main()
