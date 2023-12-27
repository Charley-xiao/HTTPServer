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
import shutil
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import Salsa20

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

    cursor.execute('INSERT OR REPLACE INTO users (username, password, email) VALUES (?, ?, ?)',
                   ('admin', 'admin', 'admin@mail.sustech.edu.cn'))
    cursor.execute('INSERT OR REPLACE INTO users (username, password, email) VALUES (?, ?, ?)',
                   ('client1', '123', 'client1@google.com'))

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
    preview_disabled = int(path.split('?p=')[1]) ^ 1 if '?p=' in path else 1
    path = path.split('?p=')[0]
    file_path = f'./data{path}'
    print(file_path)

    if os.path.exists(file_path):
        if os.path.isfile(file_path):
            # Check if the file is a text file for preview
            text_file_extensions = ['.txt', '.html', '.css', '.js', '.py']
            _, file_extension = os.path.splitext(file_path)
            is_text_file = file_extension.lower() in text_file_extensions
            print(f'is_text_file for {file_path}: ', is_text_file)

            if is_text_file and not preview_disabled:
                # Preview text-based files
                with open('preview.html', 'r') as preview:
                    preview_page = preview.read()
                    preview_page = preview_page.replace('insert_filename', f'{os.path.basename(file_path)}')
                    preview_page = preview_page.replace('insert_file_content', f'{open(file_path, "r").read()}')
                    preview_page = preview_page.replace('<a>Download</a>',
                                                        f'<a href="{path}" download>'
                                                        f'Download {os.path.basename(file_path)}</a>')
                    response_data = (f'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n'
                                     f'Content-Length: {len(preview_page)}\r\n\r\n{preview_page}')
                    client_socket.sendall(response_data.encode('utf-8'))
                    client_socket.close()
                return
            elif not preview_disabled:
                with open('preview.html', 'r') as preview:
                    preview_page = preview.read()
                    preview_page = preview_page.replace('insert_filename', f'{os.path.basename(file_path)}')
                    preview_page = preview_page.replace('<h4>File Details:</h4>',
                                                        '<h2>This file cannot be previewed.</h2>')
                    preview_page = preview_page.replace('<div class="file-preview">insert_file_content</div>', '')
                    preview_page = preview_page.replace('<a>Download</a>',
                                                        f'<a href="{path}" download>'
                                                        f'Download {os.path.basename(file_path)}</a>')
                    response_data = (f'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n'
                                     f'Content-Length: {len(preview_page)}\r\n\r\n{preview_page}')
                    client_socket.sendall(response_data.encode('utf-8'))
                    client_socket.close()
                return
            else:
                # Download the file
                with open(file_path, 'rb') as file:
                    file_content = file.read()
                    content_length = len(file_content)
                    content_type = get_content_type(file_path)
                    print(f'Content type: {content_type}')

                    response_data = (f'HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\n'
                                     f'Content-Length: {content_length}\r\n\r\n')
                    client_socket.sendall(response_data.encode('utf-8') + file_content)
                    client_socket.close()
                return
        elif os.path.isdir(file_path):
            # Handle directory listing
            files = os.listdir(file_path)
            files_list = '\n'.join(files)

            response_data = (f'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n'
                             f'Content-Length: {len(files_list)}\r\n\r\n{files_list}')
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


def list_files_and_directories(path, username):
    files_and_dirs = []
    try:
        for entry in os.listdir(path):
            entry_path = os.path.join(path, entry)
            d_entry_path = entry_path.replace(f'/data', '')
            d_entry_path = d_entry_path.replace('\\', '/')
            delete_path = d_entry_path[1:]
            if os.path.isfile(entry_path):
                files_and_dirs.append(f'''
                    <p class="file">
                        <!--<a href="{d_entry_path}" style="color: gold;">{entry}</a>-->
                        {entry}
                        <button class="downloadButton"><a href="{d_entry_path}?p=1">Download</a></button>
                        <button class="deleteButton" onclick="document.getElementById(\'{d_entry_path}\').style.display = \'block\';">Delete</button>
                        <form action="/delete?path={delete_path}" method="POST" style="display: none;" id="{d_entry_path}">
                            <button class="deleteButton" type="submit">I confirm to delete {entry}</button>
                        </form>
                    </p>''')
            elif os.path.isdir(entry_path):
                files_and_dirs.append(f'''
                    <p class="dir" onclick="toggleFolder(\'{entry}\')" id="{entry}">
                        {entry}
                        <button class="uploadButton"><a href="/upload?path={d_entry_path[1:]}">Upload</a></button>
                        <button class="deleteButton" onclick="document.getElementById(\'{d_entry_path[1:]}\').style.display = \'block\';">Delete</button>
                        <form action="/delete?path={d_entry_path[1:]}" method="POST" style="display: none;" id="{d_entry_path[1:]}">
                            <button class="deleteButton" type="submit">I confirm to delete {entry}</button>  
                        </form>
                    </p>
                ''')
                nested_entries = list_files_and_directories(entry_path, username)
                files_and_dirs.append(f'<div class="nested" id="nested_{entry}">{"".join(nested_entries)}</div>')
        return ''.join(files_and_dirs)
    except FileNotFoundError:
        return ''


def list_files_and_directories_plain(path):
    files_and_dirs = []
    try:
        for entry in os.listdir(path):
            entry_path = os.path.join(path, entry)
            d_entry_path = entry_path.replace(f'/data', '')
            d_entry_path = d_entry_path.replace('\\', '/')
            delete_path = d_entry_path[1:]
            if os.path.isfile(entry_path):
                files_and_dirs.append(f'{entry}')
            elif os.path.isdir(entry_path):
                files_and_dirs.append(f'{entry}')
                nested_entries = list_files_and_directories_plain(entry_path)
                files_and_dirs.append(f'{"".join(nested_entries)}')
        return ', '.join(files_and_dirs)
    except FileNotFoundError:
        return ''


def return_index_page(username, path=None):
    if path is None:
        path = f'/data/{username}'
    with open('index.html', 'r') as file:
        index_page = file.read()
        index_page = index_page.replace('insert_username', f'{username}')
        index_page = index_page.replace('<p class="file">1</p>',
                                        list_files_and_directories(f'.{path}', username))
        index_page = index_page.replace('<script></script>', '''<script>
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
        return index_page


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
            login_page = login_page.replace('<input type="submit" value="Login">',
                                            '<p style="color:green">Registration successful</p>'
                                            '<input type="submit" value="Login">')
            response_data = 'HTTP/1.1 200 OK\r\n\r\n' + login_page
        client_socket.sendall(response_data.encode('utf-8'))
        # if connection_header and connection_header == 'close':
        client_socket.close()
        # create root directory for the user
        os.mkdir(f'./data/{username}')
        return
    else:
        conn.close()
        with open('register.html', 'r') as file:
            register_page = file.read()
            register_page = register_page.replace('<input type="submit" value="Register">',
                                                  '<p style="color:red">Username already taken</p>'
                                                  '<input type="submit" value="Register">')
            response_data = 'HTTP/1.1 200 OK\r\n\r\n' + register_page
        client_socket.sendall(response_data.encode('utf-8'))
        # if connection_header and connection_header == 'close':
        client_socket.close()
        return


def determine_cookie(need_to_set_cookie):
    if need_to_set_cookie:
        return '\r\n' + need_to_set_cookie
    else:
        return '\r\n'


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

    encrypted_key_header = None
    for line in request_lines:
        if line.startswith('Encrypted key: '):
            encrypted_key_header = line[len('Encrypted key: '):].strip()
            break
    print(f'Encrypted Key header: {encrypted_key_header}')

    test_param = None
    if 'SUSTech-HTTP' in query_params:
        test_param = query_params['SUSTech-HTTP'][0]
        print(f'Query parameter SUSTech-HTTP: {test_param}')

    if 'path' in query_params:
        upload_path = query_params['path']
        if upload_path[0] != '/':
            query_params['path'] = '/' + upload_path
        if upload_path[-1] == '/':
            query_params['path'] = query_params['path'][:-1]
        print(f'Query parameter path: {upload_path}')

    need_to_set_cookie = None
    username = None
    password = None

    if raw_path == '/favicon.svg':
        with open('favicon.svg', 'rb') as file:
            file_content = file.read()
            content_length = len(file_content)
            content_type = 'image/svg+xml'

            response_data = (f'HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\n'
                             f'Content-Length: {content_length}\r\n\r\n')
            client_socket.sendall(response_data.encode('utf-8') + file_content)
            client_socket.close()
        return
    elif auth_header and auth_header.startswith('Basic '):
        encoded_credentials = auth_header[len('Basic '):]
        decoded_credentials = base64.b64decode(encoded_credentials).decode('utf-8')
        username, password = decoded_credentials.split(':')
        print(f'Username: {username}\nPassword: {password}')

        if not check_authorization(username, password) and not range_header:
            response_data = 'HTTP/1.1 401 Unauthorized\r\n\r\nInvalid username or password'
            client_socket.sendall(response_data.encode('utf-8'))
            return
        if not cookie_header or not username_from_cookie:
            print('Setting new session ID in cookie')
            need_to_set_cookie = set_cookie_header(username)
            # response_data = f'HTTP/1.1 200 OK\r\n{set_cookie_header(username)}\r\n\r\nHello, {username}!'
            # client_socket.sendall(response_data.encode('utf-8'))
            # client_socket.close()
            # return

    if path.split('/')[-1] == 'encrypt':
        if 'request' in query_params and query_params['request'] == 'public_key':
            random_generator = Random.new().read
            rsa = RSA.generate(2048, random_generator)
            # 生成私钥
            private_key = rsa.exportKey()
            print(private_key.decode('utf-8'))
            # 生成公钥
            public_key = rsa.publickey().exportKey()
            print(public_key.decode('utf-8'))

            with open('./data/encryption/server/rsa_private_key.pem', 'wb') as f:
                f.write(private_key)

            with open('./data/encryption/server/rsa_public_key.pem', 'wb') as f:
                f.write(public_key)

            response_data = f'HTTP/1.1 200 OK\r\n\r\n' + public_key.decode('utf-8')
            print(f'Response data: {response_data}')
            client_socket.sendall(response_data.encode('utf-8'))
            client_socket.close()
            return
        elif 'response' in query_params and query_params['response'] == 'encrypted':
            if encrypted_key_header:
                with open('./data/encryption/server/rsa_private_key.pem', 'rb') as f:
                    private_key = f.read()
                decipher = PKCS1_OAEP.new(RSA.importKey(private_key))
                key = decipher.decrypt(base64.b64decode(encrypted_key_header))
                print(f'Decrypted key: {key}')
                with open('data/encryption/server/Salsa20_key.pem', 'wb') as f:
                    f.write(key)
                response_data = f'HTTP/1.1 200 OK\r\n\r\n' + 'Key received'
                print(f'Response data: {response_data}')
                client_socket.sendall(response_data.encode('utf-8'))
                client_socket.close()
                return
            else:
                response_data = f'HTTP/1.1 400 Bad Request\r\n\r\n'
                print(f'Response data: {response_data}')
                client_socket.sendall(response_data.encode('utf-8'))
                client_socket.close()
                return
        elif 'file' in query_params:
            encrypt_transmit_file_path = '.' + '/'.join(path.split('/')[:-1]) + '/' + query_params['file']
            print(f'Encrypt transmit file path: {encrypt_transmit_file_path}')
            if os.path.exists(encrypt_transmit_file_path):
                with open(encrypt_transmit_file_path, 'rb') as f:
                    file_content = f.read()
                    with open('data/encryption/server/Salsa20_key.pem', 'rb') as f_Salsa20_key:
                        key = f_Salsa20_key.read()
                    cipher = Salsa20.new(key=key)
                    cipher_text = cipher.encrypt(file_content)
                    content_length = len(cipher_text)
                    content_type = get_content_type(encrypt_transmit_file_path)
                    print(f'Content type: {content_type}')

                    response_data = (f'HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\n'
                                     f'Content-Length: {content_length}\r\n\r\n')
                    client_socket.sendall(response_data.encode('utf-8') + file_content)
                    print(f'Response data: {response_data}')
                    print('Successfully encrypted and transmitted file')
                    client_socket.close()
                return
            else:
                response_data = 'HTTP/1.1 404 Not Found\r\n\r\nFile not found'
                client_socket.sendall(response_data.encode('utf-8'))
                client_socket.close()
                return

                # if check_authorization(username,password):
    #     print('Authorized')
    #     if cookie_header and username_from_cookie:
    #         print(f'User from cookie: {username_from_cookie}')
    #         response_data = f'HTTP/1.1 200 OK\r\n{set_cookie_header(username_from_cookie)}\r\n\r\n
    #         f'Hello, {username_from_cookie}!'
    #     else:
    #         # Set a new session ID in the cookie for the user
    #         print('Setting new session ID in cookie')
    #         response_data = f'HTTP/1.1 200 OK\r\n{set_cookie_header(username)}\r\n\r\nHello, {username}!'
    #         client_socket.sendall(response_data.encode('utf-8'))
    #         client_socket.close()

    #     if range_header and method == 'GET': # TODO: support multirange requests
    #         try:
    #             range_start, range_end = map(int, range_header[len('bytes='):].split('-'))
    #         except ValueError:
    #             response_data = 'HTTP/1.1 400 Bad Request\r\n\r\nInvalid Range header'
    #             client_socket.sendall(response_data.encode('utf-8'))
    #             # if connection_header and connection_header == 'close':
    #             client_socket.close()
    #             return

    #         request_file_path = path[1:]
    #         file_size = os.path.getsize(request_file_path)

    #         if 0 <= range_start < file_size and range_start <= range_end < file_size:
    #             with open(request_file_path, 'rb') as file:
    #                 file.seek(range_start)
    #                 content = file.read(range_end - range_start + 1)
    #                 response_data = f'HTTP/1.1 206 Partial Content\r\n
    #                 f'Content-Range: bytes {range_start}-{range_end}/{file_size}\r\n\r\n'
    #                 client_socket.sendall(response_data.encode('utf-8') + content)
    #                 # if connection_header and connection_header == 'close':
    #                 client_socket.close()
    #                 return
    #         else:
    #             response_data = 'HTTP/1.1 416 Range Not Satisfiable\r\n\r\n'

    #     if method == 'GET':
    #         print('GET')
    #         if test_param and test_param.startswith('1'): # List the files and directories
    #             print(f'Listing files and directories in ./data/{username}')
    #             response_data = 'HTTP/1.1 200 OK\r\n\r\n' +
    #             list_files_and_directories_plain(f'./data/{username}',username)
    #         elif test_param and test_param.startswith('0'): # Return the index page
    #             print('Returning index page')
    #             index_page = return_index_page(username)
    #             response_data = 'HTTP/1.1 200 OK\r\n\r\n' + index_page
    #         elif raw_path == '/':
    #             print('Returning index page')
    #             index_page = return_index_page(username)
    #             response_data = 'HTTP/1.1 200 OK\r\n\r\n' + index_page
    #         else:
    #             handle_file_request(client_socket, f'/{username}{raw_path}', auth_header)
    #             return
    #     elif method == 'POST':
    #         content_length = None
    #         for line in request_lines:
    #             if 'Content-Length' in line:
    #                 content_length = int(line.split(': ')[1])
    #                 break
    #         request_body = client_socket.recv(content_length).decode('utf-8')
    #         response_data = f'HTTP/1.1 200 OK\r\n\r\nReceived POST data: {request_body}'
    #     elif method == 'HEAD':
    #         response_data = f'HTTP/1.1 200 OK\r\n\r\n'
    #     else:
    #         response_data = 'HTTP/1.1 400 Bad Request\r\n\r\nInvalid request method'

    # else:
    #     print('Unauthorized')
    #     response_data = 'HTTP/1.1 401 Unauthorized\r\n\r\nInvalid username or password'

    if method == 'HEAD':
        if cookie_header and username_from_cookie or auth_header and auth_header.startswith(
                'Basic ') and check_authorization(username, password):
            response_data = f'HTTP/1.1 200 OK\r\n\r\n\r\n'
        else:
            response_data = f'HTTP/1.1 401 Unauthorized\r\n\r\n'
    elif range_header:
        if method != 'GET':
            response_data = 'HTTP/1.1 400 Bad Request\r\n\r\nInvalid request method'
        if cookie_header and username_from_cookie or auth_header and auth_header.startswith(
                'Basic '):
            # and check_authorization(username, password):

            request_file_path = path[1:]
            file_size = os.path.getsize(request_file_path)

            range1 = range_header.split(',')
            valid = False
            valid_range = []
            for i in range(len(range1)):
                start = int(range1[i].split('-')[0]) if range1[i].split('-')[0] else None
                print(f'start: {start}')
                end = int(range1[i].split('-')[1]) if range1[i].split('-')[1] else None
                print(f'end: {end}')
                if ((not start or 0 <= start < file_size) and (not end or 0 <= end < file_size)
                        and (start or end or start == 0) and (start <= end if start and end else True)):
                    valid = True
                    if end != 0 and not end:
                        end = file_size - 1
                    elif start != 0 and not start:
                        start = file_size - end
                        end = file_size - 1
                    valid_range.append((start, end))

            if not valid:
                response_data = b'HTTP/1.1 416 Range Not Satisfiable\r\n\r\n'
                client_socket.sendall(response_data)
                client_socket.close()
                return
            else:
                response_data = b'HTTP/1.1 206 Partial Content\r\n'
                if len(valid_range) == 1:
                    content_type = get_content_type(request_file_path)
                    response_data += f'Content-type= {content_type}\r\n'.encode('utf-8')
                    print(f'Content type: {content_type}')
                    sub_response_data = b'--THISISMYSELFDIFINEDBOUNDARY\r\n'
                    start = valid_range[0][0]
                    end = valid_range[0][1]
                    with open(request_file_path, 'rb') as file:
                        file.seek(start)
                        content = file.read(end - start + 1)
                        sub_response_data += f'Content-range= bytes {start}-{end}/{file_size}\r\n\r\n'.encode('utf-8')
                        print(f'Content-range= bytes {start}-{end}/{file_size}')
                        sub_response_data += content
                        sub_response_data += b'\r\n'

                    content_length = len(sub_response_data)
                    response_data += f'Content-Length: {content_length}\r\n\r\n'.encode('utf-8')
                    response_data += sub_response_data
                    client_socket.sendall(response_data)
                    client_socket.close()
                    return
                else:
                    response_data += b'Content-type= multipart/byteranges; boundary=THISISMYSELFDIFINEDBOUNDARY\r\n'
                    sub_response_data = b''
                    content_type = get_content_type(request_file_path)
                    for i in range(len(valid_range)):
                        sub_response_data += b'--THISISMYSELFDIFINEDBOUNDARY\r\n'
                        start = valid_range[i][0]
                        end = valid_range[i][1]
                        with open(request_file_path, 'rb') as file:
                            file.seek(start)
                            content = file.read(end - start + 1)
                            print(f'Content type: {content_type}')
                            print(f'Content-range= bytes {start}-{end}/{file_size}')
                            sub_response_data += (f'Content-type= {content_type}\r\n'
                                                  f'Content-range= bytes {start}-{end}/{file_size}\r\n\r\n').encode(
                                'utf-8')
                            sub_response_data += content
                            sub_response_data += b'\r\n'

                    content_length = len(sub_response_data)
                    response_data += f'Content-Length: {content_length}\r\n\r\n'.encode('utf-8')
                    response_data += sub_response_data
                    client_socket.sendall(response_data)
                    client_socket.close()
                    return

    elif test_param and test_param.startswith('1'):  # List the files and directories
        print(f'Listing files and directories in .{path}')
        response_data = (f'HTTP/1.1 200 OK{determine_cookie(need_to_set_cookie)}\r\n\r\n[' +
                         list_files_and_directories_plain(f'.{path}') + ']')
    elif test_param and test_param.startswith('0'):  # Return the index page
        print('Returning index page')
        index_page = return_index_page(username, path)
        response_data = f'HTTP/1.1 200 OK{determine_cookie(need_to_set_cookie)}\r\n\r\n{index_page}'
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
                response_data = f'HTTP/1.1 200 OK{determine_cookie(need_to_set_cookie)}\r\n\r\n{login_page}'
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
        if check_authorization(username, password):
            print('Authorized')
            if cookie_header and username_from_cookie:
                print(f'User from cookie: {username_from_cookie}')
                response_data = (f'HTTP/1.1 200 OK\r\n{set_cookie_header(username_from_cookie)}\r\n\r\n'
                                 f'Hello, {username_from_cookie}!')
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
                login_page = login_page.replace('<input type="submit" value="Login">',
                                                '<p style="color:red">Invalid username or password</p>'
                                                '<input type="submit" value="Login">')
                response_data = 'HTTP/1.1 401 Unauthorized\r\n\r\n' + login_page
            client_socket.sendall(response_data.encode('utf-8'))
            # if connection_header and connection_header == 'close':
            client_socket.close()
            return
    elif raw_path == '/index' and method == 'GET':
        if cookie_header and username_from_cookie:
            index_page = return_index_page(username_from_cookie)
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
            response_data = ('HTTP/1.1 302 Found\r\nLocation: /login\r\n'
                             'Set-Cookie: session-id=; Path=/; HttpOnly\r\n\r\n') + login_page
        client_socket.sendall(response_data.encode('utf-8'))
        # if connection_header and connection_header == 'close':
        client_socket.close()
        return
    elif raw_path.startswith('/upload') and method == 'GET':
        if cookie_header and username_from_cookie:
            with open('upload.html', 'r') as file:
                upload_page = file.read()
                upload_page = upload_page.replace('insert_username', f'{username_from_cookie}')
                tmp = query_params['path']
                upload_page = upload_page.replace('insert_path', f'{tmp}')
                response_data = 'HTTP/1.1 200 OK\r\n\r\n' + upload_page
            client_socket.sendall(response_data.encode('utf-8'))
            # if connection_header and connection_header == 'close':
            client_socket.close()
            return
        else:
            response_data = 'HTTP/1.1 302 Found\r\nLocation: /login\r\n\r\n'
            client_socket.sendall(response_data.encode('utf-8'))
            client_socket.close()
            return
    elif raw_path.startswith('/upload') and method == 'POST':
        print('POST')
        print(check_authorization(username, password))
        print(query_params['path'])
        print(query_params['path'].split('/')[1] == username)
        if cookie_header and username_from_cookie or auth_header and auth_header.startswith(
                'Basic ') and check_authorization(username, password) and query_params['path'] and \
                query_params['path'].split('/')[1] == username:
            content_length = None
            for line in request_lines:
                if 'Content-Length' in line:
                    content_length = int(line.split(': ')[1])
                    break
            print(f'Content length: {content_length}')
            request_body = client_socket.recv(content_length).decode('utf-8')
            print(f'Request body: {request_body}')
            file_name = ','.join(request_lines).split('filename="')[1].split('"')[0]
            print(f'File name: {file_name}')
            # file_content = request_body.split('\r\n\r\n', 1)
            file_content = request_body.split('--')[0]
            print(f'File content: {file_content}')
            tmp = query_params['path']
            # convert file_content to bytes-like object
            file_content = file_content.encode('utf-8')
            with open(f'./data/{tmp}/{file_name}', 'wb') as file:
                file.write(file_content)
            response_data = f'HTTP/1.1 302 Found\r\nLocation: /index\r\n\r\n'
            client_socket.sendall(response_data.encode('utf-8'))
            client_socket.close()
            return
        elif auth_header and auth_header.startswith('Basic ') and check_authorization(username, password) and \
                query_params['path'] and query_params['path'].split('/')[1] != username:
            # return 403
            print('403')
            with open('403.html', 'r') as file:
                page = file.read()
                page = page.replace('insert_username', f'{username_from_cookie}')
                page = page.replace('error_message', 'You are not allowed to upload files to this directory.')
                response_data = 'HTTP/1.1 403 Forbidden\r\n\r\n' + page
                client_socket.sendall(response_data.encode('utf-8'))
                client_socket.close()
                return
        else:
            print('302')
            response_data = 'HTTP/1.1 302 Found\r\nLocation: /login\r\n\r\n'
            client_socket.sendall(response_data.encode('utf-8'))
            client_socket.close()
            return
    elif raw_path.startswith('/upload'):
        # Method not allowed
        response_data = 'HTTP/1.1 405 Method Not Allowed\r\n\r\n'
    elif raw_path.startswith('/delete') and method == 'POST':
        if cookie_header and username_from_cookie:
            tmp = query_params['path']
            print(tmp.split('/')[0])
            if tmp.split('/')[1] != username_from_cookie:
                # return 403
                with open('403.html', 'r') as file:
                    page = file.read()
                    page = page.replace('insert_username', f'{username_from_cookie}')
                    page = page.replace('error_message', 'You are not allowed to delete this file.')
                    response_data = 'HTTP/1.1 403 Forbidden\r\n\r\n' + page
                    client_socket.sendall(response_data.encode('utf-8'))
                    client_socket.close()
                    return
            try:
                if os.path.isfile(f'./data/{tmp}'):
                    os.remove(f'./data/{tmp}')
                elif os.path.isdir(f'./data/{tmp}'):
                    shutil.rmtree(f'./data/{tmp}')
            except FileNotFoundError or OSError:
                with open('404.html', 'r') as file:
                    page = file.read()
                    page = page.replace('insert_username', f'{username_from_cookie}')
                    response_data = 'HTTP/1.1 404 Not Found\r\n\r\n' + page
                    client_socket.sendall(response_data.encode('utf-8'))
                    client_socket.close()
                    return
            response_data = f'HTTP/1.1 302 Found\r\nLocation: /index\r\n\r\n'
            client_socket.sendall(response_data.encode('utf-8'))
            client_socket.close()
            return
        else:
            response_data = 'HTTP/1.1 302 Found\r\nLocation: /login\r\n\r\n'
            client_socket.sendall(response_data.encode('utf-8'))
            client_socket.close()
            return
    elif raw_path.startswith('/delete'):
        # Method not allowed
        response_data = 'HTTP/1.1 405 Method Not Allowed\r\n\r\n'
    elif query_params and 'chunked' in query_params and query_params['chunked'] == '1':
        if method != 'GET':
            response_data = 'HTTP/1.1 405 Method Not Allowed\r\n\r\n'
        else:
            # Open the file for reading in binary mode
            file_path = '.' + path
            try:
                with open(file_path, 'rb') as file:
                    # Send the HTTP headers with Transfer-Encoding: chunked
                    client_socket.sendall(b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n'
                                          b'Content-Type: application/octet-stream\r\n\r\n')
                    print('Sent headers')

                    # Read the file in chunks and send them using chunked encoding
                    chunk_size = 5  # Set your desired chunk size
                    while True:
                        chunk = file.read(chunk_size)
                        if not chunk:
                            break
                        chunk_size_hex = hex(len(chunk))[2:].encode('utf-8')
                        client_socket.sendall(chunk_size_hex + b'\r\n' + chunk + b'\r\n')
                        print(f'Sent chunk of size {len(chunk)}')

                    # Send the final chunk with size 0 to signal the end
                    client_socket.sendall(b'0\r\n\r\n')
                    print('Sent final chunk')
                    client_socket.close()
                    return
            except FileNotFoundError:
                # Handle file not found
                response_data = 'HTTP/1.1 404 Not Found\r\n\r\nFile not found'
    elif path.startswith('/data'):
        # first check if authorized
        if cookie_header and username_from_cookie or auth_header and auth_header.startswith(
                'Basic ') and check_authorization(username, password):
            if method == 'POST':
                response_data = 'HTTP/1.1 405 Method Not Allowed\r\n\r\n'
            elif raw_path == '/':
                print('Returning index page')
                index_page = return_index_page(username_from_cookie)
                print('Returned')
                response_data = f'HTTP/1.1 200 OK{determine_cookie(need_to_set_cookie)}\r\n\r\n{index_page}'
                client_socket.sendall(response_data.encode('utf-8'))
                # if connection_header and connection_header == 'close':
                client_socket.close()
            else:
                handle_file_request(client_socket, raw_path, auth_header)
                return
        else:
            response_data = 'HTTP/1.1 401 Unauthorized\r\n\r\nWWW-Authenticate: Basic realm="Authorization required"'
    elif cookie_header and username_from_cookie:
        if method == 'POST':
                response_data = 'HTTP/1.1 405 Method Not Allowed\r\n\r\n'
        elif raw_path == '/':
            print('Returning index page')
            index_page = return_index_page(username_from_cookie)
            response_data = 'HTTP/1.1 200 OK\r\n\r\n' + index_page
        else:
            # Have logged in but tried to access a page that doesn't exist
            with open('404.html', 'r') as file:
                page = file.read()
                page = page.replace('insert_username', f'{username_from_cookie}')
                response_data = 'HTTP/1.1 404 Not Found\r\n\r\n' + page

    else:
        response_data = 'HTTP/1.1 401 Unauthorized\r\n\r\nWWW-Authenticate: Basic realm="Authorization required"'

    try:
        print(f'Response data: {response_data}')
        client_socket.sendall(response_data.encode('utf-8'))
        # if connection_header and connection_header == 'close':
        client_socket.close()
    except BrokenPipeError:
        print('Broken pipe')
    except OSError:
        pass


def run_server(host, port, num_workers):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f'server listening on {host}:{port}')

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
    parser = argparse.ArgumentParser(description='Simple HTTP server with Authorization')
    parser.add_argument('-i', '--host', default='localhost', help='server host')
    parser.add_argument('-p', '--port', type=int, default=8080, help='server port')
    parser.add_argument('-w', '--workers', type=int, default=4, help='Number of worker threads')
    args = parser.parse_args()

    initialize_database()
    run_server(args.host, args.port, args.workers)


if __name__ == '__main__':
    main()
