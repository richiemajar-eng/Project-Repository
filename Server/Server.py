import AiAnalyzer
import threading
import DBHandle
import Security
import socket
import time

IP_ADDRESS = "127.0.0.1"
PORT = 5050

server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
server.bind((IP_ADDRESS,PORT))
server.listen()

MAX_FAILED_ATTEMPTS = 5
PUNISH_TIME = 300 # in seconds = [5 mins = 300 seconds]
EXPIRE_TIME = 300 # in seconds = [5 mins = 300 seconds]
failed_attempts = {}

def upload(client , pressed, shift, conn):
    try:
        file = pressed['file_name']
        size = pressed["size"]

        data = DBHandle.recv_exact(client, size) # gets all the data

        print(f"Server is analyzing file: {file}")
        sample = Security.decrypt(data,shift)
        analyst = AiAnalyzer.analyze_with_gemma(sample, file)
        if analyst['state'] == "PASS":
            conn.upload_file(pressed, data, file)
            client.sendall(Security.encrypt("Uploaded Successfully and Verified by AI".encode(),shift))
        else:
            reason = analyst.get("main_reason", "Security Block")
            client.sendall(Security.encrypt(f"BLOCKED by Server AI. Reason: {reason}".encode(),shift))
    except:
        print("[Ollama] Analyse error")

def delete(client , file_name, shift, conn):
    msg = conn.del_file(file_name)
    msg = Security.encrypt(msg.encode(),shift)
    client.sendall(msg)

def download(client, file_name, shift, conn):
    content = conn.download_file(file_name)

    if content:
        size = (str(content[0])).encode()
        client.sendall(Security.encrypt(size,shift))
        client.sendall(content[1])
        print(f"{file_name} Successfully sent to donwload in client")
    else:
        client.sendall(Security.encrypt("not existing file".encode(), shift))

        print('File fetching error')


def backup_system(client,username,shift):
    file_storage_handle = DBHandle.MongoStorage(username)

    while True:
        pressed = client.recv(1024)
        pressed = Security.decrypt(pressed, shift)
        pressed = DBHandle.decapsullize(pressed)
        action = pressed["action"]

        match action:
            case "get_files":
                file_list = file_storage_handle.list_files()
                file_list = Security.encrypt(DBHandle.capsulize(file_list),shift)
                client.sendall(file_list)

            case "upload":
                print('entering upload')
                upload(client,pressed,shift,file_storage_handle)

            case "delete":
                file_name = pressed["file_name"]
                delete(client, file_name, shift, file_storage_handle)

            case "download":
                file_name = pressed["file_name"]
                download(client, file_name, shift, file_storage_handle)

            case "logout":
                break


def signup(username, email, password):
    users = DBHandle.LoginData()
    users.loader()

    user_state = users.user_taken(username)
    if not user_state:
        users.new_account(username, email, password)
        return 'success'
    elif user_state:
        return 'username is already taken'
    else:
        return 'error'


def login(username, password, addr):
    current_time = time.time()

    if addr not in failed_attempts:
        failed_attempts[addr] = {"count": 0, "lock_until": 0}

    user_data = failed_attempts[addr]

    if current_time < user_data["lock_until"]:
        time_left = int(user_data["lock_until"] - current_time)
        return f"blocked:{time_left}"


    if user_data["lock_until"] != 0:
        user_data["count"] = 0
        user_data["lock_until"] = 0

    users = DBHandle.LoginData()
    users.loader()

    login_info = users.verify(username, password)
    hashed_password = Security.hash_sha(password.encode())

    if users.user_taken(username) and login_info is not None:
        if hashed_password == login_info[3]:
            user_data["count"] = 0
            return 'success'
    user_data["count"] += 1
    if user_data["count"] > MAX_FAILED_ATTEMPTS:
        user_data["lock_until"] = PUNISH_TIME + current_time
        return f"blocked:{PUNISH_TIME}"
    return 'fail'


def two_step(client, username, password, shift):
    users = DBHandle.LoginData()
    users.loader()

    email = users.verify(username, password)[2]
    code = Security.send_verification_code(email)
    email_sent = time.time()
    while True:
        code_entry = Security.decrypt(client.recv(1024), shift).decode()
        current_time = time.time()
        if email_sent + EXPIRE_TIME < current_time:
            client.sendall(Security.encrypt("expired".encode(), shift))

        if code_entry == code:
            break
        client.sendall(Security.encrypt("fail".encode(), shift))
    client.sendall(Security.encrypt("success".encode(), shift))
    backup_system(client, username, shift)


def user_entry(client,shift,addr):
    while True:
        info = client.recv(1024)
        info = Security.decrypt(info,shift)
        info = DBHandle.decapsullize(info)
        action = info['action']
        username = info['username']
        password = info['password']
        match action:
            case "login":
                result = login(username, password, addr)
                print(result)
                client.sendall(Security.encrypt(result.encode(), shift))
                if result == "success":
                    two_step(client, username, password, shift)

            case "signup":
                email = info['email']
                result = signup(username, email,password)
                client.sendall(Security.encrypt(result.encode(),shift))


def handle_sessions():
    while True:
        client,addr = server.accept()

        Encrypt_Manager = Security.RSAKeyManager()
        public, private = Encrypt_Manager.generate_keys()

        client.sendall(public)

        shift = client.recv(256)
        shift = Encrypt_Manager.decrypt_shift(shift)

        th1 = threading.Thread(target=user_entry,args=(client,shift,addr[0]))
        th1.start()


if __name__ == '__main__':
    handle_sessions()