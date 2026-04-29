from pymongo import MongoClient
from ollama import ChatResponse
from ollama import chat
import hashlib
import sqlite3
import gridfs
import pickle
import json
import os



class LoginData:
    def __init__(self):
        self.db_name = "users.db"

        self.connection = sqlite3.connect(self.db_name)
        self.cursor = self.connection.cursor()


    def loader(self):
        sql = ("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            );
        """)
        self.cursor.execute(sql)
        self.connection.commit()


    def user_taken(self, user):
        params = (user,)
        self.cursor.execute("SELECT * FROM users WHERE username=?", params)
        row = self.cursor.fetchone()
        if row:
            return True
        else:
            return False


    def new_account(self, user, email, password):
        password = hashlib.sha256(password.encode()).hexdigest()
        params = (user, email, password)
        self.cursor.execute("INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)", params)
        self.connection.commit()


    def shutdown(self):
        self.connection.close()  # Shutting down.


    def verify(self,user ,password):
        password = hashlib.sha256(password.encode()).hexdigest()
        self.cursor.execute("SELECT * FROM users WHERE username=? AND password_hash=?", (user, password))
        row = self.cursor.fetchone()
        if row:
            return row
        return None





def capsulize(data):
    data = pickle.dumps(json.dumps(data))
    return data


def decapsullize(data):
    data = json.loads(pickle.loads(data))
    return data

class MongoStorage:
    def __init__(self, username):
        self.client = MongoClient(
            "mongodb+srv://richi_user:1234@cluster0.ghruhmw.mongodb.net/?appName=Cluster0"
        )
        self.db = self.client[f"{username}'s"]
        self.fs = gridfs.GridFS(self.db)

    def upload_file(self, metadata, file_content, filename):
        try:
            file_id = self.fs.put(
                file_content,
                filename=filename,  # <-- THIS is critical
                metadata=metadata
            )

            print(f"{filename} file uploaded")

        except:

            print(f"Error uploading file: ")

    def del_file(self, filename):
        file = self.fs.find_one({"filename": filename})
        if file:
            self.fs.delete(file._id)
            chunks_left = self.db["fs.chunks"].count_documents({"files_id": file._id})
            return f"{filename} was deleted successfully"
        else:
            return 'Not an existing file'

    def download_file(self, filename):
        file = self.fs.find_one({"filename": filename})

        if not file:
            return None

        grid_out = self.fs.get(file._id)
        return grid_out.length, grid_out.read()



    def list_files(self):
        files = []

        for file in self.fs.find():
            files.append({
                "filename": file.filename,
                "size": file.length,
                "metadata": file.metadata
            })

        return files




def recv_exact(client, size):
    data = b""
    while len(data) < size:
        chunk = client.recv(size - len(data))
        if not chunk:
            raise ConnectionError("Connection closed")
        data += chunk
    return data