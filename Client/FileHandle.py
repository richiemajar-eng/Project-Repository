import mimetypes
import hashlib
import pickle
import json
import os



class StoredFile:
    def __init__(self, name, size, content):

        self.name = name
        self.size = size
        self.extension = name.split(".")[-1]
        self.mime_type = mimetypes.guess_type(name)[0]
        self.content = content
        hashlib.sha256(self.content).hexdigest()


    def get_content(self):
        return self.content

    def get_meta(self):
        metadata = {
            "file_name": self.name,
            "size": self.size,
            "format": self.extension,
            "type": self.mime_type,
        }
        return metadata



def recv_exact(client, size):
    data = b""
    while len(data) < size:
        chunk = client.recv(size - len(data))
        if not chunk:
            raise ConnectionError("Connection closed")
        data += chunk
    return data


def existing_path(path):
    return os.path.exists(path)



def capsulize(data):
    data = pickle.dumps(json.dumps(data))
    return data

def decapsullize(data):
    data = json.loads(pickle.loads(data))
    return data
