from flask import Flask, render_template, request, redirect, url_for, session, send_file,flash
from werkzeug.utils import secure_filename
import FileHandle
import Security
import socket
import os

IP_ADDRESS = "127.0.0.1"
PORT = 5050

MAX_ATTEMPTS = 5
LOCK_TIME = 60

client = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
client.connect((IP_ADDRESS,PORT))

public_pem = client.recv(2048)
asymmetric = Security.AsymmetricEncryptor(public_pem)
shift, enc_shift = asymmetric.generate_encrypted_shift()
client.sendall(enc_shift)

app = Flask(__name__)
app.secret_key = os.urandom(26)

@app.route('/')
def index():
    return render_template('index.html')


@app.route("/login", methods=["GET", "POST"])
def login():
    error = False
    cooldown = False
    timeleft = 0

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        info = {
            "action": "login",
            "username": username,
            "password": password
        }

        info_capsule = FileHandle.capsulize(info)
        client.sendall(Security.encrypt(info_capsule, shift))

        data = client.recv(1024)
        response = Security.decrypt(data, shift).decode()

        if response == "success":
            session["temp_user"] = username
            return redirect(url_for("verification"))

        elif response.startswith("blocked"):
            cooldown = True

            parts = response.split(":")
            timeleft = int(parts[1]) if len(parts) > 1 else 300

        elif response == "fail":
            error = True

    return render_template(
        "login.html",
        error=error,
        cooldown=cooldown,
        timeleft=timeleft
    )


@app.route("/verification", methods=["GET", "POST"])
def verification():
    if "temp_user" not in session:
        return redirect(url_for("login"))

    error = None
    if request.method == "POST":
        code = request.form.get("two_fa_code")

        if not code or len(code) != 6:
            error = "Please enter a valid 6-digit code."
        else:
            try:
                client.sendall(Security.encrypt(code.encode(), shift))

                data = client.recv(1024)
                response = Security.decrypt(data, shift).decode()

                if response == "success":

                    session["username"] = session.pop("temp_user")
                    return redirect(url_for("dashboard"))
                elif response == "fail":
                    error = "Invalid verification code. Please try again."
                elif response == "expired":
                    error = "Expired verification code. Please try relaunch."

            except Exception as e:
                print(f"Verification Error: {e}")
                error = "Connection to server lost. Please login again."

    return render_template("verification.html", error=error)


@app.route("/logout")
def logout():
    info = {"action": "logout"}
    info = Security.encrypt(FileHandle.capsulize(info),shift)
    client.sendall(info)
    session.pop("username", None)  # remove user from session
    return redirect(url_for("login"))


@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if request.method == "POST":

        if "file" not in request.files:
            print("No file part")
            return "No file part"

        file = request.files["file"]

        if file.filename == "":
            print("No file selected")
            return "No file selected"

        filename = secure_filename(file.filename)

        file_content = file.read()

        file_info = FileHandle.StoredFile(filename, len(file_content), file_content)
        metadata = file_info.get_meta()
        info = {
            "action": "upload",
        } | metadata
        info = Security.encrypt(FileHandle.capsulize(info),shift)
        # client.sendall(Security.encrypt(str(len(info)).encode(), shift))
        client.sendall(info)
        client.sendall(Security.encrypt(file_content,shift))
        state = client.recv(1024)
        state = Security.decrypt(state,shift).decode()
        print(state)
        if "Uploaded Successfully" in state:
            flash(state, "success")
        else:
            flash(state, "error")

    files = []

    try:
        info = {
            "action": "get_files"
        }
        info = FileHandle.capsulize(info)
        client.sendall(Security.encrypt(info, shift))

        data = client.recv(4096)

        decrypted = Security.decrypt(data, shift)
        files_data = FileHandle.decapsullize(decrypted)
        for file in files_data:
            files.append({"filename": file["filename"],
        "size": file["size"]})

    except Exception as e:
        print("Dashboard error:", e)

    return render_template("dashboard.html", files=files)


@app.route("/download/<filename>")
def download_file(filename):

    filename = secure_filename(filename)
    info = {
        "action": "download",
        "file_name": filename,
    }
    info = FileHandle.capsulize(info)
    client.sendall(Security.encrypt(info,shift))

    size = Security.decrypt(client.recv(1024),shift).decode()

    if size.isnumeric():
        size = int(size)

        data = FileHandle.recv_exact(client, size)
        data = Security.decrypt(data,shift)
        folder_name = "app_downloads"
        os.makedirs(folder_name, exist_ok=True)
        file_path = os.path.join(folder_name, f"downloaded_{filename}")
        with open(file_path ,"wb") as f:
            f.write(data)

        flash(f"Successfully downloaded {filename} into the {folder_name} folder", "success")
    else:
        flash(size, "error")

    return redirect("/dashboard")


@app.route("/delete/<filename>")
def delete_file(filename):

    filename = secure_filename(filename)
    info = {
        "action": "delete",
        "file_name": filename,
    }
    info = FileHandle.capsulize(info)
    client.sendall(Security.encrypt(info,shift))
    action_state = client.recv(1024)
    action_state = Security.decrypt(action_state,shift).decode()
    flash(action_state, "error")

    return redirect("/dashboard")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":

        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")

        valid, messages = Security.password_requirement(password)

        if not Security.validate_email_address(email):
            return render_template(
                "signup.html",
                messages="The email address provided is invalid or does not exist.",
                username=username,
                email=email
            )

        if valid:
            info = {
                "action": "signup",
                "username": username,
                "email" : email,
                "password": password
            }

            info = FileHandle.capsulize(info)
            client.sendall(Security.encrypt(info,shift))
            data = client.recv(1024)
            data = Security.decrypt(data,shift).decode()
            if data == "username is already taken":
                return render_template("signup.html", messages=data)
            if data == "success":
                return render_template("signup.html", messages=messages , success="Account Successfully Created")

        if not valid:
            return render_template("signup.html", messages=messages)

    return render_template("signup.html")


if __name__ == "__main__":
    app.run(debug=True)
