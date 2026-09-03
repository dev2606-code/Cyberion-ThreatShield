import os

from flask import Flask, render_template, request
from werkzeug.utils import secure_filename


app = Flask(__name__)

BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

UPLOAD_FOLDER = os.path.join(
    BASE_DIR,
    "uploads"
)

os.makedirs(
    UPLOAD_FOLDER,
    exist_ok=True
)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/upload", methods=["POST"])
def upload_file():

    if "evtx_file" not in request.files:
        return "No file field received", 400

    file = request.files["evtx_file"]

    if not file or file.filename == "":
        return "No file selected", 400

    if not file.filename.lower().endswith(".evtx"):
        return "Only .evtx files are allowed", 400

    filename = secure_filename(file.filename)

    save_path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        filename
    )

    file.save(save_path)

    return render_template(
        "index.html",
        message=f"{filename} uploaded successfully!"
    )


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True,
        use_reloader=False
    )
