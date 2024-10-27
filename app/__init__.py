from flask import Flask, jsonify, request

from .validator import Email

app = Flask(__name__)


@app.route("/")
def home():
    return jsonify({"message": "Not allowed"}), 405


@app.route("/validate", methods=["POST"])
def validate_email():
    try:
        data = request.get_json()
    except Exception as e:
        return jsonify({"error": "Invalid JSON format", "message": str(e)}), 400

    if not data or "email" not in data:
        return jsonify({"error": "Email parameter is missing"}), 400

    if not data or "email" not in data:
        return jsonify({"error": "Email parameter is missing"}), 400

    email = Email(data["email"])

    result = email.validate()

    print(result)
    return jsonify(result)
