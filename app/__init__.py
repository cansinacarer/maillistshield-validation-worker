from flask import Flask, jsonify, request
from decouple import config

from .validator import Email

app = Flask(__name__)

API_KEY = config("API_KEY", default="")


@app.route("/")
def home():
    return jsonify({"message": "Not allowed"}), 405


@app.route("/validate", methods=["POST"])
def validate_email():
    try:
        data = request.get_json()
    except Exception as e:
        return jsonify({"error": "Invalid JSON format", "message": str(e)}), 400

    if not data or "api_key" not in data:
        return jsonify({"error": "Unauthorized!"}), 401

    if data["api_key"] != API_KEY:
        return jsonify({"error": "Unauthorized!"}), 401

    if "email" not in data:
        return jsonify({"error": "Email parameter is missing"}), 400

    email = Email(data["email"])

    result = email.validate()

    # If this is not a request for debugging, remove some keys
    is_debug = data.get("debug", False)
    if not is_debug:
        result.pop("autodiscover_domain", None)
        result.pop("autodiscover_host", None)
        result.pop("autodiscover_host_tld", None)
        result.pop("is_catch_all_test", None)
        result.pop("phrase_matches", None)
        result.pop("smtp_response", None)

    print(result)
    return jsonify(result)


@app.route("/status", methods=["GET"])
def status():
    return jsonify({"status": "OK"}), 200
