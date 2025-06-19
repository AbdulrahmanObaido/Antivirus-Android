from flask import Flask, request, jsonify

app = Flask(__name__)

# Example virus signatures stored as hash values
virus_db = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "Test.Dummy.Trojan"
}

@app.route('/api/check_hash', methods=['POST'])
def check_hash():
    data = request.get_json()
    hash_value = data.get('hash')
    if hash_value in virus_db:
        return jsonify({"infected": True, "name": virus_db[hash_value]}), 200
    return jsonify({"infected": False}), 200

@app.route('/api/get_signatures', methods=['GET'])
def get_signatures():
    return jsonify(list(virus_db.keys()))

@app.route('/api/report_infection', methods=['POST'])
def report_infection():
    data = request.get_json()
    hash_value = data.get('hash')
    name = data.get('name', 'Unknown.Malware')
    virus_db[hash_value] = name
    return jsonify({"status": "reported"}), 201

if __name__ == '__main__':
    app.run(debug=True, port=5000)
