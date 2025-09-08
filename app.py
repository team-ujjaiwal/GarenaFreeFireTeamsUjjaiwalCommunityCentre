from flask import Flask, jsonify, request
import requests
import binascii
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import threading
import warnings
import my_pb2
import struct

app = Flask(__name__)
key = "Yg&tc%DEuh6%Zc^8".encode()
iv = "6oyZDr22E3ychjM%".encode()

def encrypt_aes(data_bytes):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(data_bytes, AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return encrypted_data

def wishlistItems_payload(item_id):
    # Create protobuf message
    items = my_pb2.Items()
    items.id = item_id
    
    # Serialize to bytes
    serialized_data = items.SerializeToString()
    
    # Encrypt the serialized data
    encrypted_data = encrypt_aes(serialized_data)
    
    return encrypted_data

def add_item(token, encrypted_data, item_id):
    api = "https://clientbp.ggblueshark.com/ChangeWishListItem"
    
    headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream",
        'Authorization': "Bearer " + token,
        'X-Unity-Version': "2018.4.11f1",
        'X-GA-Model': "ASUS_Z01QD",
        'ReleaseVersion': "OB50"
    }
    
    try:
        response = requests.post(api, data=encrypted_data, headers=headers, verify=False, timeout=10)
        return response.status_code, item_id, response.text
    except Exception as e:
        return 500, item_id, str(e)

@app.route('/add_wishlist', methods=['GET'])
def add_to_wishlist():
    token = request.args.get('token')
    items_param = request.args.get('items', '')
    
    if not token:
        return jsonify({"error": "Token is missing!"}), 401
    
    if not items_param:
        return jsonify({"error": "Items parameter is required!"}), 400
    
    try:
        items_to_send = [int(item_id.strip()) for item_id in items_param.split(',')]
    except ValueError:
        return jsonify({"error": "Invalid items format! Use comma-separated item IDs"}), 400
    
    # Test with first item only
    test_item = items_to_send[0]
    encrypted_data = wishlistItems_payload(test_item)
    
    status, item_id, response_text = add_item(token, encrypted_data, test_item)
    
    debug_info = {
        "item_id": item_id,
        "status": status,
        "response": response_text,
        "payload_size": len(encrypted_data)
    }
    
    if status == 200:
        return jsonify({
            "message": "Item successfully added to wishlist",
            "debug": debug_info
        }), 200
    else:
        return jsonify({
            "error": "Failed to add item to wishlist",
            "debug": debug_info
        }), status

# Token verification endpoint
@app.route('/verify_token', methods=['GET'])
def verify_token():
    token = request.args.get('token')
    if not token:
        return jsonify({"error": "Token is missing!"}), 401
    
    api = "https://clientbp.ggblueshark.com/GetUserInfo"
    headers = {
        'Authorization': "Bearer " + token,
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        'X-Unity-Version': "2018.4.11f1"
    }
    
    try:
        response = requests.get(api, headers=headers, verify=False, timeout=10)
        return jsonify({
            "status": response.status_code,
            "response": response.text[:200] + "..." if len(response.text) > 200 else response.text
        }), response.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    warnings.filterwarnings("ignore", message="Unverified HTTPS request")
    app.run(debug=True, host='0.0.0.0', port=5000)