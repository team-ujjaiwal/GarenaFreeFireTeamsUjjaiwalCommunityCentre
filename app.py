from flask import Flask, jsonify, request
import requests
import binascii
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import threading
import warnings
import my_pb2

app = Flask(__name__)
key = "Yg&tc%DEuh6%Zc^8".encode()
iv = "6oyZDr22E3ychjM%".encode()

# Region URLs mapping
region_urls = {
    "IND": "https://client.ind.freefiremobile.com/",
    "BR": "https://client.br.freefiremobile.com/",
    "US": "https://client.us.freefiremobile.com/",
    "SAC": "https://client.sac.freefiremobile.com/",
    "NA": "https://client.na.freefiremobile.com/",
}
default_url = "https://clientbp.ggblueshark.com/"

def encrypt_aes(hex_data):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(bytes.fromhex(hex_data), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return binascii.hexlify(encrypted_data).decode()

def wishlistItems_payload(id):
    g = my_pb2.Items()
    g.id = id
    serialized_data = g.SerializeToString()
    hex_data = binascii.hexlify(serialized_data).decode("utf-8")
    encrypted_data = encrypt_aes(hex_data)
    return encrypted_data

def add_item(token, encrypted_payload, item_id, region):
    base_url = region_urls.get(region.upper(), default_url)
    api = f"{base_url}ChangeWishListItem"
    
    headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream",
        'Expect': "100-continue",
        'Authorization': "Bearer " + token,
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': "OB50"
    }
    
    try:
        response = requests.post(api, data=bytes.fromhex(encrypted_payload), headers=headers, verify=False, timeout=10)
        return response.status_code, item_id
    except Exception as e:
        return 500, item_id

@app.route('/add_wishlist', methods=['GET'])
def add_to_wishlist():
    token = request.args.get('token')
    region = request.args.get('region', 'IND')
    items_param = request.args.get('items', '')
    
    if not token:
        return jsonify({"error": "Token is missing!"}), 401
    
    # Parse items parameter
    if not items_param:
        return jsonify({"error": "Items parameter is required!"}), 400
    
    try:
        # Parse comma-separated item IDs
        items_to_send = [int(item_id.strip()) for item_id in items_param.split(',')]
    except ValueError:
        return jsonify({"error": "Invalid items format! Use comma-separated item IDs (e.g., 1315000008,1315000016)"}), 400
    
    threads = []
    results = []

    for item_id in items_to_send:
        encrypted_payload = wishlistItems_payload(item_id)
        thread = threading.Thread(
            target=lambda i=item_id, p=encrypted_payload: results.append(add_item(token, p, i, region))
        )
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    success_count = sum(1 for status, _ in results if status == 200)
    
    if success_count == len(results):
        return jsonify({
            "message": f"All {success_count} items have been successfully added to the wishlist",
            "region": region,
            "items_added": items_to_send
        }), 200
    else:
        failed_items = [item_id for status, item_id in results if status != 200]
        return jsonify({
            "error": f"Only {success_count} out of {len(results)} items were added successfully",
            "region": region,
            "failed_items": failed_items,
            "successful_items": success_count
        }), 207

if __name__ == "__main__":
    warnings.filterwarnings("ignore", message="Unverified HTTPS request")
    app.run(debug=False, host='0.0.0.0', port=5000)