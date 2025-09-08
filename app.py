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

# All available items
all_items = [
    909038002, 909047003, 909047015, 909047019, 909547001,
    911004701, 912047002, 914047001, 922044002, 1001000001,
    1001000002, 1001000003, 1001000004, 1001000005, 1001000006,
    1001000007, 1001000008, 1001000009, 1001000010, 1001000011,
    1001000012, 1001000013, 1001000014, 1001000015, 1001000016,
    1001000017, 1001000018, 1001000019, 1001000020, 1001000021,
    1001000022, 1001000023, 1001000024, 1001000025, 1001000026,
    1001000027, 1001000028, 1001000029, 1001000030, 1001000031,
    1001000032, 1001000033, 1001000034, 1001000035, 1001000036,
    1001000037, 1001000038, 1001000039, 1001000040, 1001000041,
    1001000042, 1001000043, 1001000044, 1001000045, 801000020, 
    801000015, 801000016, 827001001, 801000213, 801000144, 
    801000140, 801000139, 801000089
]

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
        # Handle range syntax (e.g., "1-15")
        if '-' in items_param:
            start, end = map(int, items_param.split('-'))
            items_to_send = all_items[start-1:end]  # Convert 1-based to 0-based indexing
        else:
            # Handle comma-separated list
            item_indices = [int(i.strip()) for i in items_param.split(',')]
            items_to_send = [all_items[i-1] for i in item_indices]  # Convert 1-based to 0-based indexing
    except (ValueError, IndexError):
        return jsonify({"error": "Invalid items format! Use comma-separated indices or range (e.g., 1,2,3 or 1-15)"}), 400
    
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
            "region": region
        }), 200
    else:
        return jsonify({
            "error": f"Only {success_count} out of {len(results)} items were added successfully",
            "region": region
        }), 207

if __name__ == "__main__":
    warnings.filterwarnings("ignore", message="Unverified HTTPS request")
    app.run(debug=False, host='0.0.0.0', port=5000)