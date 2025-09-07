from flask import Flask, request, jsonify
import requests
import json
import threading
import binascii
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import aiohttp
import asyncio
import urllib3
from datetime import datetime, timedelta
import os
import time
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Import the combined protobuf module
import CWVisit_CWSpam_pb2

app = Flask(__name__)

# Encryption functions from byte.py integrated directly
def Encrypt_ID(x):
    x = int(x)
    dec = ['80', '81', '82', '83', '84', '85', '86', '87', '88', '89', '8a', '8b', '8c', '8d', '8e', '8f', '90', '91', '92', '93', '94', '95', '96', '97', '98', '99', '9a', '9b', '9c', '9d', '9e', '9f', 'a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8', 'a9', 'aa', 'ab', 'ac', 'ac', 'ae', 'af', 'b0', 'b1', 'b2', 'b3', 'b4', 'b5', 'b6', 'b7', 'b8', '9', 'ba', 'bb', 'bc', 'bd', 'be', 'bf', 'c0', 'c1', 'c2', 'c3', 'c4', 'c5', 'c6', 'c7', 'c8', 'c9', 'ca', 'cb', 'cc', 'cd', 'ce', 'cf', 'd0', 'd1', 'd2', 'd3', 'd4', 'd5', 'd6', 'd7', 'd8', 'd9', 'da', 'db', 'dc', 'dd', 'de', 'df', 'e0', 'e1', 'e2', 'e3', 'e4', 'e5', 'e6', 'e7', 'e8', 'e9', 'ea', 'eb', 'ec', 'ed', 'ee', 'ef', 'f0', 'f1', 'f2', 'f3', 'f4', 'f5', 'f6', 'f7', 'f8', 'f9', 'fa', 'fb', 'fc', 'fd', 'fe', 'ff']
    xxx = ['1','01', '02', '03', '04', '05', '06', '07', '08', '09', '0a', '0b', '0c', '0d', '0e', '0f', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '1a', '1b', '1c', '1d', '1e', '1f', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '2a', '2b', '2c', '2d', '2e', '2f', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '3a', '3b', '3c', '3d', '3e', '3f', '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '4a', '4b', '4c', '4d', '4e', '4f', '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '5a', '5b', '5c', '5d', '5e', '5f', '60', '61', '62', '63', '64', '65', '66', '67', '68', '69', '6a', '6b', '6c', '6d', '6e', '6f', '70', '71', '72', '73', '74', '75', '76', '77', '78', '79', '7a', '7b', '7c', '7d', '7e', '7f']
    
    x = x/128 
    if x > 128:
        x = x/128
        if x > 128:
            x = x/128
            if x > 128:
                x = x/128
                strx = int(x)
                y = (x - strx) * 128
                stry = str(int(y))
                z = (y - int(stry)) * 128
                strz = str(int(z))
                n = (z - int(strz)) * 128
                strn = str(int(n))
                m = (n - int(strn)) * 128
                return dec[int(m)] + dec[int(n)] + dec[int(z)] + dec[int(y)] + xxx[int(x)]
            else:
                strx = int(x)
                y = (x - strx) * 128
                stry = str(int(y))
                z = (y - int(stry)) * 128
                strz = str(int(z))
                n = (z - int(strz)) * 128
                strn = str(int(n))
                return dec[int(n)] + dec[int(z)] + dec[int(y)] + xxx[int(x)]
        else:
            strx = int(x)
            y = (x - strx) * 128
            stry = str(int(y))
            z = (y - int(stry)) * 128
            strz = str(int(z))
            return dec[int(z)] + dec[int(y)] + xxx[int(x)] 
    else:
        strx = int(x)
        if strx == 0:
            y = (x - strx) * 128
            inty = int(y)
            return xxx[inty]
        else:
            y = (x - strx) * 128
            stry = str(int(y))
            return dec[int(y)] + xxx[int(x)]

def encrypt_api(plain_text):
    plain_text = bytes.fromhex(plain_text)
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()

def encrypt_message(plaintext):
    try:
        key = b'Yg&tc%DEuh6%Zc^8'
        iv = b'6oyZDr22E3ychjM%'
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_message = pad(plaintext, AES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
        return binascii.hexlify(encrypted_message).decode('utf-8')
    except Exception as e:
        print(f"Encryption error: {e}")
        return None

def load_tokens(region):
    try:
        if region == "IND":
            with open("token_ind.json", "r") as f:
                data = json.load(f)
                tokens = [item["token"] for item in data]
        elif region in {"BR", "US", "SAC", "NA"}:
            with open("token_br.json", "r") as f:
                data = json.load(f)
                tokens = [item["token"] for item in data]
        else:
            with open("token_bd.json", "r") as f:
                data = json.load(f)
                tokens = [item["token"] for item in data]
        return tokens
    except Exception as e:
        print(f"Error loading tokens for {region}: {e}")
        return []

def get_region_url(server_name, endpoint):
    if server_name == "IND":
        url = "https://client.ind.freefiremobile.com"
    elif server_name in {"BR", "US", "SAC", "NA"}:
        url = "https://client.us.freefiremobile.com"
    else:
        url = "https://clientbp.ggblueshark.com"
    
    return f"{url}/{endpoint}"

def get_player_info(uid, region, token):
    """Get actual player information using GetPlayerPersonalShow endpoint"""
    try:
        # Create payload for GetPlayerPersonalShow
        encrypted_id = Encrypt_ID(uid)
        payload = f"08{encrypted_id}10a7c4839f1e1801"
        encrypted_payload = encrypt_api(payload)
        
        url = get_region_url(region, "GetPlayerPersonalShow")
        headers = {
            "Expect": "100-continue",
            "Authorization": f"Bearer {token}",
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": "OB50",
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": "16",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; SM-N975F Build/PI)",
            "Host": "clientbp.ggblueshark.com",
            "Connection": "close",
            "Accept-Encoding": "gzip, deflate, br"
        }
        
        response = requests.post(url, headers=headers, data=bytes.fromhex(encrypted_payload), timeout=10)
        
        if response.status_code == 200:
            # Parse the protobuf response using the combined protobuf
            player_info = CWVisit_CWSpam_pb2.Info()
            player_info.ParseFromString(response.content)
            return player_info
        else:
            print(f"Failed to get player info: {response.status_code}")
            return None
    except Exception as e:
        print(f"Error getting player info: {e}")
        return None

def send_friend_request(uid, token, region, results):
    try:
        encrypted_id = Encrypt_ID(uid)
        payload = f"08a7c4839f1e10{encrypted_id}1801"
        encrypted_payload = encrypt_api(payload)

        url = get_region_url(region, "RequestAddingFriend")
        headers = {
            "Expect": "100-continue",
            "Authorization": f"Bearer {token}",
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": "OB50",
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": "16",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; SM-N975F Build/PI)",
            "Host": "clientbp.ggblueshark.com",
            "Connection": "close",
            "Accept-Encoding": "gzip, deflate, br"
        }

        response = requests.post(url, headers=headers, data=bytes.fromhex(encrypted_payload), timeout=10)

        if response.status_code == 200:
            results["success"] += 1
        else:
            results["failed"] += 1
    except Exception as e:
        print(f"Error sending friend request: {e}")
        results["failed"] += 1

def create_protobuf(uid):
    try:
        # Create a simple payload for visit requests
        # The visit endpoint expects a different format than friend requests
        # Based on the original visit.py, it uses a different protobuf structure
        message = f"08{Encrypt_ID(uid)}10a7c4839f1e1801"
        return bytes.fromhex(message)
    except Exception as e:
        print(f"Error creating protobuf: {e}")
        return None

def enc(uid):
    try:
        protobuf_data = create_protobuf(uid)
        if protobuf_data is None:
            return None
        encrypted_uid = encrypt_message(protobuf_data)
        return encrypted_uid
    except Exception as e:
        print(f"Error in enc function: {e}")
        return None

async def make_request_async(encrypt, region, token, session):
    try:
        if region == "IND":
            url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
        elif region in {"BR", "US", "SAC", "NA"}:
            url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
        else:
            url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"
            
        edata = bytes.fromhex(encrypt)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB50"
        }
        
        async with session.post(url, data=edata, headers=headers, ssl=False, timeout=5) as response:
            if response.status != 200:
                return None
            else:
                binary = await response.read()
                return decode_protobuf(binary)
    except Exception as e:
        print(f"Error in async request: {e}")
        return None

def decode_protobuf(binary):
    try:
        items = CWVisit_CWSpam_pb2.Info()
        items.ParseFromString(binary)
        return items
    except Exception as e:
        print(f"Error decoding protobuf: {e}")
        return None

def extract_player_info(protobuf_obj):
    if not protobuf_obj:
        return None, None, None
    
    try:
        # Extract information directly from the protobuf object
        if hasattr(protobuf_obj, 'AccountInfo'):
            account_info = protobuf_obj.AccountInfo
            player_name = account_info.PlayerNickname if account_info.PlayerNickname else "Unknown"
            player_level = account_info.Levels if account_info.Levels else 0
            player_likes = account_info.Likes if account_info.Likes else 0
            return player_name, player_level, player_likes
        return "Unknown", 0, 0
    except Exception as e:
        print(f"Error extracting player info: {e}")
        return "Unknown", 0, 0

@app.route("/spam", methods=["GET"])
def send_requests():
    uid = request.args.get("uid")
    region = request.args.get("region", "IND").upper()

    if not uid:
        return jsonify({"error": "uid parameter is required"}), 400

    tokens = load_tokens(region)
    if not tokens:
        return jsonify({"error": f"No tokens found for region {region}"}), 500

    # Get actual player information using the first token
    player_info = get_player_info(uid, region, tokens[0])
    
    if not player_info:
        return jsonify({"error": "Failed to get player information"}), 500

    results = {"success": 0, "failed": 0}
    threads = []

    for token in tokens[:110]:
        thread = threading.Thread(target=send_friend_request, args=(uid, token, region, results))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    total_requests = results["success"] + results["failed"]
    status = 1 if results["success"] != 0 else 2

    response_data = {
        "success_count": results["success"],
        "failed_count": results["failed"],
        "PlayerNickname": player_info.AccountInfo.PlayerNickname,
        "PlayerLevel": player_info.AccountInfo.Levels,
        "PlayerLikes": player_info.AccountInfo.Likes,
        "PlayerRegion": player_info.AccountInfo.PlayerRegion,
        "status": status
    }

    return jsonify(response_data)

@app.route('/visit', methods=['GET'])
async def visit():
    target_uid = request.args.get("uid")
    region = request.args.get("region", "").upper()
    
    if not all([target_uid, region]):
        return jsonify({"error": "UID and region are required"}), 400
        
    try:
        tokens = load_tokens(region)
        if not tokens:
            raise Exception("Failed to load tokens.")
            
        encrypted_target_uid = enc(target_uid)
        if encrypted_target_uid is None:
            raise Exception("Encryption of target UID failed.")
            
        total_visits = len(tokens) * 20
        success_count = 0
        failed_count = 0
        player_name = None
        player_level = None
        player_likes = None
        
        async with aiohttp.ClientSession() as session:
            tasks = []
            for token in tokens:
                for _ in range(20):
                    tasks.append(make_request_async(encrypted_target_uid, region, token, session))
            
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            
            for response in responses:
                if response and isinstance(response, CWVisit_CWSpam_pb2.Info):
                    success_count += 1
                    # Extract player info from the first successful response
                    if player_name is None:
                        player_name, player_level, player_likes = extract_player_info(response)
                else:
                    failed_count += 1
        
        # Set default values if player info couldn't be extracted
        if player_name is None:
            player_name, player_level, player_likes = "Unknown", 0, 0
                
        summary = {
            "TotalVisits": total_visits,
            "SuccessfulVisits": success_count,
            "FailedVisits": failed_count,
            "PlayerNickname": player_name,
            "PlayerLevel": player_level,
            "PlayerLikes": player_likes,
            "UID": int(target_uid),
            "TotalResponses": len(responses)
        }
        
        return jsonify(summary)
        
    except Exception as e:
        print(f"Error in visit endpoint: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)