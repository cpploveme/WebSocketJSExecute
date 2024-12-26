import jwt
import json
import time
import base64
import random
import aiohttp
import asyncio
from hashlib import md5
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

privatekey = "" # base64 编码过的 RSA 私钥
privatekey = base64.b64decode(privatekey)

slaves = [
    ("Local", "ws://127.0.0.1:3211", "") # 后端名称 连接地址 密钥
]

my_id = 123

def sha256_32bytes(data: str, encoding='utf-8'):
    SHA256 = hashes.Hash(hashes.SHA256())
    SHA256.update(data.encode())
    digest = SHA256.finalize().hex()
    output = digest[:32]
    return output.encode(encoding=encoding)

def generate_random_bytes(length: int) -> bytes:
    return bytes([random.randint(0, 255) for _ in range(length)])

def chacha20_encrypt(plaintext: str, key: bytes, nonce: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes")
    if len(nonce) != 16:
        raise ValueError("Nonce must be 16 bytes")
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return ciphertext

def chacha20_decrypt(ciphertext: bytes, key: bytes, nonce: bytes) -> str:
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes")
    if len(nonce) != 16:
        raise ValueError("Nonce must be 16 bytes")
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode()

def encode_jwt(payload: dict, private_key: str):
    a = jwt.encode(payload, private_key, algorithm="RS512")
    return a

async def send_websocket_request(uri, message, backend_token, name):
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(connect=10)) as session:
            async with session.ws_connect(uri) as ws:
                await ws.send_str(message)
                async for msg in ws:
                    if msg.type == aiohttp.WSMsgType.TEXT:
                        return msg.data, uri, backend_token, name
                    elif msg.type == aiohttp.WSMsgType.ERROR:
                        return None, uri, backend_token, name
    except:
        pass
    return None, uri, backend_token, name

async def sendrequests(data: list):
    tasks = []
    for name, uri, token in slaves:
        nonce = generate_random_bytes(16)
        message = {
            "timestamp": int(time.time()),
            "id": my_id,
            "nonce": base64.b64encode(nonce).decode()
        }
        check_content = str(message['timestamp']) + str(message['id']) + str(message['nonce'])
        for content in data:
            if content["type"] == 0:
                continue
            check_content = check_content + content['content']
        check_content = check_content + token
        check = md5()
        check.update(check_content.encode('utf-8'))
        message['token'] = check.hexdigest()
        message['data'] = base64.b64encode(chacha20_encrypt(json.dumps(data), sha256_32bytes(token), nonce)).decode('utf-8')
        message = encode_jwt(message, privatekey)
        task = asyncio.ensure_future(send_websocket_request(uri, message, token, name))
        tasks.append(task)
    result = await asyncio.gather(*tasks)
    return result

async def test_script(code: str):
    results = await sendrequests([{"type": 1, "content": code}])
    resdata = []
    for res in results:
        message, uri, token, name = res
        if message is None:
            resdata.append({'name': name, 'uri': uri, 'token': token, 'message': message})
            continue
        message = json.loads(base64.b64decode(message).decode())
        if message.get('error', None) is not None:
            resdata.append({'name': name, 'uri': uri, 'token': token, 'message': message, 'error': message['error']})
            continue
        check_content = str(message['timestamp']) + str(message['version']) + str(message['nonce']) + str(message['data'])
        check_content = check_content + token
        check = md5()
        check.update(check_content.encode('utf-8'))
        try:
            data = json.loads(chacha20_decrypt(base64.b64decode(message['data']), sha256_32bytes(token), base64.b64decode(message['nonce'])))
        except:
            resdata.append({'name': name, 'uri': uri, 'token': token, 'message': message})
            continue
        if check.hexdigest() != message['token']:
            resdata.append({'name': name, 'uri': uri, 'token': token, 'message': message})
            continue
        resdata.append({'name': name, 'uri': uri, 'token': token, 'message': message, 'data': data})
    return resdata

code = """
function handler() {
    let sent1 = parseInt(psutil.net_io_counters()[0]), recv1 = parseInt(psutil.net_io_counters()[1]);
    let cpu = parseFloat(psutil.cpu_percent(interval=1));
    let sent2 = parseInt(psutil.net_io_counters()[0]), recv2 = parseInt(psutil.net_io_counters()[1]);
    return [recv2 - recv1, sent2 - sent1, cpu]
}

"""

print(asyncio.run(test_script(code)))