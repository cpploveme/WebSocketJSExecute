import jwt
import json
import time
import yarl
import yaml
import js2py
import base64
import psutil
import random
import aiohttp
import asyncio
import argparse
import nest_asyncio
from hashlib import md5
from aiohttp import web
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

nest_asyncio.apply()

app = web.Application()

version = "1.0.1"

publickey = "" # base64 编码过的 RSA 公钥

serv = "0.0.0.0:3211"
path = "/"
white_list = []
backend_token = ""
interval = None


predefined = """function get(data, path, defaults) {
    defaults = (typeof defaults !== 'undefined') ? defaults : null;
    var paths = path.split('.');
    for (var i = 0; i < paths.length; i++) {
        if (data === null || data === undefined) return defaults;
        data = data[paths[i]];
    }
	if (data === null || data === undefined) return defaults;
    return data;
}

function __json_stringify(data) {
	try {
		return JSON.stringify(data);
	} catch (err) { return ''; }
}

function __json_parse(data) {
	try {
		return JSON.parse(data);
	} catch (err) { return {}; }
}

function __netloc_parse(data) {
    try {
        data = data.replace('https://', '').replace('http://', '');
		if (data.indexOf('.') != -1) {
            data = data.split(':')[0].split('/')[0];
        }
        return data;
	} catch (err) { return ''; }
}

const safeStringify = __json_stringify;
const safeParse = __json_parse;
const netlocParse = __netloc_parse;

"""

def js2pystr(s):
    return str(s).lstrip("'").rstrip("'")

async def get_fetch_req(method, body, noredir, retry_time, timeout, headers, url, round, proxy):
    try:
        if method == "POST":
            async with aiohttp.ClientSession() as session:
                async with session.post(yarl.URL(url, encoded=True), headers=headers, allow_redirects = noredir, data = body, proxy=proxy, timeout=timeout) as res:
                    content = await res.text()
                    return content, res
        else:
            async with aiohttp.ClientSession() as session:
                async with session.get(yarl.URL(url, encoded=True), headers=headers, allow_redirects = noredir, proxy=proxy, timeout=timeout) as res:
                    content = await res.text()
                    return content, res
    except:
        if round >= retry_time:
            return None, None
        return get_fetch_req(method, body, noredir, retry_time, timeout, headers, url, round + 1)

def fetch_url(temp_url, temp_params):
    try:
        params = {}
        for item in temp_params:
            params[js2pystr(item)] = temp_params[item]
        url = js2pystr(temp_url)
        method = js2pystr(params.get('method', 'GET'))
        body = js2pystr(params.get('body', None))
        noredir = js2pystr(params.get('noRedir', False))
        try:
            retry_time = int(js2pystr(params.get('retry', '0')))
        except:
            retry_time = 0
        try:
            timeout = int(js2pystr(params.get('timeout', '3000')))
        except:
            timeout = 3000
        proxy = js2pystr(params.get('proxy', None))
        headers = {}
        for item in params['headers']:
            headers[js2pystr(item)] = js2pystr(params['headers'][item])
        loop = asyncio.get_running_loop()
        try:
            content, res = loop.run_until_complete(get_fetch_req(method, body, noredir, retry_time, timeout, headers, url, 0, proxy))
        except:
            return {
                'method': method,
                'url': url,
            }
        try:
            content = {
                'status': res.reason,
                'statusCode': res.status,
                'cookies': res.cookies,
                'headers': res.headers,
                'redirects': res.history,
                'method': res.method,
                'url': res.url,
                'body': content,
            }
        except:
            content = {
                'method': method,
                'url': url,
            }
        return content
    except Exception as e:
        return {'Exception': e}

def yaml_parse(data):
    try:
        data = yaml.safe_load(js2pystr(data).replace('\\n', '\n'))
        return data
    except:
        return {}

def sleep_inside(timedata):
    loop = asyncio.get_running_loop()
    try:
        loop.run_until_complete(asyncio.sleep(int(js2pystr(timedata))))
    except:
        pass

def executejscode(content, data):
    func = js2py.EvalJs()
    func.fetch = fetch_url
    func.yamlParse = yaml_parse
    func.psutil = psutil
    func.waitSleep = sleep_inside
    try:
        with open(content, 'rb') as f:
            js_code = f.read()
        content = js_code.decode()
    except:
        pass
    load_predefined = predefined
    try:
        func.execute(load_predefined + content)
        result = str(func.handler(data))
    except Exception as e:
        result = f"Execute Error: {e}"
    if result is None:
        result = "Empty Response"
    if len(result) == 0:
        result = "Empty Response"
    return result

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

def decode_jwt(data: str, pub_key: str):
    token = jwt.decode(data, pub_key, verify=True, algorithms=["RS512"])
    return token

def res_convert(data):
    nonce = generate_random_bytes(16)
    message = {
        "timestamp": int(time.time()),
        "version": version,
        "nonce": base64.b64encode(nonce).decode(),
        "data": base64.b64encode(chacha20_encrypt(json.dumps(data), sha256_32bytes(backend_token), nonce)).decode('utf-8')
    }
    check_content = str(message['timestamp']) + str(message['version'])  + str(message['nonce']) + str(message['data'])
    check_content = check_content + backend_token
    check = md5()
    check.update(check_content.encode('utf-8'))
    message['token'] = check.hexdigest()
    return base64.b64encode(json.dumps(message).encode()).decode('utf-8')

def error_convert(data):
    message = {
        "timestamp": int(time.time()),
        "version": version,
        "error": data
    }
    return base64.b64encode(json.dumps(message).encode()).decode('utf-8')

async def websocket_handler(request):
    ws = web.WebSocketResponse()
    await ws.prepare(request)

    async for msg in ws:
        if msg.type == aiohttp.WSMsgType.TEXT:
            message = msg.data
            message = decode_jwt(message, publickey)
            if interval is not None:
                if message['timestamp'] > int(time.time()) or message['timestamp'] < int(time.time()) - interval:
                    await ws.send_str(error_convert('Timestamp Error'))
                    return
            if len(white_list) != 0 and (not message['id'] in white_list):
                await ws.send_str(error_convert('Id Is Not In The Whitelist'))
                return
            check_content = str(message['timestamp']) + str(message['id']) + str(message['nonce'])
            try:
                data = json.loads(chacha20_decrypt(base64.b64decode(message['data']), sha256_32bytes(backend_token), base64.b64decode(message['nonce'])))
            except:
                await ws.send_str(error_convert('Decrypt Failed'))
                return
            for content in data:
                if content["type"] == 0:
                    continue
                check_content = check_content + content['content']
            check_content = check_content + backend_token
            check = md5()
            check.update(check_content.encode('utf-8'))
            if check.hexdigest() != message['token']:
                await ws.send_str(error_convert('Authorization Failed'))
                return
            for command in data:
                if command['type'] == 0:
                    await ws.send_str(res_convert("Connected"))
                elif command['type'] == 1:
                    await ws.send_str(res_convert(executejscode(command['content'], None)))
        elif msg.type == aiohttp.WSMsgType.ERROR:
            print(f"WebSocket Error: {ws.exception()}")
            return
    return ws


async def main():
    print(f"[Start Server At {serv}]")

    app.add_routes([web.get(path, websocket_handler)])

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, serv.split(':')[0], int(serv.split(':')[1]), ssl_context=None)
    await site.start()

    await asyncio.Future()

parser = argparse.ArgumentParser(description="后端启动命令")
parser.add_argument("-s", "--server", required=False, type=str, help="请求链接")
parser.add_argument("-p", "--path", required=False, type=str, help="请求路径")
parser.add_argument("-t", "--token", required=False, type=str, help="验证令牌")
parser.add_argument("-i", "--interval", required=False, type=int, help="连接间隔")
parser.add_argument("-wl", "--whitelist", required=False, type=str, help="请求白名单")

args = parser.parse_args()

publickey = base64.b64decode(publickey)
if args.server:
    serv = args.server
if args.path:
    path = args.path
if args.token:
    backend_token = args.token
if args.whitelist:
    for i in args.whitelist.split(','):
        white_list.append(int(i))
if args.interval:
    interval = args.interval

asyncio.run(main())
