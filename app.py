import base64
import hashlib
import json
import logging
import os
import random
import socket
import struct
import xml.etree.ElementTree as ET
import requests
from Crypto.Cipher import AES
from flask import Flask, request, make_response

from config import load_config
from config import load_robot_config

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Load configuration
config = load_config()
robot_configs=load_robot_config()

robot_message_set=set()


def get_random_str():
    """ 随机生成16位字符串
    @return: 16位字符串
    """
    return str(random.randint(1000000000000000, 9999999999999999)).encode()


class Prpcrypt(object):
    """提供与企业微信消息的加密解密功能
    Provides encryption and decryption for messages to/from WeWork"""

    def __init__(self, key):
        """初始化加密解密对象
        Initialize encryption/decryption object

        Args:
            key: 加密密钥
            key: Encryption key"""
        self.key = base64.b64decode(key+"=")
    
        # Set encryption mode to AES CBC
        self.mode = AES.MODE_CBC

    def encrypt(self, text):
        """对明文进行加密
        Encrypt plaintext

        @param text: 需要加密的明文
        @param text: Plaintext to encrypt
        @return: 加密得到的字符串
        @return: Encrypted string"""
        # Ensure text is bytes type
        text_bytes = text.encode("utf-8")
        # Add 16-byte random string to beginning of plaintext
        text_bytes = get_random_str() + struct.pack("I", socket.htonl(len(text_bytes))) + text_bytes
        text_length = len(text_bytes)
        amount_to_pad = 32 - (text_length % 32)
        if amount_to_pad == 0:
            amount_to_pad = 32
        # Get padding character
        pad = chr(amount_to_pad)
        text_padded=text_bytes + (pad * amount_to_pad).encode("utf-8")
        text_padded_bytes = text_padded

        # Perform encryption
        cryptor = AES.new(self.key, self.mode, self.key[:16])
        try:
            ciphertext = cryptor.encrypt(text_padded_bytes)
            # 使用BASE64对加密后的字符串进行编码
            return base64.b64encode(ciphertext)
        except Exception as e:
            logger.error(e)
            return None


def robot_decrypt_message(msg_encrypt, encoding_aes_key, parse_json=True):
    """解密企业微信消息
    Decrypt messages from WeWork

    Args:
        msg_encrypt (str): 加密的消息
        msg_encrypt (str): Encrypted message
        encoding_aes_key (str): 编码AES密钥
        encoding_aes_key (str): Encoding AES key
        parse_json (bool): 是否将内容解析为JSON
        parse_json (bool): Whether to parse content as JSON

    Returns:
        dict or str: 解密后的内容
        dict or str: Decrypted content"""
    encoding_aes_key = encoding_aes_key + "="
    aes_key = base64.b64decode(encoding_aes_key)

    # Parse Base64 encoded message
    ciphertext = base64.b64decode(msg_encrypt)

    # AES decrypt
    iv = aes_key[:16]
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)

    # Remove padding
    pad_len = decrypted[-1]
    if isinstance(pad_len, str):
        pad_len = ord(pad_len)
    content = decrypted[:-pad_len]

    json_len = int.from_bytes(content[16:20], byteorder='big')
    json_content = content[20:20 + json_len].decode('utf-8')

    if parse_json:
        try:
            # 尝试将解密后的内容解析为 JSON
            return json.loads(json_content)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse decrypted content as JSON: {str(e)}")
            raise
    else:
        return json_content

def decrypt_message(msg_encrypt, encoding_aes_key, corp_id):
    """解密企业微信消息
    Decrypt messages from WeWork

    Args:
        msg_encrypt (str): 加密的消息
        msg_encrypt (str): Encrypted message
        encoding_aes_key (str): 编码AES密钥
        encoding_aes_key (str): Encoding AES key
        corp_id (str): 用于验证的公司ID
        corp_id (str): Company ID for verification

    Returns:
        str: 解密后的XML内容
        str: Decrypted XML content"""
    encoding_aes_key = encoding_aes_key + "="
    aes_key = base64.b64decode(encoding_aes_key)

    # Parse Base64 encoded message
    ciphertext = base64.b64decode(msg_encrypt)

    # AES decrypt
    iv = aes_key[:16]
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)

    # Remove padding
    pad_len = decrypted[-1]
    if isinstance(pad_len, str):
        pad_len = ord(pad_len)
    content = decrypted[:-pad_len]

    # Remove 16-byte random string and corpid
    xml_len = int.from_bytes(content[16:20], byteorder='big')
    xml_content = content[20:20+xml_len].decode('utf-8')
    received_corp_id = content[20+xml_len:].decode('utf-8')

    # Verify corp_id
    if received_corp_id != corp_id:
        raise ValueError(f"Corp ID verification failed. Expected: {corp_id}, Got: {received_corp_id}")

    return xml_content

def get_robot_config(robot_id):
    """通过robot_id获取机器人配置
    Get robot configuration by robot_id

    Args:
        robot_id: 机器人ID
        robot_id: Robot identifier

    Returns:
        机器人配置字典，如果未找到则返回None
        Robot configuration dict, None if not found"""
    for robot_config in robot_configs:
        if str(robot_config.get('robot_id')) == str(robot_id):
            return robot_config
    return None

def get_agent_config(agent_id):
    """通过agent_id获取应用配置
    Get agent configuration by agent_id

    Args:
        agent_id: 应用ID
        agent_id: Agent identifier

    Returns:
        应用配置字典，如果未找到则返回None
        Agent configuration dict, None if not found"""
    for agent_config in config.get('agents', []):
        if str(agent_config.get('agent_id')) == str(agent_id):
            return agent_config
    return None

def make_error_message(encoding_aes_key,content):
    pc = Prpcrypt(encoding_aes_key)
    error_json = {
        "msgtype": 'stream',
        "stream": {
            "id": "STREAMID",
            "finish": True,
            "content": content
        }
    }
    logger.info(f"{json.dumps(error_json)}")
    error_encrypt = pc.encrypt(json.dumps(error_json, ensure_ascii=False))
    error_encrypt = error_encrypt.decode('utf-8')
    error_message = {
        "encrypt": error_encrypt
    }
    return json.dumps(error_message)



@app.route('/wework/robot_callback/<robot_id>', methods=['GET', 'POST'])
def wework_robot_callback(robot_id):
    """处理特定robot_id的企业微信机器人回调
    Handle WeWork robot callback for specific robot_id

    Args:
        robot_id: 机器人唯一标识符
        robot_id: Unique robot identifier

    Returns:
        Flask响应对象
        Flask response object"""



    robot_config = get_robot_config(robot_id)

    if not robot_config:
        logger.error(f"Robot ID {robot_id} not found in configuration")
        return make_response("Robot not configured", 404)

    token = robot_config.get('token')
    encoding_aes_key = robot_config.get('encoding_aes_key')
    webhook_url = robot_config.get('webhook_url')
    # Store original request info for subsequent n8n reply
    # Handle verification request (GET)
    if request.method == 'GET':
        msg_signature = request.args.get('msg_signature')
        timestamp = request.args.get('timestamp')
        nonce = request.args.get('nonce')
        echostr = request.args.get('echostr')

        # Sort and concatenate token, timestamp, nonce for signature
        temp_list = [token, timestamp, nonce, echostr]
        temp_list.sort()
        temp_str = ''.join(temp_list)

        # Calculate SHA1 signature
        sha1 = hashlib.sha1()
        sha1.update(temp_str.encode('utf-8'))
        signature = sha1.hexdigest()

        # Verify request signature
        if signature != msg_signature:
            logger.error(f"Signature verification failed for robot")
            return make_response("Signature verification failed", 403)

        # If signature valid, decrypt echostr
        # For verification, return raw string instead of parsed JSON
        echostr_decrypted = robot_decrypt_message(echostr, encoding_aes_key, parse_json=False)
        return make_response(str(echostr_decrypted), 200)

    # Handle message reception (POST)
    elif request.method == 'POST':
        try:
            msg_signature = request.args.get('msg_signature')
            timestamp = request.args.get('timestamp')
            nonce = request.args.get('nonce')

            # Parse JSON request body
            try:
                json_data = request.get_json()
                if not json_data:
                    raise ValueError("No JSON data received")
            except Exception as e:
                logger.error(f"Failed to parse JSON data: {str(e)}")
                return make_response("Invalid JSON format", 400)

            msg_encrypt = json_data.get('encrypt')
            if not msg_encrypt:
                logger.error("No 'encrypt' field found in JSON")
                return make_response("Missing 'encrypt' field in JSON", 400)

            # Verify request signature
            temp_list = [token, timestamp, nonce, msg_encrypt]
            temp_list.sort()
            temp_str = ''.join(temp_list)

            sha1 = hashlib.sha1()
            sha1.update(temp_str.encode('utf-8'))
            signature = sha1.hexdigest()

            if signature != msg_signature:
                logger.error(f"Signature verification failed for message to robot {robot_id}")
                return make_response("Signature verification failed", 403)

            # Decrypt message content
            try:
                message_data = robot_decrypt_message(msg_encrypt, encoding_aes_key)
            except Exception as e:
                logger.error(f"Decryption failed: {str(e)}")
                return make_response("Decryption failed", 500)
            if message_data.get("msgid") in robot_message_set:
                logger.error(f"too many requests failed")
                return make_response(make_error_message(encoding_aes_key, f"请求过于频繁，请重试"), 200)
            else:
                robot_message_set.add(message_data.get('msgid'))

            # Format message for n8n webhook
            formatted_message = {
                "msgid": message_data.get('msgid', ''),
                "aibotid": message_data.get('aibotid', robot_id),
                "chatid": message_data.get('chatid', ''),
                "chattype": message_data.get('chattype', "single"),
                "from": message_data.get('from', {"userid": ""}),
                "msgtype": message_data.get('msgtype', "text"),
                "text": message_data.get('text', {"content": ""})
            }
            logger.info(f"Received robot message for {robot_id}: {formatted_message}")

            # Forward to configured webhook
            if webhook_url:
                try:
                    response = requests.post(
                        webhook_url,
                        json=formatted_message,
                        headers={'Content-Type': 'application/json'},
                        timeout=5
                    )
                    logger.info(f"{response.json()}")
                    pc = Prpcrypt(encoding_aes_key)
                    msg_encrypt=pc.encrypt(json.dumps(response.json(),ensure_ascii=False))
                    msg_encrypt =msg_encrypt.decode('utf-8')
                    response_message = {
                        "encrypt": msg_encrypt
                    }
                    logger.info(f"Forwarded to robot webhook, status: {response.status_code}")
                    try:
                        robot_message_set.clear()
                        return make_response(json.dumps(response_message), 200)
                    except Exception as e:
                        logger.error(f"Failed response to wework: {str(e)}")
                        return make_response(make_error_message(encoding_aes_key, f"错误:{str(e)}"), 200)
                except Exception as e:
                    logger.error(f"Failed to forward to robot webhook: {str(e)}")
                    return make_response( make_error_message(encoding_aes_key,f"错误:{str(e)}"), 200)
            else:
                return make_response(make_error_message(encoding_aes_key, "Webhook not configured"), 200)
        except Exception as e:
            logger.error(f"Error processing robot callback: {str(e)}")
            return make_response( make_error_message(encoding_aes_key,f"错误:{str(e)}"), 200)
    return make_response( make_error_message(encoding_aes_key,"未知错误"), 200)


@app.route('/wework/callback/<agent_id>', methods=['GET', 'POST'])
def wework_callback(agent_id):
    """处理特定agent_id的企业微信回调
    Handle WeWork callback for specific agent_id

    Args:
        agent_id: 应用唯一标识符
        agent_id: Unique agent identifier

    Returns:
        Flask响应对象
        Flask response object"""
    agent_config = get_agent_config(agent_id)
    
    if not agent_config:
        logger.error(f"Agent ID {agent_id} not found in configuration")
        return make_response("Agent not configured", 404)
    
    token = agent_config.get('token')
    encoding_aes_key = agent_config.get('encoding_aes_key')
    corp_id = config.get('corp_id')
    webhook_url = agent_config.get('webhook_url')
    
    # Handle verification request (GET)
    if request.method == 'GET':
        msg_signature = request.args.get('msg_signature')
        timestamp = request.args.get('timestamp')
        nonce = request.args.get('nonce')
        echostr = request.args.get('echostr')
        
        # Sort and concatenate token, timestamp, nonce for signature
        temp_list = [token, timestamp, nonce, echostr]
        temp_list.sort()
        temp_str = ''.join(temp_list)
        
        # Calculate SHA1 signature
        sha1 = hashlib.sha1()
        sha1.update(temp_str.encode('utf-8'))
        signature = sha1.hexdigest()
        
        # Verify request signature
        if signature != msg_signature:
            logger.error(f"Signature verification failed for agent {agent_id}")
            return make_response("Signature verification failed", 403)
        
        # If signature valid, decrypt echostr
        echostr_decrypted = decrypt_message(echostr, encoding_aes_key, corp_id)
        return make_response(echostr_decrypted, 200)
    
    # Handle message reception (POST)
    elif request.method == 'POST':
        try:
            msg_signature = request.args.get('msg_signature')
            timestamp = request.args.get('timestamp')
            nonce = request.args.get('nonce')
            
            # Parse the XML message
            xml_data = request.data
            xml_root = ET.fromstring(xml_data)
            encrypt_element = xml_root.find('Encrypt')
            
            if encrypt_element is None:
                logger.error("No Encrypt element found in XML")
                return make_response("Invalid XML format", 400)
            
            msg_encrypt = encrypt_element.text
            
            # Verify request signature
            temp_list = [token, timestamp, nonce, msg_encrypt]
            temp_list.sort()
            temp_str = ''.join(temp_list)
            
            sha1 = hashlib.sha1()
            sha1.update(temp_str.encode('utf-8'))
            signature = sha1.hexdigest()
            
            if signature != msg_signature:
                logger.error(f"Signature verification failed for message to agent {agent_id}")
                return make_response("Signature verification failed", 403)
            
            # Decrypt message content
            xml_content = decrypt_message(msg_encrypt, encoding_aes_key, corp_id)
            
            # Parse decrypted XML
            msg_xml = ET.fromstring(xml_content)
            
            # Extract message data
            message_data = {}
            for child in msg_xml:
                message_data[child.tag] = child.text
            
            logger.info(f"Received message for agent {agent_id}: {message_data}")
            
            # Forward to n8n webhook
            if webhook_url:
                try:
                    response = requests.post(
                        webhook_url,
                        json={
                            'agent_id': agent_id,
                            'message': message_data
                        },
                        headers={'Content-Type': 'application/json'},
                        timeout=5
                    )
                    logger.info(f"Forwarded to webhook, status: {response.status_code}")
                except Exception as e:
                    logger.error(f"Failed to forward to webhook: {str(e)}")
            
            # Return success response to WeWork
            return make_response("success", 200)
            
        except Exception as e:
            logger.error(f"Error processing callback: {str(e)}")
            return make_response("Internal server error", 500)
    return None


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)