from flask import Flask, request, make_response
import json
import hashlib
import base64
import time
import xml.etree.ElementTree as ET
from Crypto.Cipher import AES
import requests
import logging
import os
from config import load_config

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Load configuration
config = load_config()

def decrypt_message(msg_encrypt, encoding_aes_key, corp_id):
    """Decrypt messages from WeWork"""
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

def get_agent_config(agent_id):
    """Get agent configuration by agent_id"""
    for agent_config in config.get('agents', []):
        if str(agent_config.get('agent_id')) == str(agent_id):
            return agent_config
    return None

@app.route('/wework/callback/<agent_id>', methods=['GET', 'POST'])
def wework_callback(agent_id):
    """Handle WeWork callback for specific agent_id"""
    agent_config = get_agent_config(agent_id)
    
    if not agent_config:
        logger.error(f"Agent ID {agent_id} not found in configuration")
        return make_response("Agent not configured", 404)
    
    token = agent_config.get('token')
    encoding_aes_key = agent_config.get('encoding_aes_key')
    corp_id = config.get('corp_id')
    webhook_url = agent_config.get('webhook_url')
    
    # Handle verification request
    if request.method == 'GET':
        msg_signature = request.args.get('msg_signature')
        timestamp = request.args.get('timestamp')
        nonce = request.args.get('nonce')
        echostr = request.args.get('echostr')
        
        # Sort and concatenate token, timestamp, nonce
        temp_list = [token, timestamp, nonce, echostr]
        temp_list.sort()
        temp_str = ''.join(temp_list)
        
        # Calculate signature
        sha1 = hashlib.sha1()
        sha1.update(temp_str.encode('utf-8'))
        signature = sha1.hexdigest()
        
        # Verify signature
        if signature != msg_signature:
            logger.error(f"Signature verification failed for agent {agent_id}")
            return make_response("Signature verification failed", 403)
        
        # If signature is valid, decrypt echostr
        echostr_decrypted = decrypt_message(echostr, encoding_aes_key, corp_id)
        return make_response(echostr_decrypted, 200)
    
    # Handle message receive
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
            
            # Verify signature
            temp_list = [token, timestamp, nonce, msg_encrypt]
            temp_list.sort()
            temp_str = ''.join(temp_list)
            
            sha1 = hashlib.sha1()
            sha1.update(temp_str.encode('utf-8'))
            signature = sha1.hexdigest()
            
            if signature != msg_signature:
                logger.error(f"Signature verification failed for message to agent {agent_id}")
                return make_response("Signature verification failed", 403)
            
            # Decrypt message
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

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False) 