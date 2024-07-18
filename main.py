import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
import requests
import logging
from dotenv import load_dotenv

load_dotenv()

script_logger = logging.getLogger(__name__)
file_handler = logging.FileHandler('Logfile.log', encoding='utf-8')
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
script_logger.addHandler(file_handler)

DB_NAME_DEV = os.environ.get('DB_NAME_DEV')
DB_USER_DEV = os.environ.get('DB_NAME_DEV')
DB_PASSWORD_DEV = os.environ.get('DB_NAME_DEV')
DB_HOST_DEV = os.environ.get('DB_NAME_DEV')
DB_PORT_DEV = os.environ.get('DB_NAME_DEV')

DB_NAME_PROD = os.environ.get('DB_NAME_DEV')
DB_USER_PROD = os.environ.get('DB_NAME_DEV')
DB_PASSWORD_PROD = os.environ.get('DB_NAME_DEV')
DB_HOST_PROD = os.environ.get('DB_NAME_DEV')
DB_PORT_PROD = os.environ.get('DB_NAME_DEV')

AES_KEY = os.environ.get('DB_NAME_DEV')
SLACK_API_TOKEN = os.environ.get('DB_NAME_DEV')
CHANNEL_ID = os.environ.get('DB_NAME_DEV')


def encrypt(text):
    key = os.environ.get('AES_KEY').encode()
    cipher = AES.new(key, AES.MODE_ECB)
    padded_text = pad(text.encode(), AES.block_size)
    encrypted_text = cipher.encrypt(padded_text)
    return base64.b64encode(encrypted_text).decode()


def decrypt(encrypted_text):
    key = os.environ.get('AES_KEY').encode()
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_bytes = base64.b64decode(encrypted_text)
    decrypted_bytes = cipher.decrypt(encrypted_bytes)
    unpadded_text = unpad(decrypted_bytes, AES.block_size)
    return unpadded_text.decode()


def send_slack_message(e):
    try:
        client = WebClient(token=SLACK_API_TOKEN)
        
        message = f"Error encountered in Virtual Copy: {e}"
        response = client.chat_postMessage(
            channel=CHANNEL_ID,
            text=message
        )
    
    except SlackApiError as e:
            print(f"Slack API error: {e.response['error']}")


def main():
    pass


if __name__ == '__main__':
    main()