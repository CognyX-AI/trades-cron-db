import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
import psycopg2
from psycopg2.extras import RealDictCursor
import logging
from dotenv import load_dotenv

load_dotenv()

# Setting up logging
script_logger = logging.getLogger(__name__)
file_handler = logging.FileHandler('Logfile.log', encoding='utf-8')
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
script_logger.addHandler(file_handler)
script_logger.setLevel(logging.DEBUG)


# Database configurations
DB_CONFIG_FETCH_DEV = {
    "dbname": os.environ.get('DB_NAME_MAIN_DEV'),
    "user": os.environ.get('DB_USER_DEV'),
    "password": os.environ.get('DB_PASSWORD_DEV'),
    "host": os.environ.get('DB_HOST_DEV'),
    "port": os.environ.get('DB_PORT_DEV'),
}

DB_CONFIG_POST_DEV = {
    "dbname": os.environ.get('DB_NAME_POST_DEV'),
    "user": os.environ.get('DB_USER_DEV'),
    "password": os.environ.get('DB_PASSWORD_DEV'),
    "host": os.environ.get('DB_HOST_DEV'),
    "port": os.environ.get('DB_PORT_DEV'),
}

DB_CONFIG_FETCH_PROD = {
    "dbname": os.environ.get('DB_NAME_MAIN_PROD'),
    "user": os.environ.get('DB_USER_PROD'),
    "password": os.environ.get('DB_PASSWORD_PROD'),
    "host": os.environ.get('DB_HOST_PROD'),
    "port": os.environ.get('DB_PORT_PROD'),
}

DB_CONFIG_POST_PROD = {
    "dbname": os.environ.get('DB_NAME_POST_PROD'),
    "user": os.environ.get('DB_USER_PROD'),
    "password": os.environ.get('DB_PASSWORD_PROD'),
    "host": os.environ.get('DB_HOST_PROD'),
    "port": os.environ.get('DB_PORT_PROD'),
}

AES_KEY = os.environ.get('AES_KEY')
SLACK_API_TOKEN = os.environ.get('SLACK_API_TOKEN')
CHANNEL_ID = os.environ.get('CHANNEL_ID')


def encrypt(text):
    key = AES_KEY.encode()
    cipher = AES.new(key, AES.MODE_ECB)
    padded_text = pad(text.encode(), AES.block_size)
    encrypted_text = cipher.encrypt(padded_text)
    return base64.b64encode(encrypted_text).decode()

def decrypt(encrypted_text):
    key = AES_KEY.encode()
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_bytes = base64.b64decode(encrypted_text)
    decrypted_bytes = cipher.decrypt(encrypted_bytes)
    unpadded_text = unpad(decrypted_bytes, AES.block_size)
    return unpadded_text.decode()


def send_slack_message(error_message):
    try:
        client = WebClient(token=SLACK_API_TOKEN)
        response = client.chat_postMessage(
            channel=CHANNEL_ID,
            text=f"Error encountered in Database cron: {error_message}"
        )
    except SlackApiError as e:
        script_logger.error(f"Slack API error: {e.response['error']}")


def decrypt_users(users):
    try:
        if users:
            for user in users:
                user['password'] = decrypt(user['password'])

        return users
    except Exception as e:
        print("Error encountered while decrypting password ", e)


def get_users(env="DEV"):
    conn = None
    cursor = None

    try:
        db_config = DB_CONFIG_FETCH_DEV if env == "DEV" else DB_CONFIG_FETCH_PROD
        
        conn = psycopg2.connect(**db_config)
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        cursor.execute("SELECT xstation_id, password, is_real FROM users_credentials_xstation;")
        users = cursor.fetchall()

        users = decrypt_users(users)
        return users
    
    except (Exception, psycopg2.Error) as error:
        script_logger.error(f"Error while connecting to PostgreSQL: {error}")
        send_slack_message(error)
    
    finally:
        if cursor:
            cursor.close()

        if conn:
            conn.close()


def main():
    pass


if __name__ == '__main__':
    main()
    print(get_users())