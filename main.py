import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from xAPIConnector import APIClient, loginCommand
import time
import base64
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
import concurrent.futures
from functools import partial
import psycopg2
from psycopg2.extras import RealDictCursor
import logging
from dotenv import load_dotenv

load_dotenv()

# Setting up logging
script_logger = logging.getLogger(__name__)
file_handler = logging.FileHandler("Logfile.log", encoding="utf-8")
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
file_handler.setFormatter(formatter)
script_logger.addHandler(file_handler)
script_logger.setLevel(logging.DEBUG)

# Database configurations
DB_CONFIG_FETCH_DEV = {
    "dbname": os.environ.get("DB_NAME_MAIN_DEV"),
    "user": os.environ.get("DB_USER_DEV"),
    "password": os.environ.get("DB_PASSWORD_DEV"),
    "host": os.environ.get("DB_HOST_DEV"),
    "port": os.environ.get("DB_PORT_DEV"),
}

DB_CONFIG_POST_DEV = {
    "dbname": os.environ.get("DB_NAME_POST_DEV"),
    "user": os.environ.get("DB_USER_DEV"),
    "password": os.environ.get("DB_PASSWORD_DEV"),
    "host": os.environ.get("DB_HOST_DEV"),
    "port": os.environ.get("DB_PORT_DEV"),
}

DB_CONFIG_FETCH_PROD = {
    "dbname": os.environ.get("DB_NAME_MAIN_PROD"),
    "user": os.environ.get("DB_USER_PROD"),
    "password": os.environ.get("DB_PASSWORD_PROD"),
    "host": os.environ.get("DB_HOST_PROD"),
    "port": os.environ.get("DB_PORT_PROD"),
}

DB_CONFIG_POST_PROD = {
    "dbname": os.environ.get("DB_NAME_POST_PROD"),
    "user": os.environ.get("DB_USER_PROD"),
    "password": os.environ.get("DB_PASSWORD_PROD"),
    "host": os.environ.get("DB_HOST_PROD"),
    "port": os.environ.get("DB_PORT_PROD"),
}

AES_KEY = os.environ.get("AES_KEY")
SLACK_API_TOKEN = os.environ.get("SLACK_API_TOKEN")
CHANNEL_ID = os.environ.get("CHANNEL_ID")


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
    print(error_message)
    # try:
    #     client = WebClient(token=SLACK_API_TOKEN)
    #     response = client.chat_postMessage(
    #         channel=CHANNEL_ID,
    #         text=f"Error encountered in Database cron: {error_message}",
    #     )
    # except SlackApiError as e:
    #     script_logger.error(f"Slack API error: {e.response['error']}")


def decrypt_users(users):
    try:
        if users:
            for user in users:
                user["password"] = decrypt(user["password"])

        return users

    except Exception as e:
        script_logger.error(f"Error encountered while decrypting password: {e}")
        send_slack_message(e)


def get_users(env="DEV"):
    conn = None
    cursor = None

    try:
        db_config = DB_CONFIG_FETCH_DEV if env == "DEV" else DB_CONFIG_FETCH_PROD

        conn = psycopg2.connect(**db_config)
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute(
            "SELECT xstation_id, password, is_real FROM users_credentials_xstation WHERE verification = TRUE;"
        )
        users = cursor.fetchall()

        return decrypt_users(users)

    except (Exception, psycopg2.Error) as error:
        script_logger.error(f"Error while connecting to PostgreSQL: {error}")
        send_slack_message(error)

    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


def get_trades(user):
    try:
        xstation_id = user.get("xstation_id")
        password = user.get("password")
        is_real = user.get("is_real")

        client = APIClient(is_real=is_real)
        loginResponse = client.execute(
            loginCommand(userId=xstation_id, password=password)
        )

        if loginResponse["status"]:
            current_timestamp = int(time.time() * 1000)
            args_history = {"end": current_timestamp, "start": 0}
            data_history = client.commandExecute("getTradesHistory", args_history)[
                "returnData"
            ]

            time.sleep(0.2)

            args_open = {
                "openedOnly": True,
            }
            data_open = client.commandExecute("getTrades", args_open)["returnData"]

            return data_open + data_history
        else:
            script_logger.error(f"Incorrect login for user: {xstation_id}")

    except Exception as e:
        script_logger.error(f"Error fetching trades for {xstation_id}: {e}")
        send_slack_message(f"Error fetching trades for {xstation_id}: {e}")


def create_table(env="DEV"):
    conn = None
    cursor = None

    try:
        db_config = DB_CONFIG_POST_DEV if env == "DEV" else DB_CONFIG_POST_PROD
        conn = psycopg2.connect(**db_config)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS trades (
                order_id BIGINT PRIMARY KEY,
                xstation_id VARCHAR(50),
                cmd INT,
                digits INT,
                offset_value INT,
                order2 BIGINT,
                position BIGINT,
                symbol VARCHAR(50),
                comment TEXT,
                custom_comment TEXT,
                commission FLOAT,
                storage FLOAT,
                margin_rate FLOAT,
                close_price FLOAT,
                open_price FLOAT,
                nominal_value FLOAT,
                profit FLOAT,
                volume FLOAT,
                sl FLOAT,
                tp FLOAT,
                closed BOOLEAN ,
                timestamp BIGINT,
                spread INT,
                taxes FLOAT,
                open_time BIGINT,
                open_time_string VARCHAR(100),
                close_time BIGINT,
                close_time_string VARCHAR(100),
                expiration BIGINT,
                expiration_string VARCHAR(100)
            );
        """)
        conn.commit()

    except (Exception, psycopg2.Error) as error:
        script_logger.error(f"Error creating table: {error}")
        send_slack_message(f"Error creating table: {error}")

    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


def save_trades(trades, user, env="DEV"):
    conn = None
    cursor = None
    
    try:
        db_config = DB_CONFIG_POST_DEV if env == "DEV" else DB_CONFIG_POST_PROD

        conn = psycopg2.connect(**db_config)
        cursor = conn.cursor()

        for trade in trades:
            cursor.execute("""
                INSERT INTO trades (
                    order_id, xstation_id, cmd, digits, offset_value, order2, position, symbol,
                    comment, custom_comment, commission, storage, margin_rate, close_price,
                    open_price, nominal_value, profit, volume, sl, tp, closed, timestamp,
                    spread, taxes, open_time, open_time_string, close_time, close_time_string,
                    expiration, expiration_string
                )
                VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                )
                ON CONFLICT (order_id) DO UPDATE SET
                    close_price = EXCLUDED.close_price,
                    profit = EXCLUDED.profit,
                    closed = EXCLUDED.closed,
                    timestamp = EXCLUDED.timestamp,
                    close_time = EXCLUDED.close_time,
                    close_time_string = EXCLUDED.close_time_string;
            """, (
                trade['order'],
                user['xstation_id'],
                trade['cmd'],
                trade['digits'],
                trade['offset'],
                trade['order2'],
                trade['position'],
                trade['symbol'],
                trade['comment'],
                trade['customComment'],
                trade['commission'],
                trade['storage'],
                trade['margin_rate'],
                trade['close_price'],
                trade['open_price'],
                trade['nominalValue'],
                trade['profit'],
                trade['volume'],
                trade['sl'],
                trade['tp'],
                trade['closed'],
                trade['timestamp'],
                trade['spread'],
                trade['taxes'],
                trade['open_time'],
                trade['open_timeString'],
                trade.get('close_time'),
                trade.get('close_timeString'),
                trade.get('expiration'),
                trade.get('expirationString')
            ))

        conn.commit()

    except (Exception, psycopg2.Error) as error:
        script_logger.error(f"Error while inserting trades into PostgreSQL: {error}")
        send_slack_message(f"Error while inserting trades into PostgreSQL: {error}")

    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


def process_user(user, env="DEV"):
    trades = get_trades(user)
    if trades:
        save_trades(trades, user, env=env)


def main(env="DEV"):
    create_table(env)
    users = get_users(env)
    
    if users:
        process_user_with_env = partial(process_user, env=env)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            executor.map(process_user_with_env, users)



if __name__ == "__main__":
    main(env="DEV")
    main(env="PROD")
    # users = get_users()
    # trades = get_trades(users[1])
    # create_table()
    # save_trades(trades, users[1])    
