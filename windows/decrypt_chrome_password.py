import os
import json
import sqlite3
import shutil
import csv
from Cryptodome.Cipher import AES
import base64

# GLOBAL CONSTANT
CHROME_PATH_LOCAL_STATE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Local State")
CHROME_PATH_PROFILE_1 = os.path.join(os.path.dirname(os.path.abspath(__file__)),"Profile 1")

# The following functions are needed to handle decryption on macOS
def get_key_from_local_state(local_state):
    encrypted_key = local_state['os_crypt']['encrypted_key']
    encrypted_key = base64.b64decode(encrypted_key.encode())
    encrypted_key = encrypted_key[5:]
    return encrypted_key

def decrypt_password(ciphertext, secret_key):
    try:
        #(3-a) Initialisation vector for AES decryption
        initialisation_vector = ciphertext[3:15]
        #(3-b) Get encrypted password by removing suffix bytes (last 16 bits)
        #Encrypted password is 192 bits
        encrypted_password = ciphertext[15:-16]
        #(4) Build the cipher to decrypt the ciphertext
        cipher = generate_cipher(secret_key, initialisation_vector)
        decrypted_pass = decrypt_payload(cipher, encrypted_password)
        decrypted_pass = decrypted_pass.decode()  
        return decrypted_pass
    except Exception as e:
        print("Decrypt Error:","%s"%str(e))
        print("[ERR] Unable to decrypt, Chrome version <80 not supported. Please check.")
        return ""
    
def decrypt_payload(cipher, payload):
    return cipher.decrypt(payload)


def generate_cipher(aes_key, iv):
    return AES.new(aes_key, AES.MODE_GCM, iv)

    
def get_db_connection(chrome_path_login_db):
    try:
        shutil.copy2(chrome_path_login_db, "Loginvault.db") 
        return sqlite3.connect("Loginvault.db")
    except Exception as e:
        print("%s"%str(e))
        print("[ERR] Chrome database cannot be found")
        return None

if __name__ == '__main__':
    try:
        with open('decrypted_password.csv', mode='w', newline='', encoding='utf-8') as decrypt_password_file:
            csv_writer = csv.writer(decrypt_password_file, delimiter=',')
            csv_writer.writerow(["index", "url", "username", "password"])

            with open(CHROME_PATH_LOCAL_STATE, "r", encoding='utf-8') as f:
                local_state = f.read()
                local_state = json.loads(local_state)
                secret_key = get_key_from_local_state(local_state)

            chrome_path_login_db = os.path.normpath(os.path.join(CHROME_PATH_PROFILE_1, 'Login Data'))
            conn = get_db_connection(chrome_path_login_db)
            if secret_key and conn:
                cursor = conn.cursor()
                cursor.execute("SELECT action_url, username_value, password_value FROM logins")
                for index, login in enumerate(cursor.fetchall()):
                    url = login[0]
                    username = login[1]
                    ciphertext = login[2]
                    if url != "" and username != "" and ciphertext != "":
                        # Initialize vector for AES decryption
                        iv = ciphertext[3:15]
                        # Get encrypted password by removing suffix bytes (last 16 bits)
                        encrypted_password = ciphertext[15:-16]
                        decrypted_password = decrypt_password(encrypted_password, secret_key)
                        print("Sequence: %d" % (index))
                        print("URL: %s\nUser Name: %s\nPassword: %s\n" % (url, username, decrypted_password))
                        print("*" * 50)
                        csv_writer.writerow([index, url, username, decrypted_password])
                cursor.close()
                conn.close()
                os.remove("Loginvault.db")
    except Exception as e:
        print("[ERR] %s" % str(e))
