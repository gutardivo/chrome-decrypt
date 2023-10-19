import base64
import binascii
import glob
import hashlib
import os
import sqlite3
import subprocess
import sys

loginData = os.path.join(os.path.dirname(os.path.abspath(__file__)),"Profile 1/Login Data")


if len(loginData) == 0:
    loginData = os.path.join(os.path.dirname(os.path.abspath(__file__)),"Default/Login Data")


if os.environ.get("safeStorageKey"):
    safeStorageKey = os.environ["safeStorageKey"].encode("utf-8")
else:
    safeStorageKey = (
        (
            subprocess.check_output(
                "security 2>&1 > /dev/null find-generic-password -ga 'Chrome' | awk '{print $2}'",
                shell=True,
            )
        )
        .decode("utf-8")
        .strip("\n")
        .strip('"')
        .encode("utf-8")
    )


if safeStorageKey == "":
    print("ERROR getting Chrome Safe Storage Key")
    sys.exit()


def chromeDecrypt(
    encrypted_value, iv, key=None
):
    hexKey = binascii.hexlify(key)
    hexEncPassword = base64.b64encode(encrypted_value[3:])
    try:  # send any error messages to /dev/null to prevent screen bloating up
        command = "openssl enc -base64 -d -aes-128-cbc -iv '{}' -K {} <<< {} 2>/dev/null".format(
            iv, hexKey.decode("utf-8"), hexEncPassword.decode("utf-8")
        )
        decrypted = subprocess.check_output(command, shell=True)
    except Exception as e:
        decrypted = "ERROR retrieving password"
    return decrypted


def chromeProcess(safeStorageKey, loginData):
    iv = "".join(
        ("20",) * 16
    )
    key = hashlib.pbkdf2_hmac("sha1", safeStorageKey, b"saltysalt", 1003)[:16]
    fd = os.open(loginData, os.O_RDONLY)
    database = sqlite3.connect("/dev/fd/%d" % fd)
    os.close(fd)
    sql = "select username_value, password_value, origin_url from logins"
    decryptedList = []
    with database:
        for user, encryptedPass, url in database.execute(sql):
            if user == "" or (
                encryptedPass[:3] != b"v10"
            ):
                continue
            else:
                urlUserPassDecrypted = (
                    url,
                    user,
                    chromeDecrypt(encryptedPass, iv, key=key),
                )
                decryptedList.append(urlUserPassDecrypted)
    return decryptedList


if __name__ == "__main__":

    for profile in loginData:
        for i, x in enumerate(chromeProcess(safeStorageKey, "%s" % profile)):
            print(f"{i+1}, {x[0]}, {x[1]}, '{x[2].decode('utf-8')}'")
