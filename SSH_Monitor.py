import time
import re
from collections import defaultdict, deque
import os

log_line = re.compile(
    r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*?'
    r'(?:Failed password | Accepted password).*?'
    r'for\s+(?P<user>\S+).*?'
    r'from\s+(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
)
FAILED_LIMIT = 5
FAILED_WINDOW = 300
BLOCKED_IP_FILE = "blocked_ips.txt"

failed_attempts = {}

def line_re(line):
    match = log_line.search(line)
    if match:
        entry = match.groupdict()
        if 'Accepted password' in line:
            entry['event'] = 'SUCCESS'
            entry['message'] = 'User login accepted'
        else:
            entry['event'] = 'FAILURE'
            entry['message'] = 'User login failed'
        return entry
    return None

def detect_bruteforce(ip):
    now = time.time()
    if ip not in failed_attempts:
        failed_attempts[ip] = []
    failed_attempts[ip].append(now)
    valid_attempts = []
    for t in failed_attempts[ip]:
        if now - t <= FAILED_WINDOW:
            valid_attempts.append(t)
    failed_attempts[ip] = valid_attempts
    if len(valid_attempts) >= FAILED_LIMIT:
        return True
    return False

def is_ip_blocked(ip):
    if not os.path.exists(BLOCKED_IP_FILE):
        return False

    with open(BLOCKED_IP_FILE, "r") as file:
        blocked_ips = file.read().splitlines()

    return ip in blocked_ips

def save_blocked_ip(ip):
    with open(BLOCKED_IP_FILE, "a") as file:
        file.write(ip + "\n")

def block_ip(ip):
    command = f"iptables -A INPUT -s {ip} -j DROP"
    os.system(command)

def monitoring(log_file):
    file = open(log_file)
    print("Starting the analyser.......")
    while True :
        line = file.readline()
        if not line:
            time.sleep(1)
            continue
        log_details = line_re(line)
        if log_details:
            activity(log_details)

def activity(log_details):
    ip_info = log_details['ip']
    event_info = log_details['event']
    user_info = log_details['user']
    current_time = time.strftime('%H:%M:%S')
    if event_info == "SUCCESS":
        if ip_info in failed_attempts:
            del failed_attempts[ip_info]

        print(f"[{current_time}] [SUCCESS] User {user_info} logged in from {ip_info}")

    else:
        attack = detect_bruteforce(ip_info)
        print(f"[{current_time}] [FAILURE] User {user_info} failed login from {ip_info}")
        if attack:
            if not is_ip_blocked(ip_info):
                save_blocked_ip(ip_info)
                block_ip(ip_info)
                print(f"[{current_time}] [ALERT] Brute-force attack detected from {ip_info}")
            else:
                print(f"[{current_time}] [INFO] IP {ip_info} is already blocked.")

path_log = input("Enter the full path to the log file ")
monitoring(path_log)
