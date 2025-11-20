import time
import re
log_line = re.compile(
    r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*?'
    r'(?:Failed password | Accepted password).*?'
    r'for\s+(?P<user>\S+).*?'
    r'from\s+(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
)
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
        print(f"[{current_time}] [SUCCESS] User : {user_info} has been logged in successfully from IP : {ip_info}")
    if event_info == "FAILURE":
        print(f"[{current_time}] [FAILURE] User : {user_info} Failed log in attempt from IP : {ip_info}")

path_log = input("Enter the full path to the log file ")
monitoring(path_log)
