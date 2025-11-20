import time
def line_split(line):
    part1 = line.split('] ',1)
    time = part1[0]
    other = part1[1]
    part2 = other.split(' ',3)
    ip = part2[0]
    user = part2[1]
    event = part2[2]
    message = part2[3]
    return {
        'time':time,
        'ip': ip,
        'user':user,
        'envent':event,
        'message':message
    }

def monitoring(log_file):
    file = open(log_file)
    print("Starting the analyser.......")
    while True :
        line = file.readline()
        if not line:
            time.sleep(1)
            continue
        log_details = line_split(line.strip())
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
        print(f"[{current_time}] [FALURE] User : {user_info} Failed log in attempt from IP : {ip_info}")

path_log = input("Enter the full path to the log file ")
monitoring(path_log)