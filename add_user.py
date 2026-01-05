from netmiko import ConnectHandler
from object_program import *
from dotenv import load_dotenv
import os
import ast

load_dotenv()
ip_list_srt = os.getenv("IPADDRESS_LIST")

IPADDRESS = ast.literal_eval(ip_list_srt)
GROUP_VALUE = os.getenv("GROUP_VALUE")
GROUP_POLICY = os.getenv("GROUP_POLICY")



def add_3p_user(device,username_3p):  
    ''' Create commands to push 3P users'''

    commands = [
        f"username {username_3p} nopassword privilege 2",
        f"username {username_3p} attributes",
        "service-type remote-access",
        f"group-lock value {GROUP_VALUE}",
        f"vpn-group-policy {GROUP_POLICY}"
        ]   

    net_connect = ConnectHandler(**device)
    output = net_connect.send_config_set(commands, read_timeout=180)

    net_connect.save_config()
    net_connect.disconnect()

    return output



def main():
    username, password = get_credentials()
    device_ips = IPADDRESS

    for ip in device_ips:
        device = create_device(ip, username, password)
        
        # Connect to the device
        print(f"Connecting to {ip}.............................\n")
        username_3p = input("Enter 3P username: ")
        add_user = add_3p_user(device, username_3p)
        print(add_user)

if __name__ == "__main__":
    main()















