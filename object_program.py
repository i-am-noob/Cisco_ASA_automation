import getpass
from dotenv import load_dotenv
import os


load_dotenv()
IPADDRESS = os.get("IPADDRESS_LIST")


def get_credentials():
    
    ''' Get Username and Password from the user'''

    username = input("Enter Username: ")
    password = getpass.getpass("Enter Password: ")

    return username, password


def create_device(ip,username,password):
    ''' Create device dictionary using the IP address '''

    device = { 
        'device_type' : 'cisco_asa',
        'host' : ip,
        'username' : username,
        'password' : password,
        'fast_cli' : True,
        'secret' : password,
        'disabled_algorithms' : {
            "pubkeys": ["rsa-sha2-256", "rsa-sha2-512"]}
    }

    return device

def get_existing_objects(netconnect):
     '''Send show command and return the existing objects as list'''

     get_objects = netconnect.send('show run object network', read_timeout = 180, use_textfsm = True)
     return get_objects


def main():
    username,password = get_credentials()
    device_ips = IPADDRESS

    for ip in device_ips:
        device = create_device(ip, username, password)

        try:
            netconnect = ConnectHandler(**device)
            netconnect.enable()

        except:
            print(f"Error connecting to {ip}")


        get_object = get_existing_objects(netconnect)
        print(get_object)



