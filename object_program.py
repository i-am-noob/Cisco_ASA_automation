import getpass
from dotenv import load_dotenv
import os
from netmiko import ConnectHandler
import ast

load_dotenv()
ip_list_srt = os.getenv("IPADDRESS_LIST")

IPADDRESS = ast.literal_eval(ip_list_srt)



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

     get_objects = netconnect.send_command('show run object network', read_timeout = 180, use_textfsm = True)
     return get_objects

def create_object():
        ''' Create ASA object and return a dictionary of object type and value'''

    

        object_type = input("Enter object type (host/subnet/FQDN) or quit: ").lower()

        if object_type == 'quit':
            return None            
            

        if object_type == 'host':
            host_ip = input("Enter the host IP to add: ")
            ip_object = {'host' : host_ip}
            
            return ip_object

        elif object_type == 'subnet':
            network = input("Enter Network IP: ")
            netmask = input("Enter the Subnet Mask: ")
            subnet_object = {'network': network, 'subnet' : netmask}
            return subnet_object

        elif object_type =='fqdn':
            fqdn = input("Enter FQDN: ")
            fqdn_object = {'fqdn' : fqdn}
            return fqdn_object
        

def check_object_exists(new_object, existing_object):
    ''' Check if the Object created by the user exists on the ASA Device'''

    # new object can be {'host' : '10.10.10.10'} or {'network': '10.10.10.0', 'subnet' : '255.255.255.0'} or {'fqdn': 'fb.com'}

    new_object_type = list(new_object.keys())  # ['host'] or ['network', 'subnet'] or ['fqdn']
    new_object_value = list(new_object.values())

    found = False

    for item in existing_object:

        

        if new_object_type[0] == 'host' and item.get('host') == new_object_value[0]:
            print(f"The host already exists as {item['name']}")
            found = True
            return found
        
        elif new_object_type[0] == 'network' and item.get('network') == new_object_value[0] and item.get('netmask') == new_object_value[1]:
            print(f"The network already exists as {item['name']}")
            found = True
            return found
            
        
        elif new_object_type[0] == 'fqdn' and item.get('fqdn') ==new_object_value[0]:
            print(f"The FQDN already exists as {item['name']}")
            found = True
            return found
        
    return False
        

    

def create_object_command(name, description, new_object):
    ''' Create ASA command based on the object type'''

    if 'host' in new_object:
        commands = [f"object network {name}",
                        f"host {new_object['host']}",
                        f"description {description}"]
    elif 'network' in new_object:
        commands = [f"object network {name}",
                    f"subnet {new_object['network']} {new_object['subnet']}",
                    f"description {description}"]
        
    elif 'fqdn' in new_object:
        commands = [f"object network {name}",
                    f"fqdn {new_object['fqdn']}",
                    f"description {description}"]
        
    return commands 

        


def main():
    username, password = get_credentials()
    device_ips = IPADDRESS

    while True:  # Global loop: Keep adding objects until user wants to quit
        new_object = create_object()
        
        if not new_object:
            break

        for ip in device_ips:
            device = create_device(ip, username, password)   
            
            # Connect to the device
            netconnect = ConnectHandler(**device)
            print(f"Connecting to {ip}.............................\n")
            netconnect.enable()
            
            existing_object = get_existing_objects(netconnect)
            object_present = check_object_exists(new_object, existing_object)

            # If exists, ask to add another object for this specific device
            while object_present:
                choice = input(f"Object already exists on {ip}. Do you wanna add another object? (yes/no): ")
                if choice.lower() == 'yes':
                    new_object = create_object()
                    if not new_object:
                        break
                    object_present = check_object_exists(new_object, existing_object)
                else:
                    break

            # If object is now unique, create it
            if not object_present and new_object:
                print(f"Creating new object on {ip}...")
                name = input("Enter the name for your object: ").replace(" ", "_")
                description = input("Enter description: ")

                post_command = create_object_command(name, description, new_object)
                send_command = netconnect.send_config_set(post_command)
                print(send_command)

            netconnect.disconnect()

        # After all devices are finished, ask if user wants to start the whole process again
        final_choice = input("\nFinished deployment to all devices. Do you want to add another brand new object? (yes/no): ")
        if final_choice.lower() != 'yes':
            print("Exiting program.")
            break

if __name__ == "__main__":
    main()



