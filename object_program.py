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

    #while True:

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
            subnet_object = {'network': network, 'netmask' : netmask}
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
    username,password = get_credentials()
    device_ips = IPADDRESS

    for ip in device_ips:
        device = create_device(ip, username, password)

        
        netconnect = ConnectHandler(**device)
        netconnect.enable()

        existing_object = get_existing_objects(netconnect)
        
      

        new_object = create_object() # return host or fqdn or range or subnet as a dictionary
        if new_object: ## if a new object was created

            object_present = check_object_exists(new_object, existing_object)

            if not object_present:
                print("Need to create new object")
                name = input("Enter the name for your object: ")
                description = input("Enter description: ")

                post_command = create_object_command(name, description, new_object)
                




                

        netconnect.disconnect()


if __name__ == "__main__":
    main()


