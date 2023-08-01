# Ransomeware-Client-Server

This project was started using https://learning.oreilly.com/library/view/ethicalhacking/9781098129095/xhtml/ch05.xhtml/ar?.
The base project initially uses the client to create a symmetric key that is used to encypt a file, and then is itself encypted.
The server will decrypt the key used to encypt the file so that the client may decrypt the file using the symmetric key. 
The purpose of this project is to make it more realistic in how it works. Currently it just executes the code and it all happens. I would like to check for a payment, have the flow of client server change, and perhaps run the server on the cloud and potentially add a GUI for the client to just grab multiple files to encypt.