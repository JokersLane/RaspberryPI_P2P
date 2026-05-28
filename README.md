# RaspberryPI_P2P
A simulation of P2P file sharing system using a raspberry PI 4
P2P File Sharing System Program

This README file provides instructions on how to compile and run a Python program, that is designed to demonstrate peer-to-peer file sharing system using a client computer and a raspberry pi acting as a server. 
Required Prerequisites
Before running the program, ensure you have the following installed:
    • Python (3.6 or newer)
    • Linux OS preferred 
    • pip
    • Python CE/IDE (optional)
    • PyCryptodome library
    • Bluetooth connection
    • Python 3 is installed on both the client and server machines.
    • Both devices are capable of Bluetooth communication and are paired beforehand.
    • Having alice.txt in the same folder you run the python program
      
Turn on Bluetooth the raspberry pi and your computer. Make the raspberry pi’s Bluetooth discoverable and connect the two devices via Bluetooth.
To install pip using Linux OS (Ubuntu), use the following commands in the terminal:
sudo apt update
sudo apt install python3-pip

You can install PyCryptodome using pip (if you don't have it, refer to above) :
Open the terminal and enter each command separately:
sudo apt-get install build-essential python3-dev
pip install pycryptodomex
pip install pycryptodome-test-vectors
python3 -m Cryptodome.SelfTest
Note: python3 -m Cryptodome.SelfTest command will take some time to perform it’s necessary tests; please be patient and allow the .SelfTest to fully complete before executing anymore command. Without pycryptodome this program will fail to run; it is essential to have this library installed.

How to Run the Program through Terminal
    1. Open Terminal: Open a terminal window in your computer and one on the raspberry pi.
    2. Navigate to the Program Directory: Use the cd command to navigate to the directory containing server.py on the raspberry pi and client.py on the computer.
		   cd path/to/your/program/directory
	
	Client Side Example(computer): cd Documents/NAMEofTHEfolderTHATtheFILEisLOCATED
	Server Side Example(raspberry pi):  cd Documents
    3. Execute the Script: Once the file path has been established, then run the script using python3 if python 3 has been installed. MAKE SURE THAT SERVER IS RUNNING BEFORE THE CLIENT DOES!! Enter this in the terminal:
		python3 server.py
		python3 client.py
Server (server.py)
Functionality: The server program is responsible for handling incoming connections, receiving encrypted files, decrypting them, and verifying their integrity based on the accompanying hashes. It waits for connections from the client and processes each file sent to it.

Expected Output:
    • Indications that the server is ready and waiting for a connection.
    • Notifications of file receipt, decryption status, and integrity check results.
    • Error messages if the file transfer fails or if integrity checks fail.
Client (client.py)
Functionality: The client program manages the encryption and sending of files. It establishes a Bluetooth connection with the server, encrypts the files and their hashes, and sends them over the established connection. It handles key exchanges for encryption and ensures secure transmission.

Expected Output:
    • Status messages showing the connection status and details of the encryption process.
    • Progress updates during the file transmission, showing the amount of data sent.
    • Confirmation of file delivery and integrity verification from the server.
    • Error messages for connection failures or transmission errors.

Troubleshooting
    • If you encounter any issues with the PyCryptodome library installation, ensure your pip is up-to-date and try reinstalling the library.
    • Make sure you are using a Python version that is compatible with PyCryptodome (Python 3.6 or newer).
    • Bluetooth Connectivity Issues: Ensure that both devices are within range and properly paired.
    • Permission Errors: Run the scripts with administrative privileges or using sudo if you encounter permission-related errors, especially on Linux-based systems.
    • Encryption Errors: Verify that all cryptographic dependencies are correctly installed and that the files intended for transfer exist.
      
For any questions or support, please refer to the PyCryptodome website (https://www.pycryptodome.org/src/installation).
