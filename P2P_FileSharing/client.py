from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import os
import socket
import random
import shutil 




def isPrime(n):

    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True



def findPrimitiveRoot(p):
    if p == 2:
        return 1
    fact = []
    phi = p - 1
    n = phi
    for i in range(2, int(phi**0.5) + 1):
        if n % i == 0:
            fact.append(i)
            while n % i == 0:
                n //= i
    if n > 1:
        fact.append(n)
    for res in range(2, p + 1):
        flag = True
        for factor in fact:
            if pow(res, phi // factor, p) == 1:
                flag = False
                break
        if flag:
            return res
    return -1




def diffieHellman(val):

    P = val

    if((isPrime(P)) == False):

        while(isPrime(P) == False):

            P = random.randint(1,100)  # A prime number

    G = findPrimitiveRoot(P)  # Finding a primitive root for P

    # Private keys chosen randomly (should be less than P though)
    privateKeyClient = P-3

    privateKeyServer = P-16

    # Public keys computed
    publicKeyClient = pow(G, privateKeyClient, P)
    publicKeyServer = pow(G, privateKeyServer, P)

    # Secret keys computed
    secretKeyClient = pow(publicKeyServer, privateKeyClient, P)
    secretKeyServer = pow(publicKeyClient, privateKeyServer, P)

    #print("Private Key Client:", privateKeyClient)
    #print("Public Key Client:", publicKeyClient)
    #print("Secret Key Client:", secretKeyClient)

    #print("Private Key Server:", privateKeyServer)
    #print("Public Key Server:", publicKeyServer)
    #print("Secret Key Server:", secretKeyServer)

    # Verify both secret keys are the same
    if(secretKeyClient == secretKeyServer):

        return secretKeyClient, secretKeyServer

    else:
        print("The secret keys are not equal, there's an error.")



def deleteFile(filepath):

    if os.path.exists(filepath):

        os.remove(filepath)

    else:
        print("The file does not exist") 



def copyFile(filepath, copyFilePath):  

    shutil.copyfile(filepath, copyFilePath)




def hashFile(filepath, outputFilePath):
    """
    Hashes a file using SHA2-256 and writes the hash to a new file.

    Path to the file to be hashed.
    Path to write the hexadecimal hash.
    """
    hash_sha256 = SHA256.new()
    try:
        with open(filepath, 'rb') as file:

            chunk_size = 4096

            while chunk := file.read(chunk_size):

                hash_sha256.update(chunk)

    except FileNotFoundError:

        return "File not found."

    except Exception as e:

        return f"An error occurred: {e}"

    # Compute the hexadecimal digest of the hash
    hexdigest = hash_sha256.hexdigest()

    # Write the hash to the output file
    try:

        with open(outputFilePath, 'w') as output_file:

            output_file.write(hexdigest)

        return f"Hash written to {outputFilePath}."

    except Exception as e:

        return f"Failed to write hash to file: {e}"




def fileIntegrityCheck(hashFilePath1, hashFilePath2):
    """
    Compares the contents of two hash files to check file integrity.
    """
    try:
        with open(hashFilePath1, 'r') as file1:
            hash1 = file1.read().strip()
    except FileNotFoundError:
        return "Error: The first hash file does not exist."
    except Exception as e:
        return f"Error reading the first hash file: {e}"

    try:
        with open(hashFilePath2, 'r') as file2:
            hash2 = file2.read().strip()
    except FileNotFoundError:
        return "Error: The second hash file does not exist."
    except Exception as e:
        return f"Error reading the second hash file: {e}"

    if hash1 == hash2:
        return True
    else:
        return False




def generateAESkey(shardsSecretKey, salt):
    """
    Generate a consistent AES-128 key from a Diffie-Hellman shared secret integer using a predetermined salt.

    The shared secret integer from Diffie-Hellman.
    A predetermined salt used in the HKDF, must be the same for both parties.
    """
    # Convert the shared secret integer to bytes
    sharedSecretKeyBytes = shardsSecretKey.to_bytes((shardsSecretKey.bit_length() + 7) // 8, byteorder='big')

    # Use HKDF to derive a 128-bit key for AES-128
    aesKey = HKDF(sharedSecretKeyBytes, 16, salt, SHA256)

    return aesKey



def aesEncryptFile(inputFile, outputFile, aesKey):

    iv = get_random_bytes(16)  # IV for AES

    cipherAES = AES.new(aesKey, AES.MODE_CBC, iv)  # AES-128 CBC mode encryption

    try:
        with open(inputFile, 'rb') as file_in:

            with open(outputFile, 'wb') as file_out:

                file_out.write(iv)  # Write the IV to the beginning of the file

                while chunk := file_in.read(1024 * AES.block_size):

                    if len(chunk) != 1024 * AES.block_size:

                        chunk = pad(chunk, AES.block_size)  # Pad only the last chunk

                    ciphertextAES = cipherAES.encrypt(chunk)

                    file_out.write(ciphertextAES)

        print("Encryption complete.")

    except IOError as e:

        print(f"File error: {e}")






def aesDecryptFile(inputFile, outputFile, aesKey):

    try:

        with open(inputFile, 'rb') as file_in:

            iv = file_in.read(16)  # The first 16 bytes are the IV

            decryptorAES = AES.new(aesKey, AES.MODE_CBC, iv)  # AES-128 CBC mode decryption

            with open(outputFile, 'wb') as file_out:

                final_chunk = b''

                while chunk := file_in.read(1024 * AES.block_size):

                    decrypted_chunk = decryptorAES.decrypt(chunk)

                    final_chunk += decrypted_chunk

                # Unpad the last chunk outside the loop
                file_out.write(unpad(final_chunk, AES.block_size))

        print("Decryption complete.")

    except (ValueError, KeyError, IOError) as e:

        print(f"Decryption error: {e}")




def send(sock, file):
    file_path = file
    try:
        

        with open(file_path, 'rb') as file:
            # First, let the server know how big the file is
            file_size = os.path.getsize(file_path)
            file_size_b = str(file_size).encode()
            sock.send(file_size_b)

            # Second, wait for confirmation: server should send back file size
            ack = sock.recv(1024)
            if file_size != int(ack.decode()):
                raise Exception("Server data size ACK failure.")

            # Third, send the data in blocks of 1024 bytes
            data_sent = 0
            while True:
                data = file.read(1024)
                if len(data) == 0:
                    break
                sock.send(data)
                data_sent += len(data)
                print("===============> Sending [", len(data), data_sent, "bytes]")

    except Exception as e:
        print(":( Send failure:", e)

    finally:
        print("Data sent.")

    print("Waiting for final ACK.")
    try:
        ack_msg = sock.recv(1024)
    except Exception as e:
        print("Ack failure:", e)
    finally:
        print("ACK:", ack_msg)
        #sock.close()




def receive(client_sock, create_file):
    file_path = create_file
    
    try:
        #First, waiting on the data size
        size_b = client_sock.recv(1024)
        size = int(size_b.decode())
        print("Client is about to send ", size, "bytes")

        #Second, send ACK
        client_sock.send(size_b)

        #Third, start receiving data in blocks of 1024 bytes
        data_size = 0
        data = b"" #create data buffer
        with open(file_path, "wb") as file:
            while data_size < size:
                new_data = client_sock.recv(1024)
                if len(new_data) == 0:
                    break

                data_size += len(new_data)
                data += new_data
                print("==============> Received [", len(new_data), len(data), size ,"bytes]")
            file.write(data)
        
        
    except Exception as e:
        print("Data recv failure:",e)
    finally:
        print("Got everything.")
        msg = "Got all of your data. [" + str(len(data)) + " bytes]"
        client_sock.send(msg.encode())
    



def retrieve_from_server(sock, session_key, static_key):
    #prompt the user to ping server for files
    ping = input("Would you like to bretrieve your files?(Y/N):")
    sock.send(ping.encode())
    
    #This is where we receive the doubly encrypted files from server and we decrypt here with session keys
    receive(sock, "transmit1.txt")
    receive(sock, "transmit2.txt")

    aesDecryptFile("transmit1.txt", "hash.txt", session_key)
    aesDecryptFile("transmit2.txt", "encryptedFile.txt", session_key)

    deleteFile("transmit1.txt")

    deleteFile("transmit2.txt")

    #decrypt the file from server
    aesDecryptFile("encryptedFile.txt", "new_alice.txt", static_key)
    #send ping back to let the server know integrity checked it and that it should delete it's files
    hashFile("new_alice.txt", "copy_hash.txt")
    if (fileIntegrityCheck("hash.txt", "copy_hash.txt")):
        msg = "The Hash Files from the server pass the integrity check"
        sock.send(msg.encode())




def establish_connection_sender(target_addr, target_port, session_key, static_key ):


    sender_sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM)
    sender_sock.connect((target_addr, target_port))
    try:
        send(sender_sock, "transmit1.txt")
        send(sender_sock, "transmit2.txt")
        send(sender_sock, "transmit3.txt")

        #receive ack from server that files pass integrity check
        try:
            ack_msg = sender_sock.recv(1024)
        except Exception as e:
            print("Ack failure:", e)
        finally:
            #Deletes files that are stored on the client
            print("ACK:", ack_msg)
            print("Deleting files now...")
            deleteFile("hash.txt")
            deleteFile("alice.txt")
            deleteFile("encryptedFile.txt")
            deleteFile("encryptedHash.txt")
            deleteFile("transmit1.txt")
            deleteFile("transmit2.txt")
            deleteFile("transmit3.txt")
            print("Files have been deleted")

        try:
            retrieve_from_server(sender_sock,session_key, static_key)
        except Exception as e:
            print("Ackk failure:", e)
        finally:
            try:
                ack_msg = sender_sock.recv(1024)
            except Exception as e:
                print("Ack failure:", e)
            finally:
                print("ACK:", ack_msg)

    finally:
        sender_sock.close()




def main():
    target_addr = "B8:27:EB:61:31:CF"  # REPLACE WITH DEVICE ADDRESS
    target_port = 1
    file_path = "client.py"

    secretKeyClient, secretKeyServer = diffieHellman(23)
    salt = b'securelySharedSalt'
    static_key = generateAESkey(9,salt)
    session_key = generateAESkey(secretKeyClient,salt)

    #Simulate the hashing and encryption processes here before sending
    hashFile("alice.txt", "hash.txt")
    aesEncryptFile("alice.txt", "encryptedFile.txt", static_key)
    aesEncryptFile("hash.txt", "encryptedHash.txt", static_key)

    aesEncryptFile("hash.txt", "transmit1.txt", session_key)
    aesEncryptFile("encryptedFile.txt", "transmit2.txt", session_key)
    aesEncryptFile("encryptedHash.txt", "transmit3.txt", session_key)

    establish_connection_sender(target_addr, target_port, session_key, static_key)

main()

