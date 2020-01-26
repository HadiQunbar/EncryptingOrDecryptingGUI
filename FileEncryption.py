from tkinter import *
from Crypto import Random
from Crypto.Cipher import AES, PKCS1_OAEP
import os
import os.path
import time
class Encryptor:
    def __init__(self, key):
        self.key = key

    def pad(self, s):
        return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

    def encrypt(self, message, key, key_size=256): # encrypting the file using padding
        message = self.pad(message)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(message)

    def encrypt_file(self, file_name):# encrypt a Key That is given & eith the function encrypt
        with open(file_name, 'rb') as fo:
            plaintext = fo.read()
        enc = self.encrypt(plaintext, self.key)
        with open(file_name + ".enc", 'wb') as fo:
            fo.write(enc)
        os.remove(file_name)

    def decrypt(self, ciphertext, key): # decrypting by striping the padding and using he key that is given
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext[AES.block_size:])
        return plaintext.rstrip(b"\0")

    def decrypt_file(self, file_name): # Reading the file and decrypting using decrypt
        with open(file_name, 'rb') as fo:
            ciphertext = fo.read()
        dec = self.decrypt(ciphertext, self.key)
        with open(file_name[:-4], 'wb') as fo:
            fo.write(dec)
        os.remove(file_name)

    def getAllFiles(self): # Getting all files in this path of the project / Application
        dir_path = os.path.dirname(os.path.realpath(__file__))
        dirs = []
        for dirName, subdirList, fileList in os.walk(dir_path):
            for fname in fileList:
                if fname != 'main.py' and fname != 'data.txt.enc' and fname != ".idea":
                    dirs.append(dirName + "\\" + fname)
        return dirs

    def encrypt_all_files(self): # encrypt using encrypt def and getAllFiles
        dirs = self.getAllFiles()
        for file_name in dirs:
            self.encrypt_file(file_name)
        print("Button 3 was pressed")

    def decrypt_all_files(self): # decrypt using encrypt def and getAllFiles
        dirs = self.getAllFiles()
        for file_name in dirs:
            self.decrypt_file(file_name)
        print("Button 4 was pressed")




key = b'[EX\xc8\xd5\xbfI{\xa2$\x05(\xd5\x18\xbf\xc0\x85)\x10nc\x94\x02)j\xdf\xcb\xc4\x94\x9d(\x9e'
enc = Encryptor(key)
clear = lambda: os.system('cls')

if os.path.isfile('data.txt.enc'): # Checks if the data.enc is there
    help = True
    while help == True: # Do exist
        password = str(input("Enter password: "))
        enc.decrypt_file("data.txt.enc")
        p = ''
        with open("data.txt", "r") as f:
            p = f.readlines()
        if p[0] == password:
            enc.encrypt_file("data.txt")
            help = False
        else :
            print("Sorry Wrong Password")
            enc.encrypt_file("data.txt")

else:
    while True: # Doesnt exists
        clear()
        password = str(input("Setting up stuff. Enter a password that will be used for decryption: "))
        repassword = str(input("Confirm password: "))
        if password == repassword:
            break
        else:
            print("Passwords Mismatched!")
    f = open("data.txt", "w+")
    f.write(password)
    f.close()
    enc.encrypt_file("data.txt")
    print("Please restart the program to complete the setup")
    time.sleep(15)


def encryptFile():
    enc.encrypt_file(str(input("Enter name of file to encrypt: ")))
def decryptFile():
    fileName = input("Enter name of file to decrypt: ")
    enc.decrypt_file(fileName+".enc")



root = Tk() # using tkinter for creating the main Screen
root.geometry("300x300")
one = Label(root, text="Wich file want to encrypt")
oneBtn = Button(root, text="1", width="20", height='2',command=encryptFile)# When encrypting the file Write in the console the extension
two = Label(root, text="press 2 to decrypt file ")
twoBtn = Button(root, text="2", width="20", height='2',command=decryptFile)# When encrypting the file Write in the console the extension no need for .enc
three = Label(root, text="press 3 to encrypt all file in directory")
threeBtn = Button(root, text="3", width="20", height='2', command=enc.encrypt_all_files)
four = Label(root, text="press 4 to decrypt all file in directory  ")
fourBtn = Button(root, text="4", width="20", height='2', command=enc.decrypt_all_files)
one.pack()
oneBtn.pack()
two.pack()
twoBtn.pack()
three.pack()
threeBtn.pack()
four.pack()
fourBtn.pack()
root.mainloop()

def encryptFile():
    fileName = str(input("Enter name of file to encrypt: "))
    enc.encrypt_file(fileName)
def decryptFile():
    fileName = str(input("Enter name of file to encrypt: "))
    enc.decrypt_file(fileName)

