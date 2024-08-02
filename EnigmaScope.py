from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from tabulate import tabulate
import argparse
import requests
import datetime
import bcrypt
import base64
import json
import zlib
import os


class Printer:
    @staticmethod
    def log(data: str):
        print(f"[+] {data.capitalize()}")


    @staticmethod
    def err(data: str):
        print(f"[-] {str(data).capitalize()}")


class Encryptor:
    @staticmethod
    def passwordToKey(password: bytes):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            iterations=100000,
            salt=b"EnigmaScope-salt",
            length=32
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key
    

    @staticmethod
    def encrypt(password: bytes, data: bytes):
        try:
            cipher = Fernet(Encryptor.passwordToKey(password))
            return cipher.encrypt(data)
        except:
            Printer.err("encryption failed.")
            return False


    @staticmethod
    def decrypt(password: bytes, data: bytes):
        try:
            cipher = Fernet(Encryptor.passwordToKey(password))
            return cipher.decrypt(data)
        except:
            Printer.err("decryption failed.")
            return False


class EnigmaScope:
    def __init__(self, imageFilePath) -> None:
        self.imageFilePath = imageFilePath
        self.imageName = os.path.basename(self.imageFilePath)
        self.outputFolder = os.path.join(os.path.expanduser('~'), "Documents", "EnigmaScope", self.imageName.split(".")[0])
        self.TAG = zlib.compress(b"(ENIGMASCOPE-START)[ENIGMASCOPE-DATA](ENIGMASCOPE-END)")

        if not os.path.exists(self.outputFolder):
            os.makedirs(self.outputFolder)

    def sourceBufferWriter(self, jsonData):
        with open(self.imageFilePath, "rb") as f:
            data = f.read().split(self.TAG)
        
        jsonData = json.dumps(jsonData).encode()
        data = data[0] + self.TAG + zlib.compress(jsonData)
        with open(self.imageFilePath, "wb") as f:
            f.write(data)


    def sourceBufferReader(self):
        with open(self.imageFilePath, "rb") as f:
            data = f.read().split(self.TAG)
        
        if len(data) == 1:
            Printer.log("creating new source.")
            newPassword = input("Enter a new password (you cannot recover data without this password): ").encode()
            if len(newPassword) == 0:
                Printer.err("password length is 0.")
                return False
            
            token = bcrypt.hashpw(newPassword, bcrypt.gensalt())
            config = {
                "token": token.decode(),
                "data": {}
            }
            self.password = newPassword
            self.sourceBufferWriter(config)
            return "new"
        elif len(data) == 2:
            return json.loads(zlib.decompress(data[1]))
        
        return False

    def login(self):
        res = self.sourceBufferReader()

        if res == "new":
            Printer.log("new secure source was created.")
            return True
        elif not res:
            return False
        
        password = input("Enter password: ").encode()
        if not bcrypt.checkpw(password, res['token'].encode()):
            Printer.err("incorrect password.")
            return False
        
        Printer.log("password match success.")
        self.password = password
        return True
    

    def run(self):
        self.helpMenu()

        while True:
            userInput = input(f"[{self.imageName}]> ")

            if userInput == "q":
                break
            elif userInput == "help":
                self.helpMenu()
            elif userInput == "list":
                self.listSource()
            elif userInput.startswith("write "):
                self.writeSource(userInput[6:])
            elif userInput.startswith("read "):
                self.readSource(userInput[5:])
            elif userInput.startswith("delete "):
                self.deleteSource(userInput[7:])


    def listSource(self):
        data = self.sourceBufferReader()['data']
        tableData = []
        for index, fileName in enumerate(data):
            tableData.append([
                index, 
                fileName, 
                data[fileName]['time'],
                data[fileName]['size']
            ])
        
        print(f'\n{tabulate(tableData, headers=["ID", "FILE", "TIME", "SIZE"])}\n')

    
    def writeSource(self, filePath):
        if os.path.exists(filePath) and os.path.isfile(filePath):
            fileName = os.path.basename(filePath)
            fileName = self.filterFilename(fileName)
            
            with open(filePath, "rb") as f:
                binData = f.read()
                encryptedData = Encryptor.encrypt(self.password, binData)

            if not encryptedData: return
            oldData = self.sourceBufferReader()
            oldData['data'][fileName] = {
                "size": "{:.2f}".format(len(binData) / (1024 * 1024)),
                "time": str(datetime.datetime.now()),
                "bin": encryptedData.decode()
            }
            self.sourceBufferWriter(oldData)
            Printer.log(f"write '{fileName}' successfully.")
            return
        
        if 'http' in filePath:
            try:
                fileName = filePath.split("/")[-1]
                fileName = self.filterFilename(fileName)
                res = requests.get(filePath, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"})
                
                if res.status_code == 200:
                    binData = res.content
                    encryptedData = Encryptor.encrypt(self.password, binData)
                    if not encryptedData: return

                    oldData = self.sourceBufferReader()
                    oldData['data'][fileName] = {
                        "size": "{:.2f}".format(len(binData) / (1024 * 1024)),
                        "time": str(datetime.datetime.now()),
                        "bin": encryptedData.decode()
                    }
                    self.sourceBufferWriter(oldData)
                    Printer.log(f"write '{fileName}' successfully.")
                else:
                    Printer.err(f"STATUS CODE: {res.status_code}")
            except Exception as e:
                Printer.err(e)
            return
        
        Printer.err(f"URL or FILE '{filePath}' not found.")


    def readSource(self, fileId):
        data = self.sourceBufferReader()['data']

        if fileId == "*":
            for fileName in data:
                decrypedData = Encryptor.decrypt(self.password, data[fileName]['bin'])
                if not decrypedData: continue
                filePath = os.path.join(self.outputFolder, fileName)
                with open(filePath, "wb") as f:
                    f.write(decrypedData)
                Printer.log(f"Read success. Saved on '{filePath}'")
            return
        
        for fileIndex, fileName in enumerate(data):
            if int(fileId) == fileIndex:
                decrypedData = Encryptor.decrypt(self.password, data[fileName]['bin'])
                if not decrypedData: return
                filePath = os.path.join(self.outputFolder, fileName)
                with open(filePath, "wb") as f:
                    f.write(decrypedData)
                Printer.log(f"Read success. Saved on '{filePath}'")
                return
            
        Printer.err(f"ID not found")

    def deleteSource(self, fileId):
        data = self.sourceBufferReader()

        if fileId == "*":
            data['data'] = {}
            self.sourceBufferWriter(data)
            Printer.log(f"all deleted successfully.")
            return

        for fileIndex, fileName in enumerate(data['data']):
            if int(fileId) == fileIndex:
                del data['data'][fileName]
                self.sourceBufferWriter(data)
                Printer.log(f"file '{fileName}' deleted successfully.")
                return
            
        Printer.err(f"ID not found")

    
    def filterFilename(self, filename):
        chars = '\\/:*?"<>|'
        for c in chars:
           filename = filename.replace(c, '')
        return filename


    def helpMenu(self):
        print('''
+======== COMMANDS ========+
help        Help menu.
q           Exit.
              
list        List all files.     
write       <URL or FILE>   ex: write /path/to/file, write https://example.com/data.zip
read        <ID or *>       ex: read 0, read *      
delete      <ID or *>       ex: delete 0, delete *
''')
        

def main():
    parser = argparse.ArgumentParser(description="EnigmaScope is a versatile Python tool designed to conceal and encapsulate diverse elements within a unified framework.")
    parser.add_argument("-l", "--load", required=True, help="Load the source file. ex: wallpaper.jpg, icon.png ....")
    args = parser.parse_args()
    imageFilePath = args.load

    if not os.path.exists(imageFilePath):
        Printer.err("source file not found.")
        return
    
    try:
        enigmaScope = EnigmaScope(imageFilePath)
        if enigmaScope.login():
            enigmaScope.run()
    except KeyboardInterrupt:
        Printer.log("KeyboardInterrupt - enigmaScope exit.")
        exit(0)
    except Exception as e:
        Printer.err(e)

    Printer.log("enigmaScope exit.")
    
if __name__ == "__main__":
    main()