#!/usr/bin/env python3

from pwn import remote, xor
import hashlib
import base64


class Client:
    def __init__(self, verbose=True):
        # self.r = remote('nftp.challs.external.open.ecsc2024.it', 1234)
        # self.r = remote('nftp.testing.internal', 39123)
        self.r = remote('localhost', 1235)
        self.verbose = verbose


    def __chal_resp(self, chal):
        self.chal = chal
        key = bytes([22, 163, 9, 205, 30, 109, 176, 116, 171, 205, 149, 37, 244, 14, 183, 236, 163, 117, 79, 84, 154, 206, 45, 101, 255, 154, 219, 244, 145, 132, 173, 158])
        hexd = hashlib.md5(xor(bytes([(ord(c)+64)%256 for c in self.chal]), key)).hexdigest()
        return hexd
    

    def __sign(self, counter):
        sig = hashlib.md5(str(counter).encode() + bytes([(ord(c)-64)%256 for c in self.chal][:17])).hexdigest().encode()
        return sig


    def authenticate(self):
        chal = self.r.recvline(False).decode()
        resp = self.__chal_resp(chal)
        self.r.sendline(resp.encode())
        res = self.r.recvline(False).decode()

        if res != 'Successfully authenticated':
            if self.verbose:
                print(res)
            return 1
        
        self.counter = 0
        return 0
    

    def list_files(self):
        if self.verbose:
            print('Listing files...')
        
        signature = self.__sign(self.counter)
        self.counter += 1
        self.r.sendline(base64.b64encode(signature + b' list'))
        valid = self.r.recvline(False).decode()

        if valid != 'Valid signature':
            print(valid)
            self.r.close()
            exit()
        
        self.num_files = int(self.r.recvline(False).decode())

        if self.verbose:
            print(f'{self.num_files} files:')
        self.files = []

        for i in range(self.num_files):
            f = self.r.recvline(False).decode()
            self.files.append(f)
            if self.verbose:
                print(f'{i+1}. {f}')
        
        if self.verbose:
            print()
        
        return self.files
    

    def __get_file(self, filename):
        signature = self.__sign(self.counter)
        self.counter += 1
        self.r.sendline(base64.b64encode(signature + b' get ' + filename.encode()))
        valid = self.r.recvline(False).decode()

        if valid != 'Valid signature':
            print(valid)
            self.r.close()
            exit()
        
        return self.r.recvline(False).decode()


    def get_first_n_files(self, n):
        if self.verbose:
            print('Getting files...')
        
        if n >= self.num_files:
            if self.verbose:
                print('Too many files')
            return 1
        
        file_content = []

        for i in range(n):
            fc = self.__get_file(self.files[i])
            if self.verbose:
                print(f'{i+1}: {self.files[i]}')
                print(fc)
            file_content.append(fc)
        
        if self.verbose:
            print()
        
        return file_content
    

    def close(self):
        signature = self.__sign(self.counter)
        self.counter += 1
        self.r.sendline(base64.b64encode(signature + b' exit'))
        valid = self.r.recvline(False).decode()

        if valid != 'Valid signature':
            print(valid)
            self.r.close()
            exit()
        
        self.r.close()


c = Client()
c.authenticate()
c.list_files()
c.get_first_n_files(3)
c.close()