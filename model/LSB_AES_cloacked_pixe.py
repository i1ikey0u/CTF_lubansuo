#! /usr/bin/env python
#--coding=utf-8--
#environ: python3
#--coding by shuichon--
import os
import sys
import queue
import threading
import struct
import numpy
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from PIL import Image


sem2 = threading.Semaphore(20)  # 控制线程不超过20个
find_key = threading.Event()  # 设置进程间维护的统一标志


class AESCipher:
    def __init__(self, key): 
        self.bs = 32	# Block size
        self.key = hashlib.sha256(key.encode()).digest()	# 32 bit digest

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(raw)

    def decrypt(self, enc):
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)  # 支持iv
        return self._unpad(cipher.decrypt(enc[AES.block_size:]))

    def _pad(self, s):  # PKCS7 模式
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]



def assemble(v):    
    bytes = bytearray()
    length = len(v)
    for idx in range(0, int(len(v)/8)):
        byte = 0
        for i in range(0, 8):
            if (idx*8+i < length):
                byte = (byte<<1) + v[idx*8+i]                
        bytes.append(byte)
    payload_size = struct.unpack("i", bytes[:4])[0]
    return bytes[4: payload_size + 4]


"""
预处理图片数据
"""
def steg_data(steg_f):
    img = Image.open(steg_f)
    (width, height) = img.size
    conv = img.convert("RGBA").getdata()
    print("[+] Image size: %dx%d pixels." % (width, height))
    v = []
    for h in range(height):
        for w in range(width):
            (r, g, b, a) = conv.getpixel((w, h))
            v.append(r & 1)
            v.append(g & 1)
            v.append(b & 1)
    steg_data = assemble(v)
    return steg_data
    


def check(steg_data, password, preg, rstq):
    if find_key.is_set():
        return
    sem2.acquire()
    try:
        print(f'[-] 尝试参数：{password}')
        cipher = AESCipher(password)
        data_dec = cipher.decrypt(steg_data)
        if preg.encode() in data_dec:
            find_key.set() 
            print(f"[!] 发现匹配内容：{data_dec}")
            print(f"[!] 密码为：{password}")
            rstq.put(password)
            return password
    except Exception as e:
        print(f"失败 {password} failed: {str(e)}")
    finally:
        sem2.release()
    #if not find_key.is_set():
     #   print("所有key已尝试，解密失败.")
    return None


def img_lsb_mult_crack(s_data, keys, preg):
    kq = queue.Queue()
    rstq = queue.Queue()
    threads = []
    for key in keys:
        kq.put(key)
    while not kq.empty():
        if find_key.is_set():
            break
        print(f'[-] 剩余待测参数 {kq.qsize()} 个') 
        key = kq.get(False) 
        t = threading.Thread(target=check, args=(s_data, key, preg, rstq,))
        t.daemon=True
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    print('检测全部完成!')
    if not rstq.empty():
        return rstq.get()


def t():
    steg_f = r'E:\X04_CTF\00TOOLS\07图片隐写及加解密\15cloacked-pixel-python3-master\flag.png'
    s_data = steg_data(steg_f)
    dict_f =  r'E:\X04_CTF\00TOOLS\07图片隐写及加解密\15cloacked-pixel-python3-master\47.104.108.33_ctf_10000.txt'
    with open(dict_f, 'r') as file: 
        keys = file.read().splitlines()
    img_lsb_mult_crack(s_data, keys, 'flag')

if __name__ == '__main__':
    t()
    


