#!/usr/bin/env python3
# coding=utf-8
# code by shuichon
# version 5.0


from Crypto.Cipher import ARC4
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Hash import MD5
import base64
import struct
import argparse
import itertools
import string
import queue
import threading
import time

q = queue.Queue()
sem = threading.Semaphore(40)  # 控制线程不超过40个
runtime = time.strftime("%Y_%m_%d_%H_%M_%S", time.localtime())
decryption_success = threading.Event()  # 设置进程间维护的统一标志

def rc4_encrypt(data, password):
    salt = get_random_bytes(8)
    key = PBKDF2(password, salt, dkLen=16)  # 密钥长度16字节
    cipher = ARC4.new(key)
    ciphertext = cipher.encrypt(data.encode('utf-8'))
    return base64.b64encode(b"Salted__" + salt + ciphertext).decode('utf-8')

def rc4_decrypt(encrypted_data, password):  #备用
    data = base64.b64decode(encrypted_data)
    assert data[:8] == b"Salted__"
    salt = data[8:16]
    ciphertext = data[16:]
    key = PBKDF2(password, salt, dkLen=16)
    cipher = ARC4.new(key)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext
    #return plaintext.decode('utf-8')


def decrypt_by_EvpKDF(data, passwd):
    assert data[:10] == 'U2FsdGVkX1'  # 添加校验信息
    db = base64.b64decode(data)
    pb = passwd.encode()
    assert db[:8] == b"Salted__"
    saltb = db[8:16]
    k01 = MD5.new(pb + saltb).digest()
    k02 = MD5.new(k01 + pb + saltb).digest()
    kb = k01 + k02
    drpt = ARC4.new(kb)
    return drpt.decrypt(db[16:])

def read_key_from_file(key_path):
    with open(key_path, 'r') as key_file:
        keys = key_file.read().splitlines()
    return keys

def generate_num_combinations(length):
    # 使用 itertools.product 生成所有可能的数字组合
    num_combs = itertools.product(string.digits, repeat=length)
    # 将组合转换为字符串
    return num_combs
    
    
def generate_mix_combinations(length):
    # 使用 itertools.product 生成所有可能的数字和大小写字母组合
    mix_combs = itertools.product(string.digits+string.ascii_letters, repeat=length)
    # 将组合转换为字符串
    return mix_combs


def rc4_crack_mutl_thread(cipher, keys):
    start_time = time.time()
    # queue for keys
    q = queue.Queue()
    decq = queue.Queue()
    threads = []
    for key in keys:
        q.put(key)
    while not q.empty():
        if decryption_success.is_set():
            break
        key = q.get(False) #如果队列为空，False 参数会使 q.get() 立即抛出 queue.Empty 异常，而不是阻塞等待。
        t = threading.Thread(target=rc4_crack, args=(cipher, key,decq, ))
        t.setDaemon(True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    print('检测全部完成, 按Enter键退出！用时：{}'.format(time.time() - start_time))
    if not decq.empty():
        return decq.get()
    
    
    
def rc4_crack(cipher, key, decq):
    if decryption_success.is_set():
        return
    sem.acquire()
    try:
        key = ''.join(key)
        print(key)
        # decrypted_text = rc4_decrypt(cipher, key)
        decrypted_text = decrypt_by_EvpKDF(cipher,key)
        print(f"尝试使用 {key} 进行解密，结果是 {decrypted_text}")
        #  注意根据可能的解密后的字符，修改该字符串
        if "flag" in decrypted_text.decode():
            decryption_success.set()  # 设置停止标志
            print("解密成功.")
            decq.put(decrypted_text)
            return decrypted_text
    except Exception as e:
        print(f"解密失败 {key} failed: {str(e)}")
    if not decryption_success.is_set():
        print("所有key已尝试，解密失败.")
    sem.release()
    return None


def main():
    parser = argparse.ArgumentParser(description="用于破解加盐类型的RC4密文")
    parser.add_argument("-cipher", type=str, metavar="密文", help="输入要尝试解密的密文")
    parser.add_argument("-kf", type=str, metavar="密钥字典文件名", help="从指定字典文件获取key列表")
    parser.add_argument("-kln", type=int, help="生成指定长度的纯数字key列表，建议不要超过6位")
    parser.add_argument("-klm", type=int, help="生成指定长度的key列表(数字加大小写字母混合），建议不要超过4位")
    
    args = parser.parse_args()
    cipher = args.cipher
    
    if not any([hasattr(args, 'kf'), hasattr(args, 'kln'), hasattr(args, 'klm')]):
        parser.error("必须提供至少一个参数: --key-file, --key-list-name, --key-list-method")
    if args.kf:
        keys = read_key_from_file(args.kf)
        crack(cipher, keys)
    if args.kln is not None:
        print(f"生成指定长度{args.kln}的纯数字的key列表：")
        keys = generate_num_combinations(args.kln)
        crack(cipher, keys)
    if args.klm is not None:
        print(f"生成指定长度{args.kln}的key列表(数字加大小写字母混合）：")
        keys = generate_mix_combinations(args.klm)
        crack(cipher, keys)
    
if __name__ == "__main__":
    main()
    