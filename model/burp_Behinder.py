#! /usr/bin/env python
#--coding=utf-8--
#environ: python3
#--coding by shuichon--
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64
import hashlib
import queue
import threading
import time 




q = queue.Queue()
sem = threading.Semaphore(40)  # 控制线程不超过40个
runtime = time.strftime("%Y_%m_%d_%H_%M_%S", time.localtime())
decryption_success = threading.Event()  # 设置进程间维护的统一标志


def decrypt_aes_ecb(ciphertext, key):
    cipher = AES.new(key.encode(), AES.MODE_ECB)
    decrypted_bytes = cipher.decrypt(base64.b64decode(ciphertext))
    decrypted_text = unpad(decrypted_bytes, AES.block_size).decode('utf-8')
    return decrypted_text
    

def bh_aes_dec(cipher, key, decq, grep):
    grep = 'status' if grep =='' else grep
    if decryption_success.is_set():
        return
    sem.acquire()
    try:
        decrypted_text = decrypt_aes_ecb(cipher,key)
        print(f"尝试使用 {key} 进行解密，结果是 {decrypted_text}")
        #  注意根据可能的解密后的字符，修改该字符串
        if grep in decrypted_text:
            decryption_success.set() 
            print("解密成功.")
            decq.put(decrypted_text)
            return decrypted_text
    except Exception as e:
        print(f"解密失败 {key} failed: {str(e)}")
    if not decryption_success.is_set():
        print("所有key已尝试，解密失败.")
    sem.release()
    return None



def crack_mutl_thread2(cipher, keys, grep):
    start_time = time.time()
    q = queue.Queue()
    decq = queue.Queue()
    threads = []
    for key in keys:
       m = hashlib.md5()
       m.update(key.encode('utf-8'))
       md5_hash = m.hexdigest()
       md5_key = md5_hash[:16]
       q.put(md5_key)
    while not q.empty():
       if decryption_success.is_set():
           break
       key = q.get(False) 
       t = threading.Thread(target=bh_aes_dec, args=(cipher, key, decq, grep,))
       t.setDaemon(True)
       t.start()
       threads.append(t)
    for t in threads:
       t.join()
    print('检测全部完成, 按Enter键退出！用时：{}'.format(time.time() - start_time))
    if not decq.empty():
        return decq.get()
    

def read_key_from_file(key_path):
    with open(key_path, 'r') as key_file:
        keys = key_file.read().splitlines()
    return keys


# XOR模式的解密
# ref:https://liriu.life/liriu/PHP-5ba36eb0362743ed8fa5588c97325f7e
phrases = ["assert|eval(base64_decode('".encode(),
        b'<?\n@error_reporting(0);\n\nfunctio',
        b'<?\nfunction main($action, $remot',
        b'<?\n@error_reporting(0);\nset_time',
        b'\nerror_reporting(0);\n\nfunction m',
        b'<?\n@error_reporting(0);\n\n\nfuncti',
        b'<?\nerror_reporting(0);\nfunction ',
        b'@error_reporting(0);\nfunction ma',
        b'<?php\n\n$taskResult = array();\n$p',
        b"<?\nerror_reporting(0);\nheader('C",
        b'@error_reporting(0);\n\nfunction g',
        b'<?\n@error_reporting(0);\n@set_tim']
        
        
def xor(l0, l1):
    ret = [chr(ord(chr(a)) ^ ord(chr(b))) for a,b in zip(l0,l1)]
    return "".join(ret)
        

# 注意，要传入的 cipher_b 是bytes格式
def bh_xor_dec(cipher_b, key):
    # 将密钥转换为字节串，并确保其长度与密文相同
    key_bytes = (key.encode() * (len(cipher_b) // len(key) + 1))[:len(cipher_b)]
    xor_result = bytes([a ^ b for a, b in zip(cipher_b, key_bytes)])
    return xor_result.decode()


# cipher 为base64解码后的字节bytes，方便兼容
def bh_xor_check_key(cipher):
    #cipher = base64.b64decode(cipher)
    for phrase in phrases:
        p0 = phrase[0:16]
        p1 = phrase[16:]
        
        c0 = cipher[0:16]
        c1 = cipher[16:16+len(p1)]

        k0 = xor(p0, c0)
        k1 = xor(p1, c1)
        #print(k0, k1)
        if k1 in k0:
            return k0
    return None



def aes_useage():
    keys = read_key_from_file(r'./dict/pass.txt')
    aes_cipher = 'FSO8QzpCSa+PeO2zIOqINAmhtGzoUXEZuhV6cz6HaqOiQUhNwN8TD19Ma9GnP00c3ltFGRoR4WWB/hcsayO3eHjDBREw4zbna4LHydab+CCJ9WlwVybtO/JxZFdLHaQTVjrX70YFxgdP7wiSUXDtl02U2dC7qKYAY5Ev9mgu0v5yhT4juqXTQdrWI9li3er7d4TFgyLUCyWa2tau8HsOT9nkPtn+8uUyXYBiK8wbUQa7ZYOzjFz2tBucaOpUVS8g4OaHqacBKhE2JCVrXYuiIpoHzKWlrDQ5ndCz+bPBpmfWTp3MZy6iGxunadb18+Wheb1s7V4T04BgZQh9uz+JY0GU8KOrhAQWLfiN8JRlYcCYL8RJPh3KwaONFaYZyRt1AONNb1qkFdUsDfjrTpJbBrL4O48M2M+C/US6StQxKYAHmg8rcV1Y97Y3S8GQ56mfLMmmjK0UbZwQmjrrX01ENAJ0CvCCDSsuDw5VCjUZY3uGemimqh5eHzP5xJB7CRXkPTTnpE8kHs2BAQmiUwwLPr9aZQrAYI3dit0YBJlzVoGeiYkq4smQ06FosNBIPOVuTd8FnHCYyaNq4JcsFice3VROLNUFRIZBdoCSC8D+i4BpdFIBayz08/t1vx7U9pDOfK+Xfcw1/x0SSpbtwkuwO5WadGWZ0gqtk/48i3DcbODaRI5ERMcHfV1BZvsVJj8Lqcn6xxSxEYo1kMz1FxRR/E/rsi0uHWYbQ3RjKTb6j2Uy2U0GVP9OQgNrNIBeFDD5GgLwM7c8IrqdWICvzNBPlYNvLoX5qqv0N/hCp5liH9OhVteDCA++gvRNRCbYqSAlD5pqFC2B8fpeipRu0h67urt9QD2iDXhrEwxQJ1ic2KOQCqPTV0qg/M0gdF9daIH1jXbGNQUxxi3KsICGdOCeoZJQm/LyIutRJW5B0xE8Whdlbr95eZVEoYbZrVcPoJop1RiVTkyY2XxMol6rzKCqSdrZUknUojuHN5MukbpbtoRZ0Y+ulcz1eAwz+AcZuVXTUqbxikcx1YmHJrPGmdIYhqaHkjUH4Rh2ySOHBEhXQaU4W0QELeCevv8fTFw04dtEtRP8YoX961EOWOvt1inpY4xGvfVgsAAuDwjJSTA/eeoMMK+mlw+Dmqn1TRoJUTOPWSgHR8TN3nWir18zw9/mFqV3IWDXl/oceuPjAc1HnqbULmu2O+vPjkACSalwc9HQnC4BF7YxvG2ox4+jSrXTctmRdv2H312SjiWI+u8EsD1YPzXISNLAVgGogY3huFhyCPn+gR6XKnWtokXS85YtZg=='
    rst = crack_mutl_thread2(aes_cipher, keys)
    print(rst)  # behinder()函数有内置输出，可以省略此处的输出
    
    
def xor_useage():
    xor_cipher = "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"
    cipher_b = base64.b64decode(xor_cipher)
    key = bh_xor_check_key(cipher_b)
    print(key)
    if key:
        print("[+]", xor_cipher[:32], "is XOR Behinder Request!")
        print("[+] The Key of Behinder is ", key)
    else:
        print("[-]", xor_cipher[:32], "not Behinder Request..")
    # 验证开头的一组密文
    print(xor(key.encode(), cipher_b[:16]))
    # 全部解密
    print(bh_xor_dec(cipher_b, key) )
    
    
def main():
    xor_useage()
    

if __name__ == "__main__":
    main()
    
    
    
    