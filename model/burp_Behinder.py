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
    

def behinder(cipher, key, decq):
    if decryption_success.is_set():
        return
    sem.acquire()
    try:
        decrypted_text = decrypt_aes_ecb(cipher,key)
        print(f"尝试使用 {key} 进行解密，结果是 {decrypted_text}")
        #  注意根据可能的解密后的字符，修改该字符串
        if "status" in decrypted_text:
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



def crack_mutl_thread2(cipher, keys):
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
       t = threading.Thread(target=behinder, args=(cipher, key, decq))
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

    
def main():
    keys = read_key_from_file(r'./dict/pass.txt')
    cipher = 'FSO8QzpCSa+PeO2zIOqINAmhtGzoUXEZuhV6cz6HaqOiQUhNwN8TD19Ma9GnP00c3ltFGRoR4WWB/hcsayO3eHjDBREw4zbna4LHydab+CCJ9WlwVybtO/JxZFdLHaQTVjrX70YFxgdP7wiSUXDtl02U2dC7qKYAY5Ev9mgu0v5yhT4juqXTQdrWI9li3er7d4TFgyLUCyWa2tau8HsOT9nkPtn+8uUyXYBiK8wbUQa7ZYOzjFz2tBucaOpUVS8g4OaHqacBKhE2JCVrXYuiIpoHzKWlrDQ5ndCz+bPBpmfWTp3MZy6iGxunadb18+Wheb1s7V4T04BgZQh9uz+JY0GU8KOrhAQWLfiN8JRlYcCYL8RJPh3KwaONFaYZyRt1AONNb1qkFdUsDfjrTpJbBrL4O48M2M+C/US6StQxKYAHmg8rcV1Y97Y3S8GQ56mfLMmmjK0UbZwQmjrrX01ENAJ0CvCCDSsuDw5VCjUZY3uGemimqh5eHzP5xJB7CRXkPTTnpE8kHs2BAQmiUwwLPr9aZQrAYI3dit0YBJlzVoGeiYkq4smQ06FosNBIPOVuTd8FnHCYyaNq4JcsFice3VROLNUFRIZBdoCSC8D+i4BpdFIBayz08/t1vx7U9pDOfK+Xfcw1/x0SSpbtwkuwO5WadGWZ0gqtk/48i3DcbODaRI5ERMcHfV1BZvsVJj8Lqcn6xxSxEYo1kMz1FxRR/E/rsi0uHWYbQ3RjKTb6j2Uy2U0GVP9OQgNrNIBeFDD5GgLwM7c8IrqdWICvzNBPlYNvLoX5qqv0N/hCp5liH9OhVteDCA++gvRNRCbYqSAlD5pqFC2B8fpeipRu0h67urt9QD2iDXhrEwxQJ1ic2KOQCqPTV0qg/M0gdF9daIH1jXbGNQUxxi3KsICGdOCeoZJQm/LyIutRJW5B0xE8Whdlbr95eZVEoYbZrVcPoJop1RiVTkyY2XxMol6rzKCqSdrZUknUojuHN5MukbpbtoRZ0Y+ulcz1eAwz+AcZuVXTUqbxikcx1YmHJrPGmdIYhqaHkjUH4Rh2ySOHBEhXQaU4W0QELeCevv8fTFw04dtEtRP8YoX961EOWOvt1inpY4xGvfVgsAAuDwjJSTA/eeoMMK+mlw+Dmqn1TRoJUTOPWSgHR8TN3nWir18zw9/mFqV3IWDXl/oceuPjAc1HnqbULmu2O+vPjkACSalwc9HQnC4BF7YxvG2ox4+jSrXTctmRdv2H312SjiWI+u8EsD1YPzXISNLAVgGogY3huFhyCPn+gR6XKnWtokXS85YtZg=='
    rst = crack_mutl_thread2(cipher, keys)
    print(rst)  # behinder()函数有内置输出，可以省略此处的输出


if __name__ == "__main__":
    main()
    
    
    
    