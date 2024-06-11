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
from urllib.parse import unquote
from urllib.parse import unquote_plus
import gzip,io
#from Godzilla_test_data import *
from model.Godzilla_test_data import *
#from . import Godzilla_test_data   # 解决多层次导入的问题


gzl_q = queue.Queue()
gzl_sem = threading.Semaphore(40)  # 控制线程不超过40个
gzl_decryption_success = threading.Event()  # 设置进程间维护的统一标志

# NOTIC： 当前仅支持UTF-8模式



# 对gzip的数据进行解压缩
def decompress_gzip_data(compressed_data):
    compressed_stream = io.BytesIO(compressed_data)
    decompressed_data = ''
    try:  # 增加容错，其他函数最好判断一下是否是 空值
        with gzip.open(compressed_stream, mode='rb') as file:
            decompressed_data = file.read().decode('utf-8')
        return decompressed_data
    except Exception as e:
        print(f'尝试进行Gzip解压出错，出错信息：{e}')
        return None
    


# aes解密
def gzl_aes_dec(cipher, key):
    u_c = unquote(cipher)
    b_u_c = base64.b64decode(u_c)
    aes_dec = AES.new(key.encode(), AES.MODE_ECB)
    decrypted_bytes = aes_dec.decrypt(b_u_c)
    decrypted_text = unpad(decrypted_bytes, AES.block_size)
    return decrypted_text
    
    
# 传入是 str  通过SecretKey，计算对应 hash
def gzl_skey_hash(s):
    m = hashlib.md5()
    m.update(s.encode())
    # secertykey = str(m.hexdigest()[:16])
    return m.hexdigest()

# xor计算
def xor(l0, l1):
    ret = [chr(ord(chr(a)) ^ ord(chr(b))) for a,b in zip(l0,l1)]
    return "".join(ret)


# 公用函数， c类型为bytes， key为字符串  返回 bytearray, 当前兼容PHP_XOR_BASE64   和PHP_EVAL_XOR_BASE64
#  函数只使用 key 的前16位置
def gzl_xor_dec(c, key):
    result = bytearray()
    for i in range(len(c)):
        t = key[(i + 1) & 15]
        result.append( c[i] ^ ord(t) )
    return result
    
    
# 公用函数，对字节进行反序列化，然后格式化输出，需要输入bytes格式
def gzl_bytes_unserialize(data):
    assert isinstance(data, bytes)
    key = []
    rst = {}
    rst_fmt = ''
    i = 0
    try:  # 增加其他函数调用时的容错
        while i < len(data):
            # 读取key，直到读到2
            while data[i] != 2:
                key.append(data[i])
                i += 1
            # 跳过2
            i += 1
            # 读取四个字节，计算value的长度
            length_bytes = data[i:i+4]
            value_length = int.from_bytes(length_bytes, byteorder='little')
            i += 4
            # 读取value内容
            value = data[i : i+value_length]
            i += value_length
            # 将key和value存储到结果字典中
            rst[bytes(key).decode()] = value.decode()
            key.clear()
    except Exception as e:
        print(f'字节序列反序列化失败，错误信息{e}')
        return None
    print(f'获取到的反序列化明文为：{rst}')
    for key, value in rst.items():  #无需判断rst是否为空，这个循环自带容错
        rst_fmt += f"{key}={value};"
    return rst_fmt


#  公用函数，在解密基础上，增加反序列化和UnGzip的二次处理
# php_xor_base64 模式 已测试
# 输入值是 xor的返回值 ，返回值为 bytes 
def comm_php_xor_base64(data):
    uns_rst = gzl_bytes_unserialize( bytes(data) )
    print(f'反序列化格式化的结果是：{uns_rst}')
    rst = data if not uns_rst else uns_rst
    #print(f'rst： {rst}')
    ungzip = decompress_gzip_data(data)
    print(f'UNGzip的结果：{ungzip}')
    rst2 = rst if not ungzip else ungzip
    #print(f'rst2： {rst2}')
    return rst2
    


# =================== php_eval_xor_base64 ====================================================
# php_eval_xor_base64 模式的请求进行解码(当前已兼容3个连接测试和命令执行请求)，获取必要信息，有较多的硬编码
# 返回 连接密码  密钥 解密结果 请求执行的命令
def rqst_php_eval_xor_base64(rqst_str = rqst2_php_eval_xor_base64):
    params = rqst_str.split('&')
    params_dict = {}
    rst_dict = {}
    for param in params:
        key,value = param.split('=')
        params_dict[key] = value
    # 获取passwd和keymd的值
    print(params_dict)
    print(params_dict.keys())
    dict_iterator =iter(params_dict)
    paswd_k = next(dict_iterator)
    print(f'webshell连接密码可能是：{paswd_k}')
    paswd_v = params_dict.get(paswd_k, None)  # None为不存在时返回的默认值，增加容错
    key_k =  next(dict_iterator)
    key_v = params_dict.get(key_k, None)
    print(f'密钥可能是：{key_k}')
    if len(list(params_dict.keys())) > 2:
        print(f"可能还有其他疑似的连接密码或密钥")
    rst_dict['conn_pass'] = paswd_k
    rst_dict['secert_key'] = key_k
    
    rqdatas = unquote(paswd_v)
    rqd = rqdatas.split("'")[1]
    xord = base64.b64decode( unquote(rqd)[::-1] )  # base64字符串要反序
    #print(xord)
    print(xord.decode())  # 无需XOR计算，可以直接获取明文信息
    rst_dict['body'] = xord
    try:
        cmd = unquote(key_v)
        print(f'cmd 预处理结果：{cmd}')
        xcmd = base64.b64decode(unquote(cmd))
        skey_hash = gzl_skey_hash(key_k)[:16]
        print(f'skey_hash 是：{skey_hash}')
        rstxcmd = gzl_xor_dec(bytes(xcmd), skey_hash)  # xcmd强制转为bytes，增强兼容
        print(f'XOR解密结果：{rstxcmd}')
        
        rst_uns_cmd = gzl_bytes_unserialize(bytes(rstxcmd))  # 反序列化
        print(f'反序列化结果：{rst_uns_cmd}')
        
        rstxcmd2 = decompress_gzip_data( rstxcmd )  # 如果是命令执行模式，则无需反序列化，直接解压即可
        print(f'提取相关命令：{rstxcmd2}')
        
    except Exception as e:
        print(f'php_eval_xor_base64 模式尝试解密出错，错误信息：{e}')
    rst_cmd = rstxcmd2 if rst_uns_cmd == '' else rst_uns_cmd
    print(rst_cmd)
    rst_dict['cmd'] = rst_cmd
    return rst_dict


# php_eval_xor_base64 响应包的解密   测试3个连接响应都通过， 命令执行CMD1响应存在异常，已做兼容处理
# 当前直接传入 s_key_hash
# TODO：1、考虑和主程序 gzl_rsp_dec() 函数，通过已知的conn_pass，结合响应包中，计算的s_key_hash。
#  2、 CMD命令响应的相关文件写入
def rsp_php_eval_xor_base64(rsp, s_key_hash, conn_pass, ):
    #secertykey_hash = gzl_skey_hash( con_pass + secertykey)
    rst = ''
    b64_rsp = unquote(rsp)[16:-16]  # 后续考虑计算hash进行replace() ，担心base64字符串被替换，但似乎大小写可以区分
    print(b64_rsp)
    by_rsp = base64.b64decode(b64_rsp)
    unxor_rsp = gzl_xor_dec(bytes(by_rsp), s_key_hash)
    print(f'XOR 解密后的响应包： {unxor_rsp}')
    
    ungzip_rsp = decompress_gzip_data(unxor_rsp)
    print(f'UNGzip的结果：{ungzip_rsp}')
    
    if ungzip_rsp:
        rst = ungzip_rsp
    else:
        print('未解压缩成功，疑似bin文件。')
        rst = f'未解压缩成功，疑似bin文件。\n {bytes(unxor_rsp)} \n {bytes(unxor_rsp).hex() } '
    return rst


# =================== php_xor_base64 ====================================================
# php_xor_base64 模式请求1测试通过 ， 兼容 不带pass=的格式
def rqst_php_xor_base64_dec(rqst, key): 
    split_rqst = rqst.split('=')
    if len(split_rqst) > 1:  # 兼容不带pass= 关键字的格式，感觉没什么必要
        #conn_pass = split_rqst[0]  # 连接密码
        #rst['conn_pass'] = conn_pass
        #print(f'疑似连接密码是：{conn_pass}')
        c1 = unquote(split_rqst[1])
    else:
        c1 = unquote(rqst)
    md5_key = gzl_skey_hash(key)  # 无需 [:16] 截取，因为gzl_xor_dec 函数只用 md5_key 的前16位置
    xor_rst = gzl_xor_dec(base64.b64decode(c1),  md5_key)
    print(f'XOR解密结果是：{xor_rst}')
    rst = comm_php_xor_base64(bytes(xor_rst))
    return rst

#  php_xor_base64 模式， 响应包包测试通过
def rsp_php_xor_base64_dec(rsp, key):
    c1 = unquote(rsp)[16:-16]
    md5_key = gzl_skey_hash(key)
    xor_rst = gzl_xor_dec(base64.b64decode(c1),  md5_key)
    print(f'XOR解密结果是：{xor_rst}')
    rst = comm_php_xor_base64( xor_rst )
    return rst

# 爆破key 的函数 ，和aes的一致 ，TODO，考虑合并，做成公共函数
# 需要连接密码， 相应包和字典
def gzl_php_xor_base64_burpkey(rsp, con_pass, keys):
    #cipher = base64.b64decode(cipher)
    u_c = unquote(rsp)
    lp = u_c[:16]
    rp = u_c[-16:]
    hkey = (lp+rp).lower()
    print(f"根据响应包获取到的hash信息为：{hkey}")
    for key in keys:
        #print(key)
        secertykey = str(gzl_skey_hash(key) )[:16]
        secertykey_hash = gzl_skey_hash( con_pass+secertykey)
        if str(secertykey_hash) == hkey:
            print(f'找到正确的key： {key}， 响应包解密所需的SecureKey_hash为：{secertykey_hash}')
            return [key, secertykey_hash]


# =================== rsp_jsp_aes ====================================================
# 在通过请求包获取到 连接密码 con_pass 后，从响应包数据中，爆破获取 key，再获得secertykey
def jsp_aes_secretkey_brup_by_rsp(con_pass, rsp, keys):
    u_c = unquote(rsp)
    lp = u_c[:16]
    rp = u_c[-16:]
    hkey = (lp+rp).lower()
    print(f"根据响应包获取到的hash信息为：{hkey}")
    for key in keys:
        #print(key)
        #m = hashlib.md5()
        #m.update(key.encode('utf-8'))
        #secertykey = str(m.hexdigest()[:16])
        secertykey = str(gzl_skey_hash(key) )[:16]
        #print(secertykey)
        #m2 = hashlib.md5()
        #m2.update((con_pass+secertykey).encode('utf-8'))
        secertykey_hash = gzl_skey_hash( con_pass+secertykey)
        if str(secertykey_hash) == hkey:
            print(f'找到正确的key： {key}， 响应包解密所需的SecureKey_hash为：{secertykey_hash}')
            return [key, secertykey_hash]


# 服务器响应数据解密，先调用findStr函数删除服务器响应数据左右附加的混淆字符串（对于PHP_XOR_BASE64加密方式来说，前后各附加了16位的混淆字符），然后将得到的数据进行base64解码
# 11cd6a8758984163  fL1tMGI4YT1j0/79NDQm7r9PZzBi0A==  6c37ac826a2a04bc
def rsp_jsp_aes_base64_dec(rsp, key):
    #m = hashlib.md5()
    #m.update(key.encode('utf-8'))
    #md5_hash = m.hexdigest()
    #md5_key = md5_hash[:16]
    md5_key = gzl_skey_hash( key )[:16]
    u_c = unquote(rsp)
    #print(u_c) 
    lp = u_c[:16]
    rp = u_c[-16:]
    #print(lp, rp, '-------')
    b_u_c = base64.b64decode(u_c[16:-16])
    # print(b_u_c)
    aes_dec = AES.new(md5_key.encode(), AES.MODE_ECB)
    decrypted_bytes = aes_dec.decrypt(b_u_c)
    decrypted_text = unpad(decrypted_bytes, AES.block_size)
    rst = decompress_gzip_data(decrypted_text)  # ungzip
    rst = decrypted_text if rst == '' else rst
    print(rst)
    return rst

def rqst_jsp_aes_base64(rqst, key):
    c = rqst.split('=')[1]
    md5_key = gzl_skey_hash(key)[:16]
    aes_rst = gzl_aes_dec(c, md5_key)
    print(f'AES解密结果是：{aes_rst}')
    rst = comm_php_xor_base64( aes_rst )
    return rst

# JAVA_AES_BASE64 模式， 第1个请求，解密出来class文件，写入文件
def rqst1_jsp_aes_base64_dec(rqst1, key):
    c = rqst1.split('=')[1]
    #m = hashlib.md5()
    #m.update(key.encode('utf-8'))
    #md5_hash = m.hexdigest()
    #md5_key = md5_hash[:16]
    md5_key = gzl_skey_hash(key)[:16]
    rst = gzl_aes_dec(c, md5_key)
    # print(rst )   # class 字节码文件，打印没什么意义
    with open('./rqst1.class', 'wb') as cf:     
        cf.write(rst)
    print('解密完成，请查看当前目录下的 rqst1.class 文件，可以使用jadx工具反编译')
    #print(decompress_gzip_data(rst))  #示例数据无需ungzip
    #print(gzl_bytes_unserialize(rst))
    
# ===================== 遗留历史函数，待删除 =====================================



# 预留，
def gzl_crack_mutl_thread(cipher,keys):
    return 



if __name__ == "__main__":
    key = 'key'
    
    """      php_xor_base64 测试模块        """
    print( rqst_php_xor_base64_dec(rqst2_php_xor_base64, key) ) # 20240607二测通过 0608三测通过  0609 三测加命令测试通过
    #rsp_php_xor_base64_dec(rsp2_php_xor_base64, key)   # 0609 三测加命令测试通过
    
    
    """   php_eval_xor_base64 模式，请求测试    """
    #rqst_php_eval_xor_base64(rqst_cmd1_php_eval_xor_base64)  # 已测试通过，三测 3请求通过，CMD通过
    
    # php_eval_xor_base64 模式响应包测试
    #conn_pass = 'pass'
    #s_key_hash = '3c6e0b8a9c15224a'
    #t = rsp_php_eval_xor_base64(rsp_cmd2_php_eval_xor_base64, s_key_hash, conn_pass)  # 3个响应及CMD都通过， CMD1响应本体有异常
    #print(t)
    
    
    """      JSP AES 测试模块        """
    #rqst1_jsp_aes_base64_dec(rqst1_java_aes_base64, key)   # 已完成  20240607二测似乎还有问题 0609测试通过
    #rqst_jsp_aes_base64(rqst2_java_aes_base64, key)   # 0609请求2测试通过
    #rsp_jsp_aes_base64_dec(rsp_java_aes_base64, key)    # 已完成aes&gzip  20240607二测通过  0609测试通过
    
    
    # 通过响应包解密key  20240607二测通过
    """
    with open('../dict/pass.txt', 'r') as f: 
        keys = f.read().splitlines()  # 读取文件内容
    con_pass = 'pass'
    jsp_aes_secretkey_brup_by_rsp(con_pass, rsp, keys)
    """
    print('end')



