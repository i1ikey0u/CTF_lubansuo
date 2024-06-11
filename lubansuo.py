#! /usr/bin/env python
#--coding=utf-8--
#environ: python3
#--coding by shuichon--

import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from tkinter import scrolledtext
import base64
from tkinter import filedialog
from model.burp_RC4_Salt import *
from model.burp_Behinder import *
from model.burp_Godzilla import *
from model.LSB_AES_cloacked_pixe import *


root = tk.Tk()
root.wm_iconbitmap(r'3.ico')
root.title("CTF鲁班锁  https://github.com/i1ikey0u/CTF_lubansuo/")
root.geometry("800x600")
root.minsize(400, 300)


#   字典信息相关函数合并，多标签公用
keys = []
def open_dict_f_v2(entry_widget):
    filepath = filedialog.askopenfilename()  # 弹出文件选择对话框
    if filepath:  # 如果用户选择了文件
        try:
            with open(filepath, 'r') as file: 
                global keys  # 声明使用全局的keys
                keys = file.read().splitlines()  # 读取文件内容
                msg = f"文件读取成功！字典数量 {len(keys)}"
        except Exception as e:
            msg = (f"读取文件时发生错误：{e}")
        entry_widget.insert(tk.END, msg)
      


tabControl = ttk.Notebook(root)
tabControl.pack(fill=tk.BOTH, expand=True)

tab1 = ttk.Frame(tabControl)
tabControl.add(tab1, text='Base64解码及隐写')

# 第二个选项卡
tab2 = ttk.Frame(tabControl)
tabControl.add(tab2, text='RC4(Salt)解密')

# 第三个选项卡
tab3 = ttk.Frame(tabControl)
tabControl.add(tab3, text='冰蝎Webshell流量解密')

tab4 = ttk.Frame(tabControl)
tabControl.add(tab4, text='哥斯拉Godzilla流量解密')

tab5 = ttk.Frame(tabControl)
tabControl.add(tab5, text='LSB_(AES)_cloacked-pixel')


# tab1 base64 按钮功能实现
def Base64_DecBut_action():
    user_input = Enc_input.get('1.0', tk.END).strip()
    Dec_text_output.delete("1.0", tk.END)
    decode = ''
    try:
        if chck_mul_line.get() == 1:
            for l in user_input.splitlines() :
               dec = base64.b64decode(l).decode() +'\n'
               decode += dec
        else:
            decode = base64.b64decode(user_input)
    except Exception as e:
        messagebox.showinfo("提示", {e})
    Dec_text_output.insert(tk.END, decode)

def ClsBut_action():
    b64_Enc.delete('1.0', tk.END)
    
def MiscDecBut_action():
    user_input = b64_Enc.get('1.0', tk.END).strip()
    Dec_text_output.delete("1.0", tk.END)
    bit2_text_output.delete("1.0", tk.END)
    R2toA_output.delete("1.0", tk.END)
    decode = ''
    bin_str = ''
    try:
        for l in user_input.splitlines() :
            steg_l = l.replace('\n', '')  # 似乎可以优化
            dec = base64.b64decode(l).decode() +'\n'
            decode += dec
            norm_l = base64.b64encode(base64.b64decode(steg_l)).decode()
            #print(steg_l, norm_l)
            diff = get_base64_diff_value(steg_l, norm_l)
            #print(diff)
            pads_num = steg_l.count('=')
            if diff:
                bin_str += bin(diff)[2:].zfill(pads_num * 2)
            else:
                bin_str += '0' * pads_num * 2
        Dec_text_output.insert(tk.END, decode)
        bit2_text_output.insert(tk.END, bin_str)
        flag = B2toa(bin_str)
        R2toA_output.insert(tk.END, flag)
    except Exception as e:
        messagebox.showinfo("提示", {e})
    messagebox.showinfo('提示', '执行完毕！')

def get_base64_diff_value(s1, s2):
    base64chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    res = 0
    for i in range(len(s2)):
        if s1[i] != s2[i]:
            return abs(base64chars.index(s1[i]) - base64chars.index(s2[i]))
    return res
    
    
def B2toa(x):
    i = 0
    flag = ''
    while i < len(x):
        if int(x[i:i+8],2):
            flag += chr(int(x[i:i+8],2))
        i += 8
    return(flag)
    

# 可以在一个应用程序中混用 grid 和 pack 布局管理器，但不能在同一个容器（1个 Frame）中同时用 grid 和 pack。
tab1.grid_columnconfigure(0, weight=1) # 权重为1，使其自动扩展。
tab1.grid_columnconfigure(1, weight=0)  # 分割线所在列，权重为0，不让其扩展。
tab1.grid_columnconfigure(2, weight=1) # 权重为1，使其自动扩展。
tab1.grid_rowconfigure(0, weight=1)

left_frame = ttk.Frame(tab1)
left_frame.grid(row=0, column=0, sticky="nsew")

separator = tk.Frame(tab1, width=1, bg="gray")
separator.grid(row=0, column=1, sticky="ns")  # ns 在垂直方向上扩展

right_frame = ttk.Frame(tab1)
right_frame.grid(row=0, column=2, sticky="nsew")

# base64左侧
b64_Enc_l = ttk.Label(left_frame, text="请输入Base64编码的字符串:")
b64_Enc_l.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)

b64_Enc = tk.Text(left_frame, wrap='word',)
b64_Enc.insert(tk.END, "请输入Base64编码的字符串:")
b64_Enc.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=8, pady=10)

# 绑定事件，特定事件
def clear_default(event):
        default_text = "请输入Base64编码的字符串:"
        if b64_Enc.get("1.0", tk.END).startswith(default_text): # 检查是否只包含默认文本
            b64_Enc.delete("1.0", tk.END)
# 绑定左键点击事件到清空默认文本的功能
b64_Enc.bind("<Button-1>", clear_default)

#  base64右半侧
DecFrame = tk.Frame(right_frame)
DecFrame.pack(side=tk.TOP, fill=tk.X, padx=8, pady=5)

# 复选框(暂时无作用，仅作调试使用)
"""
def on_checkbox_change():
    #当复选框状态改变时调用的回调函数
    return
    if chck_mul_line.get() == 1:
        print("复选框被选中")
    else:
        print("复选框未被选中")
"""


chck_mul_line = tk.IntVar()  # 设定全局变量，无需 command=on_checkbox_change
chck_mul_line_btn = ttk.Checkbutton(DecFrame, text="按行解码", variable=chck_mul_line)
chck_mul_line_btn.pack(side=tk.LEFT, expand=1, padx=5, pady=5)  


# 常规解码（TODO：1.末尾等号异常的处理，2.字符串是否是base64的判断）
DecBut = ttk.Button(DecFrame, text="Base64解码", command=Base64_DecBut_action)
DecBut.pack(side=tk.LEFT, expand=1, padx=5, pady=5)


DecButMisc = ttk.Button(DecFrame, text="Base64隐写解密", command=MiscDecBut_action)
DecButMisc.pack(side=tk.LEFT, fill=tk.X, padx=5, pady=5)

# 结果展示
Dec_output_label = ttk.Label(right_frame, text="解码结果:")
Dec_output_label.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)
Dec_text_output = tk.Text(right_frame, wrap='word', height=10)
Dec_text_output.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=5, pady=5)


bit2_output_label = ttk.Label(right_frame, text="隐写解密结果（二进制）:")
bit2_output_label.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)
bit2_text_output = tk.Text(right_frame, wrap='word', height=10)
bit2_text_output.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=5, pady=5)

R2toA = ttk.Label(right_frame, text="二进制转Ascii:")
R2toA.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)
R2toA_output = tk.Text(right_frame, wrap='word', height=10)
R2toA_output.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=5, pady=10)
# base64 end


# tab2 RC4(Salt)加解密  start
tab2.grid_columnconfigure(0, weight=1) # 权重为1，使其自动扩展。
tab2.grid_columnconfigure(1, weight=0)  # 分割线所在列，权重为0，不让其扩展。
tab2.grid_columnconfigure(2, weight=1) # 权重为1，使其自动扩展。
tab2.grid_rowconfigure(0, weight=1)

left_frame2 = ttk.Frame(tab2)
left_frame2.grid(row=0, column=0, sticky="nsew")

separator2 = tk.Frame(tab2, width=1, bg="gray")
separator2.grid(row=0, column=1, sticky="ns")  # ns 在垂直方向上扩展

right_frame2 = ttk.Frame(tab2)
right_frame2.grid(row=0, column=2, sticky="nsew")

# 左侧
RC4_Enc_input_l = ttk.Label(left_frame2, text="请输入RC4密文:")
RC4_Enc_input_l.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)

RC4_Enc_input = tk.Text(left_frame2, wrap='word',)
# RC4_Enc_input.Label(left_frame, text="请输入Base64编码的字符串:")
#RC4_Enc_input.insert(tk.END, "请输入使用Open SSL风格的RC4密文，一般以'U2FsdGVkX1……'开头:")
RC4_Enc_input.insert(tk.END, "U2FsdGVkX196pWxlPoR49+G/eJXJcKqLOruhqNiHzQ==")
RC4_Enc_input.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=8, pady=10)

# 绑定事件
def clear_default2(event):
        default_text = "请输入使用Open SSL风格的RC4密文，一般以'U2FsdGVkX1……'开头:"
        if RC4_Enc_input.get("1.0", tk.END).startswith(default_text): # 检查是否只包含默认文本
            RC4_Enc_input.delete("1.0", tk.END)
# 绑定左键点击事件到清空默认文本的功能
RC4_Enc_input.bind("<Button-1>", clear_default2)

#  RC4右半侧
RC4_DecFrame = tk.Frame(right_frame2)
RC4_DecFrame.pack(side=tk.TOP, fill=tk.X, padx=8, pady=5)

# RC4相关控件函数

# RC4破解结果
def rc4_dec():
    cipher = RC4_Enc_input.get('1.0', tk.END).strip()
    if keys:
        rst = rc4_crack_mutl_thread(cipher, keys)
    RC4_Dec_input.delete("1.0", tk.END)
    RC4_Dec_input.insert(tk.END, rst.decode())
    messagebox.showinfo("提示", "解密完毕！")


get_dict_f = tk.StringVar()
get_dict_f = ttk.Button(right_frame2, text="选择字典",  command=lambda:open_dict_f_v2(dict_input))
get_dict_f.pack(side=tk.TOP,  anchor=tk.NW, padx=5, pady=5)  

# 字典选择信息展示
dict_input = tk.Entry(right_frame2)
dict_input.pack(side=tk.TOP, fill = tk.X, anchor=tk.NW,  padx=8, pady=10)


# 解密结果展示
RC4_R_Frame3 = tk.Frame(right_frame2)
RC4_R_Frame3.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)


# get_dict_f = tk.StringVar()  command属性期望接收一个无参数的函数调用。如果你直接写成command=rc4_dec(some_cipher_variable)，那么在界面创建时就会立即执行rc4_dec函数，而不是在按钮被点击时。
burp_rc4 = ttk.Button(RC4_R_Frame3, text="解密!!!",  command=lambda: rc4_dec())
burp_rc4.pack(side=tk.TOP, anchor=tk.NW,  padx=5, pady=5)  

rc4_rst_l = tk.Label(RC4_R_Frame3, text="解密结果：")
rc4_rst_l.pack(side=tk.TOP, anchor=tk.NW,  padx=8, pady=10)

RC4_Dec_input = tk.Text(RC4_R_Frame3, wrap='word',)
RC4_Dec_input.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=8, pady=10)



"""
# 内置字典规则设定
RC4_R_Frame2 = tk.Frame(right_frame2)
RC4_R_Frame2.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)

dict_list_l = tk.Label(RC4_R_Frame2, text="使用内置字典规则")
dict_list_l.pack(side=tk.TOP, anchor=tk.NW, padx=8, pady=10)

chck_num = tk.IntVar()
chck_num = ttk.Checkbutton(RC4_R_Frame2, text="数字", variable=chck_mul_line, command=on_checkbox_change)
chck_num.pack(side=tk.LEFT, padx=5, pady=5)  # 使用pack布局管理器添加复选框到窗口

chck_alp = tk.IntVar()
chck_alp = ttk.Checkbutton(RC4_R_Frame2, text="字母", variable=chck_mul_line, command=on_checkbox_change)
chck_alp.pack(side=tk.LEFT, padx=5, pady=5)  # 使用pack布局管理器添加复选框到窗口
"""

#  冰蝎流量解密
tab3.grid_columnconfigure(0, weight=1) # 权重为1，使其自动扩展。
tab3.grid_columnconfigure(1, weight=0)  # 分割线所在列，权重为0，不让其扩展。
tab3.grid_columnconfigure(2, weight=1) # 权重为1，使其自动扩展。
tab3.grid_rowconfigure(0, weight=1)

left_frame3 = ttk.Frame(tab3)
left_frame3.grid(row=0, column=0, sticky="nsew")

separator3 = tk.Frame(tab3, width=1, bg="gray")
separator3.grid(row=0, column=1, sticky="ns")  # ns 在垂直方向上扩展

right_frame3 = ttk.Frame(tab3)
right_frame3.grid(row=0, column=2, sticky="nsew")

# tabl3 左侧
Behinder_Enc_input_l = ttk.Label(left_frame3, text="请输入冰蝎加密流量:")
Behinder_Enc_input_l.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)

Behinder_Enc_input = tk.Text(left_frame3, wrap='word',)
Behinder_Enc_input.insert(tk.END, "请输入提取到的冰蝎加密流量，一般是base64编码")
Behinder_Enc_input.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=8, pady=10)

# 绑定事件
def clear_default3(event):
        default_text = "请输入提取到的冰蝎加密流量，一般是base64编码"
        if Behinder_Enc_input.get("1.0", tk.END).startswith(default_text): # 检查是否只包含默认文本
            Behinder_Enc_input.delete("1.0", tk.END)
# 绑定左键点击事件到清空默认文本的功能
Behinder_Enc_input.bind("<Button-1>", clear_default3)



# 后续考虑是不是要合并
def Behinder_dec():
    cipher = Behinder_Enc_input.get('1.0', tk.END).strip()
    if not cipher:
        messagebox.showinfo("提示", "请输入要解密的密文")
        return
    rst = ''
    grep = behinder_grep_entry.get()
    model = behingder_model_opt.get()
    # preg = 'status' if preg =='' else preg # 设置默认值
    print(behingder_model_opt.get())
    if model == opts[0]:
        if keys:
           rst = crack_mutl_thread2(cipher, keys, grep)
        else:
            messagebox.showinfo("提示", "未选择字典文件")
    elif model == opts[1]:
        key_h = bh_xor_check_key(cipher)
        key_a = bytes.fromhex(key_h)
        rst = f'疑似 XOR 使用的密钥是： {key_h}，转为Ascii为{key_a}'
        rst += '\r\n===========================================\r\n'
        rst += bh_xor_dec(cipher_b, key_h)
    elif model == opts[2]:
        cipher_b = base64.b64decode(cipher)
        key_h = bh_xor_check_key(cipher_b)
        key_a = bytes.fromhex(key_h)
        rst = f'疑似 XOR 使用的密钥是： {key_h}，转为Ascii为{key_a}'
        rst += '\r\n===========================================\r\n'
        rst += bh_xor_dec(cipher_b, key_h)
    else:
        messagebox.showinfo("提示", "正在开发中……")
    Behinder_Dec_input.delete("1.0", tk.END)
    Behinder_Dec_input.insert(tk.END, rst)
    messagebox.showinfo("提示", "解密完毕！")

def behingder_model_opt_sltd(event):
    model = behingder_model_opt.get()
    if model in [opts[1], opts[2]]:
        messagebox.showinfo("提示", "XOR相关模式无需设置字典及要匹配的关键字")
        get_dict_f2.config(state="disabled")
        behinder_grep_entry.config(state="disabled")
    else:
        get_dict_f2.config(state="normal")
        behinder_grep_entry.config(state="normal")
    print(f"你选择了: {model}")
    

# 冰蝎解密 右侧布局

# 冰蝎加密模式选择
behinder_model_frame = ttk.Frame(right_frame3)
behinder_model_frame.grid(row=0, sticky="nsew")


behingder_model_l = tk.Label(behinder_model_frame, text="选择加密模式：")
behingder_model_l.pack(side=tk.LEFT, anchor=tk.NW,  padx=5, pady=5)
opts = ["AES加密模式", "XOR模式", "XOR_BASE64", "AES&Imagic(暂未实现)"]
behingder_model_opt = tk.StringVar() # 设置一个变量，结合textvariable指定，直接全局使用
behingder_model_cbx = ttk.Combobox(behinder_model_frame, values=opts,  textvariable=behingder_model_opt,  state='readonly') # 设置state，不可修改
behingder_model_cbx.pack(side=tk.TOP,  fill = tk.X, anchor=tk.NW,  padx=5, pady=10) 
behingder_model_cbx.set(opts[0])  # 可选：设置默认值
behingder_model_cbx.bind("<<ComboboxSelected>>", behingder_model_opt_sltd)



# 测试函数
"""
def is_base64_code(s):
    '''Check s is Base64.b64encode'''
    if not isinstance(s, str) or not s:
        return "params s not string or None"

    _base64_code = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I',
                    'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R',
                    'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a',
                    'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
                    'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
                    't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1',
                    '2', '3', '4', '5', '6', '7', '8', '9', '+',
                    '/', '=']
    _base64_code_set = set(_base64_code)  # 转为set增加in判断时候的效率
    # Check base64 OR codeCheck % 4
    code_fail = [i for i in s if i not in _base64_code_set]
    if code_fail or len(s) % 4 != 0:
        return False
    return True

# optionMeua 空间模式，样式不太直观
behingder_model_opt.set(options[0])  # 设置默认值
behingder_model_optM = tk.OptionMenu(behinder_model_frame, behingder_model_opt, *options, command=behingder_model_opt_slectd)  
behingder_model_optM.pack(side=tk.LEFT,  fill = tk.X, anchor=tk.NW,  padx=5, pady=5) 
"""


# 字典设置
behinder_dict_frame = ttk.Frame(right_frame3)
behinder_dict_frame.grid(row=1, sticky="nsew")

get_dict_f2 = tk.StringVar()
get_dict_f2 = ttk.Button(behinder_dict_frame, text="选择字典",  command=lambda: open_dict_f_v2( dict_input2 ))
get_dict_f2.pack(side=tk.LEFT,  anchor=tk.NW, padx=5, pady=5)  

# 字典选择信息
dict_input2 = tk.Entry(behinder_dict_frame)
dict_input2.pack(side=tk.TOP, fill = tk.X, anchor=tk.NW,  padx=8, pady=10)


# TODO  关键字匹配
behinder_grep_frame = ttk.Frame(right_frame3)
behinder_grep_frame.grid(row=3, sticky="nsew")

behinder_grep_l = tk.Label(behinder_grep_frame, text="可能的关键字：")
behinder_grep_l.pack(side=tk.LEFT, anchor=tk.NW,  padx=5, pady=5)

behinder_grep_entry = tk.Entry(behinder_grep_frame)
behinder_grep_entry.pack(side=tk.LEFT, anchor=tk.NW,  padx=5, pady=5)
behinder_grep_entry.insert(0, "status")

burp_Behinder_btn = ttk.Button(behinder_grep_frame, text="尝试解密",  command=lambda: Behinder_dec())
burp_Behinder_btn.pack(side=tk.LEFT, anchor=tk.NW,  padx=5, pady=5)  


# 结果展示
behinder_dec_frame = ttk.Frame(right_frame3)
behinder_dec_frame.grid(row=4, sticky="nsew")

behinder_rst_l = tk.Label(behinder_dec_frame, text="解密结果：")
behinder_rst_l.pack(side=tk.TOP, anchor=tk.NW,  padx=8, pady=10)

Behinder_Dec_input = tk.Text(behinder_dec_frame, wrap='word')
Behinder_Dec_input.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=5, pady=10)
#  end



# LSB AES 隐写 cloacked-pixel模式  start

def reda_img_file():
    filepath = filedialog.askopenfilename()  # 弹出文件选择对话框
    if filepath:  # 如果用户选择了文件
        #msg = ''
        try:
            with open(filepath, 'r') as file: 
                msg = f"图片读取成功！图片位置： {filepath}"
        except Exception as e:
            msg = (f"读取文件时发生错误：{e}")
            messagebox.showinfo("提示", msg)
        img_path_in.delete('0', tk.END)
        img_path_in.insert(tk.END, msg)


def img_lsb_dec():
    if img_path_in.get() == "":
        messagebox.showinfo("提示", "请选择图片！")
        return 
    if img_pass_entry.get() == "":
        messagebox.showinfo("提示", "请输入密码，或者使用字典爆破密码！")
        return
    else:
        key = img_pass_entry.get()
        cipher = AESCipher(key)
        img_data = steg_data(img_path_in.get().replace('图片读取成功！图片位置： ', ''))
        data_dec = cipher.decrypt(img_data)
        img_lsb_Dec_out.delete('1.0', tk.END)
        img_lsb_Dec_out.insert(tk.END, data_dec)
        messagebox.showinfo("提示", "提取完毕！")

def img_lsb_crack():
     info = info_entry.get()
     img_path = img_path_in.get().replace('图片读取成功！图片位置： ', '')
     if info == "":
        messagebox.showinfo("提示", "请设置爆破时匹配的关键字")
        return 
     if img_path == "":
        messagebox.showinfo("提示", "请选择图片！")
        return 
     else:
        img_data = steg_data(img_path)
        passwd = img_lsb_mult_crack(img_data, keys, info)
        img_pass_entry.delete('0', tk.END)
        img_pass_entry.insert(tk.END, passwd)
        messagebox.showinfo("提示", "密码破解尝试结束！")
        # 增加内容的提取
        cipher = AESCipher(passwd)
        data_dec = cipher.decrypt(img_data)
        img_lsb_Dec_out.delete('1.0', tk.END)
        img_lsb_Dec_out.insert(tk.END, data_dec)


img_frame = ttk.Frame(tab5)
img_frame.grid(row=0, sticky="nsew")

img_path_btn = ttk.Button(img_frame, text="打开图片",  command=lambda: reda_img_file( ))
img_path_btn.pack(side=tk.LEFT, anchor=tk.SW, padx=5, pady=5)  

img_path_in = tk.Entry(img_frame)
img_path_in.pack(side=tk.TOP, fill=tk.X, anchor=tk.SW, padx=5, pady=5)  


dict_frame = ttk.Frame(tab5)
dict_frame.grid(row=1, sticky="nsew")

get_dict_f3 = ttk.Button(dict_frame, text="选择字典",  command=lambda: open_dict_f_v2( dict_input3 ))
get_dict_f3.pack(side=tk.LEFT,  anchor=tk.NW, padx=5, pady=5)  

dict_input3 = tk.Entry(dict_frame)
dict_input3.pack(side=tk.TOP, fill = tk.X, anchor=tk.NW,  padx=8, pady=10)


pass_frame = ttk.Frame(tab5)
pass_frame.grid(row=2, sticky="nsew")

# 关键字匹配
info_l = tk.Label(pass_frame, text="设置爆破时匹配的关键字：")
info_l.pack(side=tk.LEFT, anchor=tk.NW,  padx=5, pady=5)
info_entry = tk.Entry(pass_frame)
info_entry.pack(side=tk.LEFT, anchor=tk.NW,  padx=5, pady=5)

img_lsb_crack_btn = ttk.Button(pass_frame, text="字典爆破/密码",  command=lambda: img_lsb_crack() )
img_lsb_crack_btn.pack(side=tk.LEFT, anchor=tk.NW,  padx=5, pady=5)  

img_pass_entry = tk.Entry(pass_frame)
img_pass_entry.pack(side=tk.LEFT,  anchor=tk.NW,  padx=5, pady=5)

img_lsb_btn = ttk.Button(pass_frame, text="提取LSB数据",  command=lambda: img_lsb_dec() )
img_lsb_btn.pack(side=tk.LEFT, anchor=tk.NW,  padx=5, pady=5)  



img_lsb_f = ttk.Frame(tab5)
img_lsb_f.grid(row=3, sticky="nsew")

img_lsb_l = tk.Label(img_lsb_f, text="提取结果：")
img_lsb_l.pack(side=tk.TOP, anchor=tk.NW,  padx=5, pady=5)

img_lsb_Dec_out = tk.Text(img_lsb_f, wrap='word')
img_lsb_Dec_out.pack(side=tk.TOP, fill=tk.Y, expand=True, padx=5, pady=10)

"""
TODO:  添加哥斯拉Godzilla流量解密

def add_info_scrolltxtb(entry_widget, info):
    entry_widget.insert(tk.END, info)

scrolltxtb = scrolledtext.ScrolledText(root, wrap=tk.WORD)
scrolltxtb.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=8)
"""


#  哥斯拉Godzilla流量解密 标签页功能代码

# 绑定事件
def gzl_clear_default(event):
        default_text = "请输入哥斯拉Godzilla加密流量，一般是base64编码"
        if gzl_Enc_input.get("1.0", tk.END).startswith(default_text):
            gzl_Enc_input.delete("1.0", tk.END)


def gzl_model_opt_sltd(event):
    model = gzl_model_opt.get()
    gzl_get_dict_btn.config(state=tk.NORMAL)
    gzl_dict_input.config(state="normal")
    gzl_wspass_l.config(state="normal")
    gzl_wspass_entry.config(state="normal")
    gzl_skey_l.config(state="normal")
    gzl_skey_entry.config(state="normal")
    burp_gzl_btn.config(state="normal")
    gzl_key_hash_entry.config(state="normal")
    gzl_rqst_btn.config(state="normal")
    gzl_rsp_btn.config(state="normal")
    if model == gzl_opts[0]:
         messagebox.showinfo("JSP_AES_BASE64 模式", "请先输入连接密码和key，或者1.粘贴请求包，获取连接密码，2.再粘贴响应包，爆破key，3.解密")
    elif model in (gzl_opts[1], gzl_opts[4], gzl_opts[7], gzl_opts[8], gzl_opts[9], gzl_opts[12]) :
        print('RAW 模式 合集')
        gzl_get_dict_btn.config(state="disabled")
        gzl_dict_input.config(state="disabled")
        gzl_wspass_l.config(state="disabled")
        gzl_wspass_entry.config(state="disabled")
        gzl_skey_l.config(state="disabled")
        gzl_skey_entry.config(state="disabled")
        burp_gzl_btn.config(state="disabled")
        gzl_key_hash_entry.config(state="disabled")
        gzl_rqst_btn.config(state="disabled")
        gzl_rsp_btn.config(state="disabled")
        messagebox.showinfo(f'提示', 'RAW模式兼容性不好，暂未开发')
    elif model == gzl_opts[2]:
        print('PHP_EVAL _XOR_BASE64 模式')
        messagebox.showinfo(f'PHP_EVAL _XOR_BASE64 模式', '请输入访问webshell的第2个POST请求包内容。一般内容如下：\n **passwd**=eval%28base64_decode%28strrev%28urldecode(…… \n **key**=DlMRWA1cL1gOVDc2MjRhRwZFEQ%3D%3D')
    elif model == gzl_opts[3]:
        messagebox.showinfo("PHP_XOR_BASE64 模式", "请先输入连接密码和key，或者1.粘贴请求包，获取连接密码，2.再粘贴响应包，爆破key，3.解密 \n POST请求包内容，一般内容为：**pass**=R0YEQgNVBE…… ")
       
    else:
        gzl_get_dict_btn.config(state="normal")
        # gzl_grep_entry.config(state="normal")
        print(f"你选择了: {model}")
    
    
# 示例函数处置函数  TODO：增加请求3和CMD请求 相关按钮和功能
def gzl_example_data(num):
    #gzl_wspass_entry.delete(0, tk.END)
    gzl_Enc_input.delete("1.0", tk.END)
    model = gzl_model_opt.get()
    if num == 1:
        gzl_wspass_entry.delete(0, tk.END)
        if model == gzl_opts[0]:
            print('JSP_AES_BASE64 请求1')
            gzl_wspass_entry.insert(tk.END, rqst1_java_aes_base64.split('=')[0] )
            gzl_Enc_input.insert(tk.END, rqst1_java_aes_base64)
        elif model  == gzl_opts[2]:
            print('PHP_EVAL _XOR_BASE64 请求1')
            gzl_wspass_entry.insert(tk.END, rqst1_php_eval_xor_base64.split('=')[0] )
            gzl_Enc_input.insert(tk.END, rqst1_php_eval_xor_base64)
        elif model  == gzl_opts[3]:
            print('PHP_XOR_BASE64 请求1 ')
            gzl_wspass_entry.insert(tk.END, rqst1_php_xor_base64.split('=')[0] )
            gzl_Enc_input.insert(tk.END, rqst1_php_xor_base64)
        elif model == gzl_opts[4]:   # TODO： 需要优化
            print('PHP _XOR_RAW 请求1')
            # HEX 模式，需要二次处理，会丢失 链接密码信息
            #gzl_wspass_entry.insert(tk.END, rqst2_php_xor_raw.split('=')[0])
            gzl_Enc_input.insert(tk.END, rqst1_php_xor_raw)
    elif num == 2:
        gzl_wspass_entry.delete(0, tk.END)
        if model == gzl_opts[0]:
            print('JSP_AES_BASE64 请求2')
            gzl_wspass_entry.insert(tk.END, rqst2_java_aes_base64.split('=')[0] )
            gzl_Enc_input.insert(tk.END, rqst2_java_aes_base64)
        elif model  == gzl_opts[2]:
            print('PHP_EVAL _XOR_BASE64 请求2')
            gzl_wspass_entry.insert(tk.END, rqst2_php_eval_xor_base64.split('=')[0])
            gzl_Enc_input.insert(tk.END, rqst2_php_eval_xor_base64)
        elif model  == gzl_opts[3]:
            print('PHP_XOR_BASE64 请求2')
            gzl_wspass_entry.insert(tk.END, rqst2_php_xor_base64.split('=')[0])
            gzl_Enc_input.insert(tk.END, rqst2_php_xor_base64)
        elif model == gzl_opts[4]:   # 需要优化
            print('PHP _XOR_RAW 请求2')
            gzl_Enc_input.insert(tk.END, rqst2_php_xor_raw)
    elif num == 3:
        #  响应包，不删除 链接密码
        if model == gzl_opts[0]:
            print('JSP_AES_BASE64 响应包')
            gzl_Enc_input.insert(tk.END, rsp_java_aes_base64)
        elif model  == gzl_opts[1]:
            print('JSP_AES_RAW 相应包（暂未实现）') 
        elif model  == gzl_opts[2]:
            print('PHP_EVAL _XOR_BASE64 响应包')
            gzl_Enc_input.insert(tk.END, rsp2_php_eval_xor_base64)  # 响应包
        elif model  == gzl_opts[3]:
            print('PHP_XOR_BASE64 响应包')
            gzl_Enc_input.insert(tk.END, rsp2_php_xor_base64)  # 响应包2 请求1无响应
        elif model == gzl_opts[4]:   # 需要优化
            print('PHP _XOR_RAW 响应包')
            gzl_Enc_input.insert(tk.END, rsp2_php_xor_raw)  # 响应包2 请求1无响应
    else :
        print('选择异常')

    
def gzl_burp_key():
    model = gzl_model_opt.get()
    gzl_skey_entry.delete(0, tk.END)
    gzl_key_hash_entry.delete(0, tk.END)
    if model == gzl_opts[0] :
        print('JSP_AES_BASE64 模式 破解Secretkey')
        con_pass = gzl_wspass_entry.get(0, tk.END)
        rsp_data = gzl_Enc_input.get("1.0", tk.END)
        if keys:
           rst =  jsp_aes_secretkey_brup_by_rsp(con_pass, rsp_data, keys)
        else:
            messagebox.showinfo("提示", "未选择字典文件！")
            #"JSP_AES_RAW", "PHP_EVAL _XOR_BASE64", "PHP_XOR_BASE64","PHP _XOR_RAW"
    if model == gzl_opts[2]:
        print('PHP_EVAL _XOR_BASE64 模式')
    elif model == gzl_opts[3]:  # xor模式
        print('PHP_XOR_BASE64 模式')
    elif model == gzl_opts[4]:
        print('PHP _XOR_RAW 模式')
        
    gzl_skey_entry.insert(tk,END, rst)
    # gzl_key_hash_entry.insert(tk.END, skeyhash) # 缺少上下文，TODO
    messagebox.showinfo("提示", "破解完成！")
    

# 似乎是多余的函数，在其他步骤会进行计算
def gzl_burp_skey_hash():
    print('进入计算SecretKey_hash的函数')
    skey = gzl_skey_entry.get()
    print(skey)
    skeyhash = ''
    cipher = gzl_Enc_input.get('1.0', tk.END).strip()
    conn_pass = gzl_wspass_entry.get()
    if not keys:
        messagebox.showinfo('提示', '未设置字典文件')
        return
    if conn_pass == '':
        messagebox.showinfo('提示', '请填写或通过请求包读取连接密码')
        return
    if skey == "":
        print('爆破key流程')
        tmp = gzl_php_xor_base64_burpkey(cipher, conn_pass, keys)
        skey = tmp[0]
    skeyhash = gzl_skey_hash(skey)[:16]  #直接计算hash
    gzl_key_hash_entry.delete(0, tk.END)
    gzl_key_hash_entry.insert(tk.END, skeyhash)
    gzl_skey_entry.insert(tk.END, skey)
    messagebox.showinfo('提示', '爆破/计算结束')


def gzl_dec(num):
    rst = ''
    model = gzl_model_opt.get()
    cipher = gzl_Enc_input.get('1.0', tk.END).strip()
    conn_pass = gzl_wspass_entry.get()
    key = gzl_skey_entry.get()
    skey_hash = gzl_key_hash_entry.get()
    if not cipher:
        messagebox.showinfo("提示", "请输入要解密的密文")
        return
    
    # 请求包模式
    if num == 1:
        print('请求包测试')
        # 获取连接密码  见初始化
        # 获取key 
        # 获取key_hash 见初始化
        # 解密
        if model == gzl_opts[0]:
            print('JSP_AES_BASE64 请求解密')
            if key == '':
                messagebox.showinfo("提示", "请计算/爆破key和k_hash")
                return
            #rqst1_jsp_aes_base64_dec(cipher, key)   # TODO：暂未兼容请求1
            rst = rqst_jsp_aes_base64(cipher, key)
            rst = repr(rst)
            print( rst[:4] )
            print( bytes.fromhex('cafebabe') )
            if rst[:4] == bytes.fromhex('cafebabe'):
                with open('./rqst1.class', 'wb') as cf:     
                    cf.write(rst)
                rst = '解密完成，请查看当前目录下的 rqst1.class 文件（每次解密均会进行覆盖），可以使用jadx工具反编译'
        elif model == gzl_opts[1] :
            print('1 raw，已在模式选择屏蔽') 
        elif model == gzl_opts[2]:
            print('PHP_EVAL_XOR_BASE64 请求解密模式')
            rst_dict = rqst_php_eval_xor_base64(cipher)
            conn_pass = rst_dict['conn_pass']
            s_key = rst_dict['secert_key']
            skey_hash = gzl_skey_hash(s_key)[:16]
            rbody = rst_dict['body']
            cmd = rst_dict['cmd'] 
            rst += f'webshell连接密码可能是：{conn_pass}\n'
            gzl_wspass_entry.delete(0, tk.END)
            gzl_wspass_entry.insert(tk.END, conn_pass)  # 此处会覆盖连接密码控件，TODO：提高兼容
            rst += f'密钥是：{s_key}\n'
            gzl_skey_entry.delete(0, tk.END)
            gzl_skey_entry.insert(tk.END, s_key)
            rst += f'流量解密key_hash可能是：{skey_hash}\n'
            gzl_key_hash_entry.delete(0, tk.END)
            gzl_key_hash_entry.insert(tk.END, skey_hash)
            rst += f'请求主体是：{rbody.decode()}\n'
            rst += f'执行的命令是：{cmd}\n'
        elif model == gzl_opts[3]:
            print('PHP_XOR_BASE64 请求解密')  # TODO： 需要区分请求1和请求2
            #messagebox.showinfo("提示", "该模式进行后续解密，需要SecretKey，请通过相应包计算/爆破相关值！")
            if key == '':
                messagebox.showinfo("提示", "请计算/爆破key和k_hash")
                return
            rst = rqst_php_xor_base64_dec(cipher, key)
        else:
            messagebox.showinfo("提示", "正在开发中……")
    elif num == 2:
        print('响应包测试')
        if conn_pass == '':
            messagebox.showinfo('提示', '请先输入webshell的连接密码，或从请求包中提取')
            return
        if not skey_hash:
            messagebox.showinfo('提示', '请先爆破/计算SecretKey_hash，或通过请求包获取相关值')
            return
        if model == gzl_opts[0]:
            print('JSP_AES_BASE64 响应包解密')
            rst = rsp_jsp_aes_base64_dec(cipher, key)
            print(rst)
        elif model == gzl_opts[1] :
            print('JSP_AES_RAW 响应包解密(暂未实现)')
            # print(skey_hash)
        elif model == gzl_opts[2]:
            print('PHP_EVAL_XOR_BASE64 响应包解密')
            rsp_data = rsp_php_eval_xor_base64(cipher, skey_hash, conn_pass)
            rst += f'响应结果是：{rsp_data}\n'
        elif model == gzl_opts[3]:
            print('PHP_XOR_BASE64 响应包解密') 
            # TODO： 当前不统一，此处传递到是key，不是key_hash
            if key == "":
                print('PHP_XOR_BASE64 响应包解密错误，缺少key')
                #tmp = gzl_php_xor_base64_burpkey(cipher, conn_pass, keys)
                #key = tmp[0]
                #k_hash = tmp[1]
            rst = rsp_php_xor_base64_dec(cipher, key)
        else:
            messagebox.showinfo("提示", "正在开发中……")
            
    """
    # 请求和响应的区别，建议在外层分别，内层处理模式的区别
    if conn_pass == '':
        messagebox.showinfo('提示', '请先输入webshell的连接密码')
    if not skey_hash:
        messagebox.showinfo('提示', '请先爆破/计算SecretKey_hash')
    # TODO： 需要根据场景，判定其生效范围。建议增加对 key 的判定，如果key为空，根据函数需要，设定
    if not keys:
        messagebox.showinfo("提示", "未选择字典文件")
        return
    """
    print(f'最终结果是：{rst }')
    gzl_Dec_input.delete("1.0", tk.END)
    gzl_Dec_input.insert(tk.END, str(rst) )  # 使用repr强制转换
    messagebox.showinfo("提示", "解密完毕！")


#  合并到  gzl_dec() 函数，通过参数判定
def  gzl_rsp_dec():
    skey_hash = gzl_key_hash_entry.get()
    cipher = gzl_Enc_input.get("1.0", tk.END)
    conn_pass = gzl_wspass_entry.get()
    gzl_Dec_input.delete('1.0', tk.END)
    rsp_rst = ''
    if cipher is None:
        messagebox.showinfo('提示', '请先输入要解密的响应包的流量')
    if conn_pass == '':
        messagebox.showinfo('提示', '请先输入webshell的连接密码')
    if not skey_hash:
        messagebox.showinfo('提示', '请先爆破/计算SecretKey_hash')
    else:
        rsp_rst = rsp_php_eval_xor_base64(cipher, conn_pass, s_key_hash)
        gzl_Dec_input.insert(tk.END, rsp_rst)


gzl_top_f = ttk.Frame(tab4)
gzl_top_f.pack(side=tk.TOP, fill=tk.X, expand=0, padx=5, pady=2)  

gzl_m_f = ttk.Frame(tab4)
gzl_m_f.pack(side=tk.TOP, fill=tk.X, expand=0, padx=5, pady=2)  

gzl_b_f = ttk.Frame(tab4)
gzl_b_f.pack(side=tk.TOP, fill=tk.X, expand=0, padx=5, pady=2)  

# 加密模式选择
gzl_set_fr = ttk.Frame(gzl_top_f)
gzl_set_fr.pack(side=tk.TOP, fill=tk.BOTH, expand=0, padx=5)  

gzl_model_l = tk.Label(gzl_set_fr, text="选择加密模式：")
gzl_model_l.pack(side=tk.LEFT, anchor=tk.NW,  padx=5)
gzl_opts = ["JSP_AES_BASE64","JSP_AES_RAW", "PHP_EVAL _XOR_BASE64", "PHP_XOR_BASE64","PHP _XOR_RAW", "ASP_EVAL_BASE64", "ASP_XOR_BASE64","ASP_XOR_RAW", "ASP_RAW","ASP_RAW", "C#_AES_BASE64", "C#_EVAL_AES_BASE64", "C#_AES_RAW", "C#_ASMX_AES_BASE64"]
gzl_model_opt = tk.StringVar() # 设置一个变量，结合textvariable指定，直接全局使用
gzl_model_cbx = ttk.Combobox(gzl_set_fr, values=gzl_opts,  textvariable=gzl_model_opt,  state='readonly') # 设置state，不可修改
gzl_model_cbx.pack(side=tk.LEFT,  fill = tk.X, anchor=tk.NW,  padx=5) 
gzl_model_cbx.set(gzl_opts[0])  # 可选：设置默认值
gzl_model_cbx.bind("<<ComboboxSelected>>", gzl_model_opt_sltd)

gzl_wspass_l = ttk.Label(gzl_set_fr, text="连接密码:")
gzl_wspass_l.pack(side=tk.LEFT, anchor=tk.NW,  padx=5)
gzl_wspass_entry = tk.Entry(gzl_set_fr)
gzl_wspass_entry.pack(side=tk.LEFT, fill = tk.X, anchor=tk.NW,  padx=5)

"""  临时下移
gzl_skey_l = ttk.Label(gzl_set_fr, text="SecretKey")
gzl_skey_l.pack(side=tk.LEFT, anchor=tk.NW,  padx=5)
gzl_skey_entry = tk.Entry(gzl_set_fr)
gzl_skey_entry.pack(side=tk.LEFT, fill = tk.X, anchor=tk.NW,  padx=5)
"""

"""
# 关键字匹配，暂时不需要
gzl_grep_l = tk.Label(gzl_set_fr, text="明文关键字：")
gzl_grep_l.pack(side=tk.LEFT, anchor=tk.NW,  padx=5)
gzl_grep_entry = tk.Entry(gzl_set_fr)
gzl_grep_entry.pack(side=tk.LEFT, anchor=tk.NW,  padx=5)
gzl_grep_entry.insert(0, "status")
"""

# 爆破frame
gzl_bp_fr = ttk.Frame(gzl_top_f)
gzl_bp_fr.pack(side=tk.TOP, fill=tk.BOTH, expand=0, padx=5,pady = 2)  

# 字典选择  临时上调至 连接密码模块 后边，使用明文 SecretKey 模块代替
gzl_get_dict_btn = ttk.Button(gzl_set_fr, text="选择字典文件",  command=lambda: open_dict_f_v2( gzl_dict_input ))
gzl_get_dict_btn.pack(side=tk.LEFT,  anchor=tk.NW, padx=7)  
gzl_dict_input = tk.Entry(gzl_set_fr)
gzl_dict_input.pack(side=tk.LEFT, fill = tk.X, anchor=tk.NW,  padx=5)


gzl_skey_l = ttk.Label(gzl_bp_fr, text="SecretKey")
gzl_skey_l.pack(side=tk.LEFT, anchor=tk.NW,  padx=5)
gzl_skey_entry = tk.Entry(gzl_bp_fr)
gzl_skey_entry.pack(side=tk.LEFT, fill = tk.X, anchor=tk.NW,  padx=5)

burp_gzl_btn = ttk.Button(gzl_bp_fr, text="爆破/计算SecretKey_HASH",  command=lambda: gzl_burp_skey_hash())
burp_gzl_btn.pack(side=tk.LEFT, anchor=tk.NW,  padx=9)  
gzl_key_hash_entry = tk.Entry(gzl_bp_fr)
gzl_key_hash_entry.pack(side=tk.LEFT, fill = tk.X, anchor=tk.NW,  padx=5)

gzl_rqst_btn = ttk.Button(gzl_bp_fr, text="请求包解密",  command=lambda: gzl_dec(1))
gzl_rqst_btn.pack(side=tk.LEFT, anchor=tk.NW,  padx=5)  
gzl_rsp_btn = ttk.Button(gzl_bp_fr, text="响应包解密",  command=lambda: gzl_dec(2))
gzl_rsp_btn.pack(side=tk.LEFT, anchor=tk.NW,  padx=5)  


# 解密按钮
gzl_btn_frame = ttk.Frame(gzl_top_f)
#gzl_btn_frame.grid(row=2, sticky="sew")
gzl_btn_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)  

gzl_Enc_input_l = ttk.Label(gzl_btn_frame, text="待解密的哥斯拉Godzilla加密流量:           ")
gzl_Enc_input_l.pack(side=tk.LEFT, fill=tk.X, padx=5, pady=5)
gzl_examp_r1_btn = ttk.Button(gzl_btn_frame, text="测试数据-请求包1",  command=lambda: gzl_example_data(1))
gzl_examp_r1_btn.pack(side=tk.LEFT, anchor=tk.NW,  padx=5, pady=5)  
gzl_examp_r2_btn = ttk.Button(gzl_btn_frame, text="测试数据-请求包2",  command=lambda: gzl_example_data(2))
gzl_examp_r2_btn.pack(side=tk.LEFT, anchor=tk.NW,  padx=5, pady=5)  
gzl_examp_rsp_btn = ttk.Button(gzl_btn_frame, text="测试数据-响应包",  command=lambda: gzl_example_data(3))
gzl_examp_rsp_btn.pack(side=tk.LEFT, anchor=tk.NW,  padx=5, pady=5)  


# 中部  输入加密流量
gzl_Enc_input = tk.Text(gzl_m_f, wrap='word',)
#gzl_Enc_input.insert(tk.END, "请输入哥斯拉Godzilla加密流量，一般是base64编码")
gzl_Enc_input.pack(side=tk.TOP, fill=tk.BOTH, expand=0, padx=5, pady=2)
#gzl_Enc_input.bind("<Button-1>", gzl_clear_default)    # 绑定左键点击事件到清空默认文本的功能


# 底部  结果展示
gzl_rst_l = tk.Label(gzl_b_f, text="解密结果：")
gzl_rst_l.pack(side=tk.TOP, anchor=tk.NW,  padx=5, pady=5)

gzl_Dec_input = tk.Text(gzl_b_f, wrap='word')
gzl_Dec_input.pack(side=tk.TOP, fill=tk.BOTH, expand=0, padx=5, pady=5)

#  end



#  日志记录及重定向
class RedirectedStdout:
    def __init__(self, filename):
        self.filename = filename
        self.file = open(filename, 'w')

    def write(self, output):
        self.file.write(output)
        self.file.flush()  # 确保立即写入磁盘

    def __del__(self):
        self.file.close()

def logs(msg):
    logf = 'logs.txt'
    with open(logf, 'a+') as f:
        f.writelines(msg)
        

def main():
    global stdout_backup
    stdout_backup = sys.stdout  # 保存原始stdout
    sys.stdout = RedirectedStdout('logs.txt')  # 重定向stdout到文件
    root.mainloop()
    sys.stdout = stdout_backup # 在程序结束前恢复原来的stdout
       
if __name__ == "__main__":
    main()
