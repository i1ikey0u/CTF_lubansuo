#! /usr/bin/env python
#--coding=utf-8--
#environ: python3
#--coding by shuichon--
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import base64
from tkinter import filedialog
from model.burp_RC4_Salt import *
from model.burp_Behinder import *
from model.LSB_AES_cloacked_pixe import *



root = tk.Tk()
root.wm_iconbitmap("./3.ico")
root.title("CTF鲁班锁")
root.geometry("800x600")
root.minsize(400, 300)


# 测试  字典信息相关函数合并
keys = []
def open_dict_f_v2(entry_widget):
    filepath = filedialog.askopenfilename()  # 弹出文件选择对话框
    if filepath:  # 如果用户选择了文件
        #msg = ''
        try:
            with open(filepath, 'r') as file: 
                global keys  # 声明使用全局的keys
                keys = file.read().splitlines()  # 读取文件内容
                # dict_info.set(f"文件读取成功！字典数量{len(keys)}")
                msg = f"文件读取成功！字典数量 {len(keys)}"
        except Exception as e:
            msg = (f"读取文件时发生错误：{e}")
        entry_widget.insert(tk.END, msg)
        """if entry_widget == 'dict_input':
            dict_input.insert(tk.END, msg)
        elif entry_widget == 'dict_input2':
            dict_input2.insert(tk.END, msg)
        else:
            raise ValueError(f"无效的 Entry 控件：{entry_widget}")"""



tabControl = ttk.Notebook(root)
tabControl.pack(fill=tk.BOTH, expand=True)

tab1 = ttk.Frame(tabControl)
tabControl.add(tab1, text='Base64解码及隐写')

# 第二个选项卡
tab2 = ttk.Frame(tabControl)
tabControl.add(tab2, text='RC4(Salt)解密')

# 第三个选项卡
tab3 = ttk.Frame(tabControl)
tabControl.add(tab3, text='冰蝎webshell解密')

tab4 = ttk.Frame(tabControl)
tabControl.add(tab4, text='LSB_(AES)_cloacked-pixel')


# tab1 base64 按钮功能实现
def DecBut_action():
    user_input = Enc_input.get('1.0', tk.END).strip()
    Dec_text_output.delete("1.0", tk.END)
    decode = ''
    if chck_mul_line.get() == 1:
        for l in user_input.splitlines() :
           dec = base64.b64decode(l).decode() +'\n'
           decode += dec
    else:
        decode = base64.b64decode(user_input)
    Dec_text_output.insert(tk.END, decode)

def ClsBut_action():
    Enc_input.delete('1.0', tk.END)
    
def MiscDecBut_action():
    user_input = Enc_input.get('1.0', tk.END).strip()
    bit2_text_output.delete("1.0", tk.END)
    decode = ''
    bin_str = ''
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
    messagebox.showinfo('执行完毕！')

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
Enc_input_l = ttk.Label(left_frame, text="请输入Base64编码的字符串:")
Enc_input_l.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)

Enc_input = tk.Text(left_frame, wrap='word',)
Enc_input.insert(tk.END, "请输入Base64编码的字符串:")
Enc_input.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=8, pady=10)

# 绑定事件
def clear_default(event):
        default_text = "请输入Base64编码的字符串:"
        if Enc_input.get("1.0", tk.END).startswith(default_text): # 检查是否只包含默认文本
            Enc_input.delete("1.0", tk.END)
# 绑定左键点击事件到清空默认文本的功能
Enc_input.bind("<Button-1>", clear_default)

#  base64右半侧
DecFrame = tk.Frame(right_frame)
DecFrame.pack(side=tk.TOP, fill=tk.X, padx=8, pady=5)

# 复选框(暂时无作用，仅作调试使用)
def on_checkbox_change():
    """当复选框状态改变时调用的回调函数"""
    if chck_mul_line.get() == 1:
        print("复选框被选中")
    else:
        print("复选框未被选中")

chck_mul_line = tk.IntVar()
chck_mul_line_btn = ttk.Checkbutton(DecFrame, text="按行解码", variable=chck_mul_line, command=on_checkbox_change)
chck_mul_line_btn.pack(side=tk.LEFT, expand=1, padx=5, pady=5)  # 使用pack布局管理器添加复选框到窗口


# 常规解码（TODO：末尾等号异常的处理）
DecBut = ttk.Button(DecFrame, text="尝试解码", command=DecBut_action)
DecBut.pack(side=tk.LEFT, expand=1, padx=5, pady=5)


# 结果展示
Dec_output_label = ttk.Label(right_frame, text="解码结果:")
Dec_output_label.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)
Dec_text_output = tk.Text(right_frame, wrap='word', height=10)
Dec_text_output.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=5, pady=5)

# 第二块隐写
MiscFrame = tk.Frame(right_frame)
MiscFrame.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)

DecButMisc = ttk.Button(MiscFrame, text="Base64隐写", command=MiscDecBut_action)
DecButMisc.pack(side=tk.LEFT, fill=tk.X, padx=5, pady=5)

ClsBut = ttk.Button(MiscFrame, text="待定", command=ClsBut_action)
ClsBut.pack(side=tk.LEFT, fill=tk.X, padx=5, pady=5)

bit2_output_label = ttk.Label(right_frame, text="隐写解密结果（二进制）:")
bit2_output_label.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)
bit2_text_output = tk.Text(right_frame, wrap='word', height=10)
bit2_text_output.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=5, pady=5)

R2toA = ttk.Label(right_frame, text="二进制转Ascii:")
R2toA.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)
R2toA_output = tk.Text(right_frame, wrap='word', height=10)
R2toA_output.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=5, pady=10)


# tabl2 RC4(Salt)加解密

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
    if keys:
        rst = crack_mutl_thread2(cipher, keys)
    Behinder_Dec_input.delete("1.0", tk.END)
    Behinder_Dec_input.insert(tk.END, rst)
    messagebox.showinfo("提示", "解密完毕！")


# 冰蝎解密 右侧布局
get_dict_f2 = tk.StringVar()
get_dict_f2 = ttk.Button(right_frame3, text="选择字典",  command=lambda: open_dict_f_v2( dict_input2 ))
get_dict_f2.pack(side=tk.TOP,  anchor=tk.NW, padx=5, pady=5)  

# 字典选择信息
dict_input2 = tk.Entry(right_frame3)
dict_input2.pack(side=tk.TOP, fill = tk.X, anchor=tk.NW,  padx=8, pady=10)

burp_Behinder = ttk.Button(right_frame3, text="解密",  command=lambda: Behinder_dec())
burp_Behinder.pack(side=tk.TOP, anchor=tk.NW,  padx=5, pady=5)  

behinder_rst_l = tk.Label(right_frame3, text="解密结果：")
behinder_rst_l.pack(side=tk.TOP, anchor=tk.NW,  padx=8, pady=10)

Behinder_Dec_input = tk.Text(right_frame3, wrap='word',)
Behinder_Dec_input.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=8, pady=10)
#  end

# LSB AES 隐写 cloacked-pixel模式

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


img_frame = ttk.Frame(tab4)
img_frame.grid(row=0, sticky="nsew")

img_path_btn = ttk.Button(img_frame, text="打开图片",  command=lambda: reda_img_file( ))
img_path_btn.pack(side=tk.LEFT, anchor=tk.SW, padx=5, pady=5)  

img_path_in = tk.Entry(img_frame)
img_path_in.pack(side=tk.TOP, fill=tk.X, anchor=tk.SW, padx=5, pady=5)  


dict_frame = ttk.Frame(tab4)
dict_frame.grid(row=1, sticky="nsew")

get_dict_f3 = ttk.Button(dict_frame, text="选择字典",  command=lambda: open_dict_f_v2( dict_input3 ))
get_dict_f3.pack(side=tk.LEFT,  anchor=tk.NW, padx=5, pady=5)  

dict_input3 = tk.Entry(dict_frame)
dict_input3.pack(side=tk.TOP, fill = tk.X, anchor=tk.NW,  padx=8, pady=10)


pass_frame = ttk.Frame(tab4)
pass_frame.grid(row=2, sticky="nsew")

# 关键字匹配
info_l = tk.Label(pass_frame, text="设置爆破时匹配的关键字：")
info_l.pack(side=tk.LEFT, anchor=tk.NW,  padx=5, pady=5)
info_entry = tk.Entry(pass_frame)
info_entry.pack(side=tk.LEFT, anchor=tk.NW,  padx=5, pady=5)

img_lsb_crack_btn = ttk.Button(pass_frame, text="字典爆破/密码",  command=lambda: img_lsb_crack() )
img_lsb_crack_btn.pack(side=tk.LEFT, anchor=tk.NW,  padx=5, pady=5)  

img_pass_entry = tk.Entry(pass_frame)
img_pass_entry.pack(side=tk.LEFT,  anchor=tk.NW,  padx=8, pady=10)

img_lsb_btn = ttk.Button(pass_frame, text="提取LSB数据",  command=lambda: img_lsb_dec() )
img_lsb_btn.pack(side=tk.LEFT, anchor=tk.NW,  padx=5, pady=5)  



img_lsb_f = ttk.Frame(tab4)
img_lsb_f.grid(row=3, sticky="nsew")

img_lsb_l = tk.Label(img_lsb_f, text="提取结果：")
img_lsb_l.pack(side=tk.LEFT, anchor=tk.NW,  padx=8, pady=10)

img_lsb_Dec_out = tk.Text(img_lsb_f, wrap='word')
img_lsb_Dec_out.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=8, pady=10)

"""
TODO,添加 执行期间的过程信息
"""


root.mainloop()
