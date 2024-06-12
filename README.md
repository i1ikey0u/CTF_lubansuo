# CTF_lubansuo/CTF鲁班锁

CTF鲁班锁

## 简介
将日常CTF比赛中遇到的一些隐写和解密，特别是一些非常规的，制作为图形界面工具，给大家提供使用。  

完全开源，欢迎大家提建议和意见。特别是在CTF比赛里面，一些需要便捷工具的，或者一些工具不开源的。欢迎提交Issues，有空会逐步加进来。

## 问题
1.触发反病毒程序的提示  
因为打包exe时使用了去除CMD控制台的参数，可能会提示存在病毒，如有疑问，可以直接运行脚本  py -3 lubansuo.py  
2.由于加密流量加解密的文字较多，tk的文本控件性能有瓶颈，可能导致界面操作存在偶尔的卡顿  

## 当前进展
1.初步完成了冰蝎加密流量的解密工作（主要为PHP版本的 AES 和 XOR模式的解密）  
2.正在全力开发哥斯拉Godzilla使用的Webshell流量的解密，已对PHP版本的2个主流webshell加密流量完成解密  
3.最最主要是，**支持从给定的Godzilla流量中提取websshell连接密码， 并爆破解密流量需要的 key**  
4.Godzillajsp版本的具备初步功能  
5.增加使用日志  

## 需要协助
工作太繁忙，没有现成的C#和ASP的环境。如果有需要对应环境的 冰蝎/Behinder 或 哥斯拉/Godzilla 的加密流量解密功能，请协助提供对应的数据，相关要求如下：  
1.冰蝎/Behinder  
可以提供原始pcap包，该pcap包内冰蝎流量的简要说明；  
也可以提供对应的密文数据；  
最好提供webshell密码，方便调试。  

2.哥斯拉/Godzilla  
可以提供原始pcap包；  
也可以提供对应的密文数据，需要区分和明确标记说明是请求包还是响应包；  
最好提供webshell连接密码和对应的密钥key，方便调试。  


## TODO
-完成哥斯拉Godzilla使用的剩余其他Webshell流量的解密  
-完善冰蝎webshell加密流量的解密工作  
-完善使用说明和示例，当前哥斯拉加密流量的解密过程比较繁琐  
-支持多个wireshark导出的批量解密  
-支持pcap包直接读入解密  
-优化或者更换技术栈，解决界面操作偶尔的卡顿问题  

