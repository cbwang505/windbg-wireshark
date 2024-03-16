
#### 使用说明

把目录下文件复制到如下位置,Wireshark支持版本4.0以上
C:\Program Files\Wireshark\plugins\4.0\kdnet.lua
C:\Program Files\Wireshark\gcrypt.dll
C:\Program Files\Wireshark\luagcrypt.dll
启动
"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe" -k "com:pipe,port=\\.\pipe\pipeout,baud=115200,resets=0,reconnect"
powershell执行
Set-VMComPort -VMName win10x6422h2 -Path \\.\pipe\pipein -Number 1
在虚拟机中执行
bcdedit /dbgsettings serial DEBUGPORT:1 BAUDRATE:115200
bcdedit /debug on
最后执行
pipe.exe pipeout pipein
Wireshark在pipe.exe目录下打开生成的pcap文件

## 运行效果 ##

以下是笔者模拟器运行的效果,如图:

![查看大图](img/pipe.gif)



## 参与贡献 ##


作者来自ZheJiang Guoli Security Technology,邮箱cbwang505@hotmail.com