# 常见的类型
壳的概念：
核心功能代码之外还有一些起混淆作用的代码

壳的形式：


具体实现的形式：
1.普通的壳（oep）
壳代码的区别：
执行一些普通的功能
2.加密
壳代码的区别：
执行解密功能
3.指令
壳代码区别：
把汇编语言的逻辑重新写一下

eg： xor eax，eax
两个eax进行与或运算


加壳的实际意义：
防止别人了解代码的运行逻辑

# 加壳过程

1.oep
修改程序的入口点
然后，在入口点的地方添加你需要的壳代码（根据你的需要顺便写）
壳代码执行结束之后，再次运行核心功能代码（跳转到程序正常入口地址）

upx：
压缩与解压

## 工具加壳
1.oep
msfvenom -K -X
backdorrfactory

## 手工加壳
1.oep
修改程序的入口点
入口点为0002 126C（126C为入口地址）
eg：
找到想操作的入口点：
可以在od中找到未使用的内存（空地）
![[./PIC/1.png]]
修改入口地址为：C1 88 
![[2.png]]

为何程序在其他机器都可以运行
跳转地址 0002 126C 像od等程序可以识别126C，可以动态修改0002，故可以正确跳转到程序入口地址，正常运行
![[./PIC/3.png]]
程序的机器码不会变，E9==>jmp D1 50 FF FF ==>126C



upx：
压缩与解压

kali中加upx的壳：upx Projrct1.exe
解壳：upx -d Project1.exe

加壳后的 （ida中）Import 中的API就被隐藏了


donut:(将任意.net下的程序转换为shellcode)

核心代码先做加密
加密后的核心代码和壳代码变成新的exe，壳代码负责解密

加密：
``` python
#!/usr/bin/python
#coded by orca666

import sys

#your shellcode [x64]
f= open("payload.bin",'rb')
a=f.read
raw_data = a

encoded_shellcode = []
for opcode in raw_data:
	# the encryption keys:

	new_opcode = ((((()))))
	encoded_shellcode.append(new_opcode)
print("".join(["\\x{0}".format(hex(abs(i)).replace())])
```

解密
``` c
for(int i=0;i<=sizeof(shellcode);i++){
char DecodedOpCode = shellcode[i] ^ 0x7a^0xf7^0x32^0x05^0xd8^0xc7^0x52^0x11;
}
```

使用donut可以将任意exe变为shellcode：
``` bash
./donut.exe -f 文件名
```

手工加壳：
https://bbs.pediy.com/thread-269795.htm
https://bbs.pediy.com/thread-267369.htm

指令壳：
