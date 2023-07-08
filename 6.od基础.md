明确我们的使用目的：
在恶意样本分析中，我们使用od通常都是用来补充一些详细信息或者是寻找一些特殊的东西
主要是抓住看到的信息的不通点

## 动态看到的有哪些
1.堆栈具体的值
ida：

![[./PIC/9.png]]

od：
![[./PIC/10.png]]
根据程序运行可以看到具体的堆栈值

2.特殊的函数寻找方式
三种常见的win32api调用方式：
	1.loadlibrary
	2.include<windos.h>
	3.getprocessaddress
以上三种在静态分析中也可以看到

静态分析中看不到:
hash:
https://www.cnblogs.com/bokernb/p/6407484.html
为什么看不到
pe导入表导出表
getprocessaddress 直接看到的就是字符串 也就是函数名

hash 我们可以把dll中的函数统一规划成一种16进制格式然后通过一些计算过程找到它
立即数--》地址--》函数名

eg：msf使用的是hash

syscalls：
较难

3.内存变化
a=1
b=a+1
可以直接跳转到指向的地址直接看到内存内容

结合ida
1.地址问题
eg：00401038
40 如果为40的话 就直接取后面四位数
eg： ida-->00401038 od-->007F1038 后四位相同
如果不是40 如 41 那就取后面的1
ida-->00410000
od：005F1017 用005F0000+10000(后面的1)

### ida和od地址不同原因
od是在运行，而ida是静态分析
eg：ida中00401038 前四位0040 在od中会被替换如007F

## 基础使用

界面

操作

f7 使用场景
运行的汇编代码中有call
如果想看call的函数的具体代码，就用f7
f8 使用场景
没有call
如果想看call的函数的具体代码，就用f8

ctrl + f8 使用场景(自动运行)
循环
当运行到关键位置，f12暂停

FC 重置调用约定
![[./PIC/11.png]]
一般在写shellcode时，会先规定调用约定


https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x86/src/block/block_api.asm