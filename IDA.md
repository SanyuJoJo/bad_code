空格     将代码转化为(前面加地址的)汇编代码[==>转化回来（仅汇编代码）]  ||  option==>line prefixes(graph)
自动注释   option==>Auto comments
手动注释
字符交叉引用 Ctrl + X

# 界面
## 初始界面
### IDA View-A

空格     将代码转化为(前面加地址的)汇编代码[==>转化回来（仅汇编代码）]  ||  option==>line prefixes(graph)
自动注释   option==>Auto comments
手动注释
字符交叉引用 Ctrl + X

### Hex view-1
以16进制显示代码

## structure
结构体分析
（作用---?）
### Enms
枚举
枚举一些敏感的端
## imports
导入段
## exports
导出段

### string操作(Strings window)
view==>opensubview==>strings

显示 unicode ASCII 

### 返回上一步界面
<=左箭头 =>右箭头相反
## 转化成伪代码
F5
加壳或者正在加载 按F5没作用
进度条下方没有小三角，即加载完成
### 手动注释
伪代码界面 右键Edit comments

在 IDA View A中
(地址+汇编代码界面)(空格)
G：跳转地址
### 交叉引用图模式
view->graph->xref
可以看到函数及其引用关系图
显示函数的引用关系(调用关系)
## 查看谁调用了该函数
选中某地址=》Ctrl+x，ok即可跳转调用
类比变量，字符串...
## 参数重命名
右键=>Use  standard symbolic constant
### 修改函数名称
左侧函数列表，搜索该函数，右键=>单击Editfunction



像InternetopenUrlA,以类似UrlA结尾，一般为函数接口
InternetopenUrlA--->查百度

## 样本
吾爱破解病毒区
tria.ge
any.run
cnblogs.com
# 插件编写
## idc插件
``` python
ea = ScreenEA()
for i in range(0x00,0x50):
	b=Byte(ea+i)
	decode_byte = b^0x55
	PatchByte(ea+i,decode_byte)
```

``` c++
#include<idc.idc>
static main(){
	auto ea = ScreenEA(),i,b,decode_byte;
	for(i=0x00;i<0x50;i++)
	{
		b=Byte(ea+i)
		decode_byte = b^0x50;
		PatchByte(ea+i,decode_byte);
	}
}
```

``` c++
#include<idc.idc>

static list_callers(bad_func){
	auto func,addr,xref,source;
	//LockByName-->通过函数名称找到函数的地址
	func = LockByName(bad_func);
	//BADADDR-->坏地址（找本程序地址可用）
	if (func == BADADDR){
		Warning("not found:%s",bad_func);
	}
	else {
		//RfirstB找该函数的交叉引用的列表，返回第一个行
		
		for(addr = RfirstB(func);addr!=BADADDR;addr=RnextB(func,addr))
		{
		//实例化交叉引用
		xref = XrefType();
		//fl_CN:远调用 fl_CF:近调用 fl_JF:远跳转 fl_JN:近跳转 ida中显示p为调用
		if (xrel == fl_CN || xref == fl_CF)
		{
			source = GetFunctionName(addr);
			Message("%s is called from 0x%x in %s\n",bad_func,addr,source);
		}
		}
	}
}

static main(){
	list_callers("");
}
```

使用
IDA 
文件--->Script-->选择idc文件


# 静态分析的结构和经验
### 分支结构

满足条件走绿色线
不满足走红色线
switch 

cmp[地址+偏移量] //里面装的是前面几个的跳转条件
蓝色的线是前面几个case
上面的绿色的线是default条件
#### 情况和场景
如果遇到分支结构，尤其是函数中存在关键变量的分支结构
一、沙盒识别:
分支结构中条件中有和操作系统相关的api函数
识别内存大小
if 内存<2g 退出
if 进程数量<20 退出
二、语言识别
识别语言以针对性攻击
三、命令的选择
常见在木马中

每一个分支下都有很大的代码块或者函数的调用，尤其是在这之前存在网络通信特征

## 网络结构
常见分为两类:
1.tcp连接和udp这一类的通常会直接调用socket
2.http(s)
调用socket，有一个前提条件，就是使用wsa
socket流程:
库:ws2_32
1.wsa相关
2.socket
3.connect
4.recv/send
5.closesocket
6.wsacleanup
在恶意代码分析中，只要存在GetTickCount，80%概率都是确定目标的uid
遇到勒索软件怎么提高解密成功几率：
记录下被勒索的具体时间（精确到秒）
原因：
很多的勒索软件的密钥由于需要一对一，GetTickCount或者是能唯一识别的东西来做密钥的基础

http:
wininet.h
v4 =InternetOpenA(0,1u,0,0,0);
InternetOpenUrlA(v4,&szUrl,0,0,0x84000000,0);
internetCloseHandle(v4);
internetCloseHandle(0);

恶意代码http场景:
攻防演练环境下：
http协议下的命令和结果传输

apt环境下:
一、勒索文本的存放
二、公有环境下存放一些敏感变量
尤其是遇到pastebin
密钥，或者是某个函数的参数，某个变量的变化（较常见）
三、结果存放到网站上

``` python
def eyiguochen(a):
	b=1
	c=b+a
	return c
def wangyeqingqiu():
	re = requests.get("http://www.baidu.com/a")
	return re.content
if __name__ == '__main__':
	a = wangyeqingqu()
	c = eyiguochen(a)
	if c==3:
		pass
	else:
		pass
```


## 文件结构

释放文件:

1.0040A058 LoadResource KERNEL32
LoadResource:从资源文件中找到位置
CreatFile：创建文件

2.从变量里面直接创建文件
看变量的hex是否存在pe相关的东西

3.从网络释放文件
创建结构，下载内容
1.先会创建一个pe结构，但是没有内容
2.保存下这个指针
3.recv之后（介绍过来的其实就是meterpreter的文件内容，以msf举例）
4.就可以选择是创建文件还是直接在内存运行

## 加解密结构

一、使用微软加密
![[./PIC/7.png]]
二、自己写的加解密但是有随机数的情况
![[./PIC/8.png]]
对注册表操作+带RNG这种字样
3.自己写的加解密自己的密钥
f5看到很多的for循环 while循环还有循环里面有很多的异或操作和位移操作

密钥的选择：比较能够唯一识别的--MAC地址，时间....

密码体系：
对称：
明文---加密的密钥---密文 对称密钥体系

非对称：
明文---公钥---私钥---密文