关于 pwntools
========================

首先思考一件事, 你要使用它编写漏洞利用脚本还是将它作为另一个软件项目的一部分
这将决定你使用 Pwntools 的方式

曾经, 我们仅仅通过 ``from pwn import *`` 这样的方式来使用 pwntools (旧版本), 但是将会带来一系列地附作用 (副作用)

在我们重新设计 Pwntools 2.0 版本的时候, 我们确定了两个和以前不一样的目标

* 我们希望能够有一个 标准的 python 模块, 来允许其他人来快速地熟悉 pwntools
* 我们想拥有更多的边缘作用(附加功能), 尤其是能将终端变成二进制模式

To make this possible, we decided to have two different modules. :mod:`pwnlib` 
为了使我们的目标成为显示, 我们决定实现两个不同的 python 模块
:mod:`pwnlib` 将会是更加 Nice, 更加纯净的 Python 模块
而 :mod:`pwn` 将更加侧重于 CTF 竞赛


:mod:`pwn` --- CTF 二进制漏洞利用工具
-----------------------------------------

.. module:: pwn

如上所述, 我们也希望能够在默认情况下就能获取大量的副作用 (附加作用)
这就是这个模块的目的, 它会做如下操作:

* 从拥有许多子模块的 :mod:`pwnlib` 库的根层中引入所有模块/常量等等
  也就是说, 你只要使用 ``import pwn`` 或者 ``from pwn import *`` 
  你就拥有了编写一个漏洞利用程序所需要的所有准备工作
* 调用 :func:`pwnlib.term.init` 会将你的终端修改为二进制模式
  并且使用函数让终端的显示不像它本身的样子
* 设置 :data:`pwnlib.context.log_level` 为 `"info"` 
* 尝试解析 :data:`sys.argv` 这个变量中的所有值
  并且所有的值解析成功之后, 它将会被删除


:mod:`pwnlib` --- 标准 Python 库
---------------------------------------

.. module:: pwnlib

这个模块是我们专门 "净化" 过的 Python 代码
我们认为引入 :mod:`pwnlib` 或者任何其他的子模块将不会有任何副作用 (附加作用) (除了例如: caching)
就像我们在设计之初就制定好的规则
就大部分情况而言, 你只会得到你导入的包
例如, 当你 ``import pwnlib.util`` 的时候, 你将不会访问到 :mod:`pwnlib.util.packing` 
尽管还有有一小部分的异常 (例如: :mod:`pwnlib.shellcraft` ), 这些部分并不很特别符合我们预期的目标
也就是极简和纯净, 但是引入它们已经并不会引起副作用了 (附加作用, 译者注: side-effects)

