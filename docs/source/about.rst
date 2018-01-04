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

As stated, we would also like to have the ability to get a lot of these
side-effects by default. That is the purpose of this module. It does
the following:

* Imports everything from the toplevel :mod:`pwnlib` along with
  functions from a lot of submodules. This means that if you do
  ``import pwn`` or ``from pwn import *``, you will have access to
  everything you need to write an exploit.
* Calls :func:`pwnlib.term.init` to put your terminal in raw mode
  and implements functionality to make it appear like it isn't.
* Setting the :data:`pwnlib.context.log_level` to `"info"`.
* Tries to parse some of the values in :data:`sys.argv` and every
  value it succeeds in parsing it removes.

:mod:`pwnlib` --- 标准 Python 库
---------------------------------------

.. module:: pwnlib

This module is our "clean" python-code. As a rule, we do not think that
importing :mod:`pwnlib` or any of the submodules should have any significant
side-effects (besides e.g. caching).

For the most part, you will also only get the bits you import. You for instance
not get access to :mod:`pwnlib.util.packing` simply by doing ``import
pwnlib.util``.

Though there are a few exceptions (such as :mod:`pwnlib.shellcraft`), that does
not quite fit the goals of being simple and clean, but they can still be
imported without implicit side-effects.
