.. testsetup:: *

   from pwn import *

``from pwn import *``
========================

你将会看到这是 pwntools 的最常见的用法

    >>> from pwn import *

这行代码引入了从全局命名空间中引入了大量实用代码来让你的漏洞利用过程更加简单

下面我们来快速浏览一下那些被导入的模块的清单, 大致是以重要性和使用频率来排序

- :mod:`pwnlib.context`
    - :data:`pwnlib.context.context`
    - 负责大多数对于 pwntools 的设置
    - 你可以设置 `context.log_level = 'debug'` 来找出漏洞利用程序中的错误进行调试
    - 范围感知, 所以你可以通过 :meth: `.ContextType.local` 来禁用一段代码的日志记录
- ``remote``, ``listen``, ``ssh``, ``process``
    - :mod:`pwnlib.tubes`
    - 非常方便的将关于 CTF 题目的所有常见函数进行封装
    - 可以连接任何你想连接的东西 (套接字等), 并且确实是你想要的
    - 有一些很常见有用的操作例如: ``recvline``, ``recvuntil``, ``clean`` 等等
    - 通过使用 ``.interactive()`` 来直接与应用进行交互
- ``p32`` and ``u32``
    - :mod:`pwnlib.util.packing`
    - 如果你懒得去记忆 ``'>'`` 在 ``struct.pack`` 库中到底表示的是有符号数还是无符号数的话, 那么这些函数将会很有用, 并且在尾部不会有丑陋的 ``[0]`` 这样的代码
    - 可以用正常的参数传递的方式设置 ``signed`` 和 ``endian`` (你也可以直接通过 ``context`` 来进行一次性的设置, 之后就再也不需要关心这些)
    - 为最常见的字节长度设计的函数已经定义好了 (``u8``, ``u64`` 等等), 并且你也可以自行通过 :func:`pwnlib.util.packing.pack` 进行设置
- ``log``
    - :mod:`pwnlib.log`
    - 让你的输出更漂亮!
- ``cyclic`` and ``cyclic_func``
    - :mod:`pwnlib.util.cyclic`
    - 用来生成一些字符串, 这些字符串可以帮助你找到任何已知的字符串的字串的偏移量, 通过参数来设置 (默认为 4 字节)
    - 这在缓冲区溢出漏洞中是非常有帮助的
    - 不需要再寻找 0x41414141, 只需要看到 0x61616171 就说明你可以在偏移量为 64 的位置控制 EIP
- ``asm`` and ``disasm``
    - :mod:`pwnlib.asm`
    - 快速将汇编代码转换为机器码, 反过来也一样
    - 如果你已经安装了 binutils 那么就可以支持任何架构
    - 已经内置了超过 20 种不同的架构, 可以在这里查看所有架构的详情: `ppa:pwntools/binutils <https://launchpad.net/~pwntools/+archive/ubuntu/binutils>`_
- ``shellcraft``
    - :mod:`pwnlib.shellcraft`
    - 已经为你准备好的 shellcode 仓库
    - ``asm(shellcraft.sh())`` 将会给你提供一个 shell
    - 对于 shellcode 片断可重用的模板化库
- ``ELF``
    - :mod:`pwnlib.elf`
    - ELF 文件成熟的操作工具, 包括符号解析, 虚拟内存在文件中的偏移, 并且还可以修改并保存二进制文件
- ``DynELF``
    - :mod:`pwnlib.dynelf`
    - 只给出一个指向任何加载模块的指针, 以及一个可以在任何地址泄露数据的函数, DynELF 库就可以动态地解析任意函数地址
- ``ROP``
    - :mod:`pwnlib.rop`
    - 通过使用 DSL 来描述你想要调用的代码, 然后就可以自动生成 ROP 链, 而不需要二进制地址
- ``gdb.debug`` and ``gdb.attach``
    - :mod:`pwnlib.gdb`
    - Launch a binary under GDB and pop up a new terminal to interact with it.  Automates setting breakpoints and makes iteration on exploits MUCH faster.
    - 在 GDB 中启动一个二进制程序, 或者直接弹出一个 GDB 的终端并与之交互
    - 自动设置断点, 并更快地对漏洞进行迭代
    - 通过指定 PID 附加到一个正在运行的进程上, 或者 :mod:`pwnlib.tubes` 对象上, 甚至仅仅是一个已连接的套接字上
- ``args``
    - Dictionary containing all-caps command-line arguments for quick access
    - 快速访问命令行参数, 其中参数的键全部大写, 并且为字典类型
    - 可以通过 ``python foo.py REMOTE=1`` 或者 ``args['REMOTE'] == '1'` 来设置命令行参数
    - 你也可以在这里设置日志等级或者终端偏好
        - `NOTERM`
        - `SILENT`
        - `DEBUG`
- ``randoms``, ``rol``, ``ror``, ``xor``, ``bits``
    - :mod:`pwnlib.util.fiddling`
    - 通过指定的一些字母来生成一个随机的数据, 或者
    - 简化了通常需要 `0xffffffff` 这样的掩码的数学运算, 或者
    - 调用 `ord` 和 `chr` 函数很多次 (an ugly number of times)
- ``net``
    - :mod:`pwnlib.util.net`
    - 一套用来查询网络接口的库
- ``proc``
    - :mod:`pwnlib.util.proc`
    - 一套用来查询进程的库
- ``pause``
    - 新版本的 ``getch``
- ``safeeval``
    - :mod:`pwnlib.util.safeeval`
    - 安全通过 eval 执行 python 代码, 没有讨厌的副作用。

再看一下面的这些库, 显而易见, 它们也被导入全局命名空间, 并且可以直接使用

- ``hexdump``
- ``read`` and ``write``
- ``enhex`` and ``unhex``
- ``more``
- ``group``
- ``align`` and ``align_down``
- ``urlencode`` and ``urldecode``
- ``which``
- ``wget``

除此之外, 下面展示的所有模块已经被自动导入, 因为通常情况下你会频繁会使用到这些库的

- ``os``
- ``sys``
- ``time``
- ``requests``
- ``re``
- ``random``
