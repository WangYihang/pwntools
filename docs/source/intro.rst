.. testsetup:: *

   from pwn import *

快速开始
========================

为了让你先快速了解 pwntools, 让我们首先来看一个小例子
为了编写 Exploits, pwntools 提供了一个优雅的小 Demo

    >>> from pwn import *

这句话将一系列的函数引入全局命名空间
现在你可以做例如: 汇编, 反汇编, 封包, 解包等一系列的操作只通过调用一个单独的函数

你可以参考 :doc:`globals` 来获取所有被导入的模块/常量列表

建立链接
------------------

你需要的是和 CTF 的 pwn 题中的二进制程序进行交互, 以便与将它 pwn 掉, 对吧?

pwntools 的 :mod:`pwnlib.tubes` 模块让这件事变得异常简单

这个模块对外暴露了一个标准的接口来与进程/套接字/串口/或者其他任何输入输出设备进行交流
例如, 通过 :mod:`pwnlib.tubes.remote` 进行远程连接

    >>> conn = remote('ftp.ubuntu.org',21)
    >>> conn.recvline() # doctest: +ELLIPSIS
    '220 ...'
    >>> conn.send('USER anonymous\r\n')
    >>> conn.recvuntil(' ', drop=True)
    '331'
    >>> conn.recvline()
    'Please specify the password.\r\n'
    >>> conn.close()

实现监听一个端口也很简单

    >>> l = listen()
    >>> r = remote('localhost', l.lport)
    >>> c = l.wait_for_connection()
    >>> r.send('hello')
    >>> c.recv()
    'hello'

通过库 :mod:`pwnlib.tubes.process` , 我们可以很容易地和进程进行交互

::

    >>> sh = process('/bin/sh')
    >>> sh.sendline('sleep 3; echo hello world;')
    >>> sh.recvline(timeout=1)
    ''
    >>> sh.recvline(timeout=5)
    'hello world\n'
    >>> sh.close()

不仅可以通过编写代码和程序进行交互, 也可以通过直接通过终端和进程进行交互

    >>> sh.interactive() # doctest: +SKIP
    $ whoami
    user

当你拿到 SSH 的权限的时候, 你甚至可以通过 SSH 这个模块来执行你的 Exploit
使用 :mod:`pwnlib.tubes.ssh`, 你可以快速地运行一个进程并且获取输出
或者运行一个进程然后就像 ``process`` 一样和这个进程进行交互

::

    >>> shell = ssh('bandit0', 'bandit.labs.overthewire.org', password='bandit0', port=2220)
    >>> shell['whoami']
    'bandit0'
    >>> shell.download_file('/etc/motd')
    >>> sh = shell.run('sh')
    >>> sh.sendline('sleep 3; echo hello world;') # doctest: +SKIP
    >>> sh.recvline(timeout=1)
    ''
    >>> sh.recvline(timeout=5)
    'hello world\n'
    >>> shell.close()

打包和解包
------------------

A common task for exploit-writing is converting between integers as Python
sees them, and their representation as a sequence of bytes.
Usually folks resort to the built-in ``struct`` module.

pwntools makes this easier with :mod:`pwnlib.util.packing`.  No more remembering
unpacking codes, and littering your code with helper routines.

    >>> import struct
    >>> p32(0xdeadbeef) == struct.pack('I', 0xdeadbeef)
    True
    >>> leet = '37130000'.decode('hex')
    >>> u32('abcd') == struct.unpack('I', 'abcd')[0]
    True

The packing/unpacking operations are defined for many common bit-widths.

    >>> u8('A') == 0x41
    True

设置目标架构和操作系统类型
--------------------------------------

The target architecture can generally be specified as an argument to the routine that requires it.

    >>> asm('nop')
    '\x90'
    >>> asm('nop', arch='arm')
    '\x00\xf0 \xe3'

However, it can also be set once in the global ``context``.  The operating system, word size, and endianness can also be set here.

    >>> context.arch      = 'i386'
    >>> context.os        = 'linux'
    >>> context.endian    = 'little'
    >>> context.word_size = 32

Additionally, you can use a shorthand to set all of the values at once.

    >>> asm('nop')
    '\x90'
    >>> context(arch='arm', os='linux', endian='big', word_size=32)
    >>> asm('nop')
    '\xe3 \xf0\x00'

.. doctest::
   :hide:

    >>> context.clear()

设置日志等级
-------------------------

You can control the verbosity of the standard pwntools logging via ``context``.

For example, setting

    >>> context.log_level = 'debug'

Will cause all of the data sent and received by a ``tube`` to be printed to the screen.

.. doctest::
   :hide:

    >>> context.clear()

汇编和反汇编
------------------------

Never again will you need to run some already-assembled pile of shellcode
from the internet!  The :mod:`pwnlib.asm` module is full of awesome.

    >>> asm('mov eax, 0').encode('hex')
    'b800000000'

But if you do, it's easy to suss out!

    >>> print disasm('6a0258cd80ebf9'.decode('hex'))
       0:   6a 02                   push   0x2
       2:   58                      pop    eax
       3:   cd 80                   int    0x80
       5:   eb f9                   jmp    0x0

However, you shouldn't even need to write your own shellcode most of the
time!  pwntools comes with the :mod:`pwnlib.shellcraft` module, which is
loaded with useful time-saving shellcodes.

Let's say that we want to `setreuid(getuid(), getuid())` followed by `dup`ing
file descriptor 4 to `stdin`, `stdout`, and `stderr`, and then pop a shell!

    >>> asm(shellcraft.setreuid() + shellcraft.dupsh(4)).encode('hex') # doctest: +ELLIPSIS
    '6a3158cd80...'


其他工具
----------------------

Never write another hexdump, thanks to :mod:`pwnlib.util.fiddling`.


Find offsets in your buffer that cause a crash, thanks to :mod:`pwnlib.cyclic`.

    >>> print cyclic(20)
    aaaabaaacaaadaaaeaaa
    >>> # Assume EIP = 0x62616166 ('faab' which is pack(0x62616166))  at crash time
    >>> print cyclic_find('faab')
    120

ELF 文件解析以及操作
----------------

Stop hard-coding things!  Look them up at runtime with :mod:`pwnlib.elf`.

    >>> e = ELF('/bin/cat')
    >>> print hex(e.address) #doctest: +SKIP
    0x400000
    >>> print hex(e.symbols['write']) #doctest: +SKIP
    0x401680
    >>> print hex(e.got['write']) #doctest: +SKIP
    0x60b070
    >>> print hex(e.plt['write']) #doctest: +SKIP
    0x401680

You can even patch and save the files.

    >>> e = ELF('/bin/cat')
    >>> e.read(e.address, 4)
    '\x7fELF'
    >>> e.asm(e.address, 'ret')
    >>> e.save('/tmp/quiet-cat')
    >>> disasm(file('/tmp/quiet-cat','rb').read(1))
    '   0:   c3                      ret'

