pwntools
====================================

``pwntools`` is a CTF framework and exploit development library.
Written in Python, it is designed for rapid prototyping and development,
and intended to make exploit writing as simple as possible.

``pwntools`` 是一个 CTF (Capture The Flag) 框架, 并且是一个漏洞利用开发库
使用 Python 编写
它的主要被设计用于快速原型设计以及开发, 致力于让使用者编写尽可能简介的漏洞利用程序


The primary location for this documentation is at docs.pwntools.com_, which uses
readthedocs_. It comes in three primary flavors:

该文档的主要地址位于: docs.pwntools.com_, 并使用 readthedoc_ 进行维护, 该文档存在三个分支

- Stable_
- Beta_
- Dev_

.. _readthedocs: https://readthedocs.org
.. _docs.pwntools.com: https://docs.pwntools.com
.. _Stable: https://docs.pwntools.com/en/stable
.. _Beta: https://docs.pwntools.com/en/beta
.. _Dev: https://docs.pwntools.com/en/dev


快速开始
---------------

.. toctree::
   :maxdepth: 3
   :glob:

   关于
   安装
   intro
   globals
   命令行工具


模块索引
------------

每一个 ``pwntools`` 的模块如下所示.

.. toctree::
   :maxdepth: 1
   :glob:

   adb
   args
   asm
   atexception
   atexit
   constants
   config
   context
   dynelf
   encoders
   elf
   exception
   flag
   fmtstr
   gdb
   libcdb
   log
   memleak
   protocols
   qemu
   replacements
   rop
   rop/*
   runner
   shellcraft
   shellcraft/*
   term
   timeout
   tubes
   tubes/*
   ui
   update
   useragents
   util/*

.. toctree::
   :hidden:

   testexample

.. only:: not dash

   目录和表格
   ==================

   * :ref:`genindex`
   * :ref:`modindex`
   * :ref:`search`
