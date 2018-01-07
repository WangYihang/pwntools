.. testsetup:: *

   from pwn import *
   old = context.defaults.copy()

.. testcleanup:: *

    context.defaults.copy = old

Command Line Tools
========================

pwntools 也提供了大量有用的命令行工具, 它们用作某些内部功能的包装

.. toctree::

.. autoprogram:: pwnlib.commandline.main:parser
   :prog: pwn

