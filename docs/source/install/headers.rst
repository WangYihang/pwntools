Python 开发版
-----------------------------

Some of pwntools' Python dependencies require native extensions (for example, Paramiko requires PyCrypto).

pwntools 的一些 Python 依赖库需要 Native 的扩展 (例如: Paramiko 需要首先安装 PyCrypto)

In order to build these native extensions, the development headers for Python must be installed.
为了构建这些 native 的扩展, 需要首先安装 Python 的开发版

Ubuntu
^^^^^^^^^^^^^^^^

.. code-block:: bash

    $ apt-get install python-dev

Mac OS X
^^^^^^^^^^^^^^^^

不需要额外操作