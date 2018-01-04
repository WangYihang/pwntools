安装
============

Pwntools 在 Ubuntu 12.04 以及 14.04 版本上适配最合适
但是大部分的函数也能工作在 Unix-Like 的发行版上 (例如: Debain, Arch, FreeBSD, OSX 等等)

先决条件
-------------

为了正确安装 ``Pwntools``, 你需要首先确保你已经安装了下列库

.. toctree::
   :maxdepth: 3
   :glob:

   install/*

安装稳定版本
-----------------

pwntools 目前支持使用 ``pip`` 安装

.. code-block:: bash

    $ apt-get update
    $ apt-get install python2.7 python-pip python-dev git libssl-dev libffi-dev build-essential
    $ pip install --upgrade pip
    $ pip install --upgrade pwntools

开发
--------------

如果你只是本地使用 Pwntools 进行 Hacking
你可能需要执行如下命令:

.. code-block:: bash

    $ git clone https://github.com/Gallopsled/pwntools
    $ pip install --upgrade --editable ./pwntools

.. _Ubuntu: https://launchpad.net/~pwntools/+archive/ubuntu/binutils
