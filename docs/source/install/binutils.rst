Binutils
-------------

为了支持一些不常见的架构的汇编指令(例如: 在 Mac OS X 操作系统上汇编 Sparc 的 Shellcode)
需要首先安装交叉编译的 ``binutils``
我们已经尽我们最大的努力使这个更加丝滑

在下面的例子中, 请替换 ``$ARCH`` 为你所需要的目标架构 (例如： arm, mips64, vax, 等等)

如果你有一个八核的现代 CPU , 那么从源码构建 `binutils` 大约需要 60 秒钟

Ubuntu
^^^^^^^^^^^^^^^^

如果你的操作系统是 Ubuntu 12.04 到 15.10 之间, 那么你需要首先添加 pwntools 的软件源 `Personal Package Archive repository <http://binutils.pwntools.com>`__.

Ubuntu Xenial (16.04) 有许多官方的软件包来支持大多数架构, 因此不需要再额外做什么

.. code-block:: bash

    $ apt-get install software-properties-common
    $ apt-add-repository ppa:pwntools/binutils
    $ apt-get update

然后, 为你的目标架构安装 binutils

.. code-block:: bash

    $ apt-get install binutils-$ARCH-linux-gnu

Mac OS X
^^^^^^^^^^^^^^^^

Mac OS X 安装比较容易, 但是也需要从源码编译 binutils
但是, 我们已经做好了 ``homebrew`` 的软件包以便于可以通过一条命令完成构建
After installing `brew <http://brew.sh>`__, grab the appropriate
在安装完成 `brew <http://brew.sh>`__ 之后, 就可以开始正式安装 binutils 了
`binutils
repo <https://github.com/Gallopsled/pwntools-binutils/>`__.

.. code-block:: bash

    $ brew install https://raw.githubusercontent.com/Gallopsled/pwntools-binutils/master/osx/binutils-$ARCH.rb

Alternate OSes
^^^^^^^^^^^^^^^^

如果你想一步一步手动从源码编译所有的工作, 手动构建 ``binutils`` 也很简单

.. code-block:: bash

    #!/usr/bin/env bash

    V=2.25   # Binutils Version
    ARCH=arm # Target architecture

    cd /tmp
    wget -nc https://ftp.gnu.org/gnu/binutils/binutils-$V.tar.gz
    wget -nc https://ftp.gnu.org/gnu/binutils/binutils-$V.tar.gz.sig

    gpg --keyserver keys.gnupg.net --recv-keys 4AE55E93
    gpg --verify binutils-$V.tar.gz.sig

    tar xf binutils-$V.tar.gz

    mkdir binutils-build
    cd binutils-build

    export AR=ar
    export AS=as

    ../binutils-$V/configure \
        --prefix=/usr/local \
        --target=$ARCH-unknown-linux-gnu \
        --disable-static \
        --disable-multilib \
        --disable-werror \
        --disable-nls

    MAKE=gmake
    hash gmake || MAKE=make

    $MAKE -j clean all
    sudo $MAKE install

