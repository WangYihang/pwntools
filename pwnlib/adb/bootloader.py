#!/usr/bin/env python
# encoding:utf-8

from __future__ import unicode_literals

import ctypes
import io
import os
import sys

class img_info(ctypes.Structure):
    _fields_ = [
        ('name', ctypes.c_char * 64),
        ('size', ctypes.c_uint32)
    ]

class bootloader_images_header(ctypes.Structure):
    _fields_ = [
        ('magic', ctypes.c_char * 8),
        ('num_images', ctypes.c_uint32),
        ('start_offset', ctypes.c_uint32),
        ('bootldr_size', ctypes.c_uint32),
    ]

    def __init__(self, *a, **kw):
        super(bootloader_images_header, self).__init__(*a, **kw)
        if self.magic != self.MAGIC:
            raise ValueError("Incorrect magic (%r, expected %r)" % (self.magic, self.MAGIC))
    MAGIC = 'BOOTLDR!'

class BootloaderImage(object):
    def __init__(self, data):
        """安卓 BootLoader 镜像

        Arguments:
            data(str): 从镜像文件中提取出的二进制数据.
        """
        self.data = data
        self.header = bootloader_images_header.from_buffer_copy(data)

        imgarray = ctypes.ARRAY(img_info, self.header.num_images)
        self.img_info = imgarray.from_buffer_copy(data, ctypes.sizeof(self.header))

    def extract(self, index_or_name):
        """extract(index_or_name) -> bytes

        解压一个镜像的内容

        Arguments:
            index_or_name(str,int): 镜像的索引或者名称.

        Returns:
            镜像的内容.
        """
        if isinstance(index_or_name, int):
            index = index_or_name
        else:
            for i in range(len(self.img_info)):
                if self.img_info[i].name == index_or_name:
                    index = i
                    break
            else:
                raise ValueError("Invalid img name: %r" % index_or_name)

        if index >= len(self.img_info):
            raise ValueError("index out of range (%s, max %s)" % (index, len(self.img_info)))

        offset = self.header.start_offset

        for i in range(index):
            offset += self.img_info[i].size

        return self.data[offset:offset + self.img_info[index].size]

    def extract_all(self, path):
        """extract_all(path)

        将所有的镜像解压到提供的目录
        文件名以 '.img' 结尾, 并且取不包含后缀名的那部分
        """
        if not os.path.isdir(path):
            raise ValueError("%r does not exist or is not a directory" % path)

        for img in self.img_info:
            imgpath = os.path.join(path, img.name + '.img')
            with open(imgpath, 'wb+') as f:
                data = self.extract(img.name)
                f.write(data)

    def __str__(self):
        rv = []
        rv.append("Bootloader")
        rv.append("  Magic:  %r" % self.header.magic)
        rv.append("  Offset: %#x" % self.header.start_offset)
        rv.append("  Size:   %#x" % self.header.bootldr_size)
        rv.append("  Images: %s" % self.header.num_images)
        for img in self.img_info:
            rv.append("    Name: %s" % img.name)
            rv.append("    Size: %#x" % img.size)
            rv.append("    Data: %r..." % self.extract(img.name)[:32])
        return '\n'.join(rv)

if __name__ == '__main__':
    # Easy sanity checking
    b = BootloaderImage(open(sys.argv[1]).read())
    print(b)
