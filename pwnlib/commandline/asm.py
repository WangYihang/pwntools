#!/usr/bin/env python2
# encoding:utf-8

from __future__ import absolute_import

import argparse
import sys

from pwn import *
from pwnlib.commandline import common

parser = common.parser_commands.add_parser(
    'asm',
    help = u'将 shellcode 汇编成机器码'
)

parser.add_argument(
    'lines',
    metavar='line',
    nargs='*',
    help=u'需要被汇编的代码, 如果没有提供这个参数, 就会从标准输入流中读取'
)

parser.add_argument(
    "-f", "--format",
    help=u"格式化输出 (默认输出到终端的为十六进制, 其他的是原始二进制)",
    choices=['raw', 'hex', 'string', 'elf']
)

parser.add_argument(
    "-o","--output",
    metavar='file',
    help=u"指定输出文件 (默认标准输出流)",
    type=argparse.FileType('w'),
    default=sys.stdout
)

parser.add_argument(
    '-c', '--context',
    metavar = 'context',
    action = 'append',
    type   = common.context_arg,
    choices = common.choices,
    help = u'指定 shellcode 将要被运行的系统环境: 操作系统/架构/字节序/字长 (默认: linux/i386), 可以在其中进行选择: %s' % common.choices,
)

parser.add_argument(
    '-v', '--avoid',
    action='append',
    help = u'编码 shellcode 使它避免指定的字符 (以 16 进制提供; 默认: 000a)'
)

parser.add_argument(
    '-n', '--newline',
    dest='avoid',
    action='append_const',
    const='\n',
    help = u'编码 shellcode 使它避免换行符'
)

parser.add_argument(
    '-z', '--zero',
    dest='avoid',
    action='append_const',
    const='\x00',
    help = u'编码 shellcode 使它避免空字节'
)


parser.add_argument(
    '-d',
    '--debug',
    help=u'使用 GDB 调试 shellcode',
    action='store_true'
)

parser.add_argument(
    '-e',
    '--encoder',
    help=u"指定编码器"
)

parser.add_argument(
    '-i',
    '--infile',
    help=u"指定输入文件",
    default=sys.stdin,
    type=file
)

parser.add_argument(
    '-r',
    '--run',
    help=u"运行输出",
    action='store_true'
)

def main(args):
    tty    = args.output.isatty()

    if args.infile.isatty() and not args.lines:
        parser.print_usage()
        sys.exit(1)

    data   = '\n'.join(args.lines) or args.infile.read()
    output = asm(data.replace(';', '\n'))
    fmt    = args.format or ('hex' if tty else 'raw')
    formatters = {'r':str, 'h':enhex, 's':repr}

    if args.avoid:
        output = encode(output, args.avoid)

    if args.debug:
        proc = gdb.debug_shellcode(output, arch=context.arch)
        proc.interactive()
        sys.exit(0)

    if args.run:
        proc = run_shellcode(output)
        proc.interactive()
        sys.exit(0)

    if fmt[0] == 'e':
        args.output.write(make_elf(output))
        try: os.fchmod(args.output.fileno(), 0700)
        except OSError: pass
    else:
        args.output.write(formatters[fmt[0]](output))

    if tty and fmt is not 'raw':
        args.output.write('\n')

if __name__ == '__main__':
    pwnlib.commandline.common.main(__file__)
