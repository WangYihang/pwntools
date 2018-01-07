#!/usr/bin/env python
# encoding:utf-8

"""
实现了将 flag 提交到 flag 服务器的函数
"""
from __future__ import absolute_import

import os

from pwnlib.args import args
from pwnlib.log import getLogger
from pwnlib.tubes.remote import remote

env_server  = args.get('FLAG_HOST', 'flag-submission-server').strip()
env_port    = args.get('FLAG_PORT', '31337').strip()
env_proto   = args.get('FLAG_PROTO', 'tcp').strip()
env_file    = args.get('FLAG_FILE', '/does/not/exist').strip()
env_exploit_name = args.get('EXPLOIT_NAME', 'unnamed-exploit').strip()
env_target_host  = args.get('TARGET_HOST', 'unknown-target').strip()
env_team_name    = args.get('TEAM_NAME', 'unknown-team').strip()

log = getLogger(__name__)

def submit_flag(flag,
                exploit=env_exploit_name,
                target=env_target_host,
                server=env_server,
                port=env_port,
                proto=env_proto,
                team=env_team_name):
    """
    向比赛服务器提交 flag

    Arguments:
        flag(str): 需要被提交的 flag.
        exploit(str): Exploit ID, 可选
        target(str): 目标ID, 可选
        server(str): Flag 服务器的地址(主机名), 可选
        port(int): Flag 服务器的端口, 可选
        proto(str), Flag 服务器的协议, 可选

    可选参数会从环境变量中获得, 或者会被排除在外

    Returns:
        一个字符串表示提交的结果或者返回一个错误代码

    Doctest:

        >>> l = listen()
        >>> _ = submit_flag('flag', server='localhost', port=l.lport)
        >>> c = l.wait_for_connection()
        >>> c.recvall().split()
        ['flag', 'unnamed-exploit', 'unknown-target', 'unknown-team']
    """
    flag = flag.strip()

    log.success("Flag: %r" % flag)

    data = "\n".join([flag,
                      exploit,
                      target,
                      team,
                      ''])

    if os.path.exists(env_file):
        write(env_file, data)
        return

    try:
        with remote(server, int(port)) as r:
            r.send(data)
            return r.recvall(timeout=1)
    except Exception:
        log.warn("Could not submit flag %r to %s:%s" % (flag, server, port))
