#!/usr/bin/env python3
# coding: utf-8
import time
from netmiko import ConnectHandler
import paramiko
import config


class ParamikoConnection:
    # 初始化连接创建Transport通道
    def __init__(self, host='xxx.xxx.xxx.xxx', port=22, user='xxx', pwd='xxxxx', timeout=10):
        self.host = host
        self.port = port
        self.user = user
        self.pwd = pwd
        self.timeout = timeout
        self._net_connect = None
        self._ssh = None
        self._chan = None
        self._stdin = None
        self._stdout = None
        self._stderr = None
        self.get_pty = True
        self.bufsize = 8128
        self.environment = {"COSIGN_PASSWORD": "1234qwer"}

        self.__transport = paramiko.Transport((self.host, self.port))
        self.__transport.connect(username=self.user, password=self.pwd)
        self.sftp = paramiko.SFTPClient.from_transport(self.__transport)

    @property
    def ssh(self) -> paramiko.SSHClient:
        if not self._ssh:
            self._ssh = paramiko.SSHClient()
            self._ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy)
            self._ssh.connect(hostname=self.host, port=self.port, username=self.user, password=self.pwd)
        return self._ssh

    @property
    def shell(self) -> paramiko.Channel:
        # self._chan = None
        # print(f'{self._chan}')
        # print(f'{self._chan.closed if self._chan else ""}')

        if not self._chan or self._chan.closed:
            self._stdin = None
            self._stdout = None
            self._stderr = None
            print('shell init')
            # self._chan = self.ssh.invoke_shell()
            chan = self.ssh._transport.open_session(timeout=self.timeout)
            # if get_pty:
            #     chan.get_pty()
            chan.settimeout(self.timeout)
            if self.environment:
                chan.update_environment(self.environment)
            self._chan = chan
            # self._chan.get_pty(
            #     term="vt100",
            #     width=80,
            #     height=24,
            #     width_pixels=0,
            #     height_pixels=0, )
            # self._chan.settimeout(self.timeout)
            # if self.environment:
            #     self._chan.update_environment(self.environment)
        return self._chan

    @property
    def stdin(self):
        if not self._stdin:
            self._stdin = self.shell.makefile_stdin("wb", self.bufsize)
        return self._stdin

    @property
    def stdout(self):
        if not self._stdout:
            self._stdout = self.shell.makefile("r", self.bufsize)
        return self._stdout

    @property
    def stderr(self):
        if not self._stderr:
            self._stderr = self.shell.makefile_stderr("r", self.bufsize)
        return self._stderr

    @property
    def net_connect(self):
        if not self._net_connect:
            self._net_connect = ConnectHandler(**{
                'device_type': 'linux',
                'host': self.host,
                'username': self.user,
                'password': self.pwd
            })
        return self._net_connect

    # 关闭通道
    def close(self):
        self.sftp.close()
        self.__transport.close()

    # 上传文件到远程主机
    def upload(self, local_path, remote_path):
        self.sftp.put(local_path, remote_path)

    # 从远程主机下载文件到本地
    def download(self, remote_path, local_path):
        self.sftp.get(remote_path, local_path)

    # 在远程主机上创建目录
    def mkdir(self, target_path, mode=0o777):
        self.sftp.mkdir(target_path, mode)

    # 删除远程主机上的目录
    def rmdir(self, target_path):
        self.sftp.rmdir(target_path)

    # 查看目录下文件以及子目录（如果需要更加细粒度的文件信息建议使用listdir_attr）
    def listdir(self, target_path):
        return self.sftp.listdir(target_path)

    # 删除文件
    def remove(self, target_path):
        self.sftp.remove(target_path)

    # 查看目录下文件以及子目录的详细信息（包含内容和参考os.stat返回一个FSTPAttributes对象，对象的具体属性请用__dict__查看）
    def listdirattr(self, target_path):
        try:
            list = self.sftp.listdir_attr(target_path)
        except BaseException as e:
            print(e)
        return list

    # 获取文件详情
    def stat(self, remote_path):
        return self.sftp.stat(remote_path)

        # SSHClient输入命令远程操作主机

    def cmd(self, command):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy)
        ssh._transport = self.__transport
        stdin, stdout, stderr = ssh.exec_command(command)
        s = stdout.read().decode('utf-8')
        # print(f"cmd result: {s}")
        return s.split('\n')

    def cmd_netmiko(self, command):
        # 找到目前所在视图
        current_view = self.net_connect.find_prompt()
        # 执行命令，返回结果为字符串，赋值给output
        output = self.net_connect.send_command(command)
        # print(f"\n{'v' * 80}\n{current_view} {command}\n{output}\n{'^' * 80}\n")
        return output

    # SSHClient输入命令远程操作主机
    def cmd_debug(self, command):
        # print(f"【cmd】: {command}")
        stdin, stdout, stderr = self.stdin, self.stdout, self.stderr
        stdin.write(command + '\n')
        output = ''
        break_flag = False
        while stdout.readable() or stderr.readable():
            while stdout.readable():
                s = stdout.read(1024).decode('utf-8')
                if not s:
                    break_flag = True
                    break
                break_flag = False
                output += s
            while stderr.readable():
                s = stderr.read().decode('utf-8')
                if not s:
                    break_flag = break_flag and True
                    break
                break_flag = False
                output += s
            if break_flag:
                break
        # print(f"【result】: {output}\n{'=' * 80}end\n\n")
        return output.split('\n')


if __name__ == '__main__':
    ssh = ParamikoConnection(config.SERVER['server_ip'], user=config.SERVER['username'],
                                             pwd=config.SERVER['password'])
    c =  ssh.cmd("cd /home/8101/raw;tcpreplay -t -l0 --duration 10 -i enp3s0f0 interface_add_back_1.pcap interface_add_back_2.pcap")
    print(c)

