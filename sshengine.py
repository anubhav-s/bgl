# coding: utf-8
"""
# ==============================================================================
# Name:             ssh_engine
#
# Purpose:          to deliver a ssh connection to a certain device
#
#
# Author:           ANUSE
# Created:          27/03/2015
# Copyright:        (c) Barco 2015
# Licence:          All Rights Reserved
# ==============================================================================
# Extra used pypi modules which may need to be installed:
#
# ==============================================================================
"""

import logging
import re
import socket
import time

import paramiko
import scp
from paramiko import SSHException

from ..configurator.configurator_helper import ssh_credentials

KEEP_ALIVE_INTERVAL = 2.5 * 60
CHANNEL_TIME_OUT = 60


class SshEngine(object):
    def __init__(self, ssh_con, hostname, username, password, model):
        self.ssh_con = ssh_con
        self.address = hostname
        self.username = username
        self.password = password
        self.logger = logging.getLogger("ssh")
        self.model = model
        self.session = None

    @staticmethod
    def __protocol__():
        """
        returns the protocol used
        :return: string
        """
        return "ssh"

    def __str__(self):
        """
        :return: string representation
        """
        return "ssh engine with parameters %s, %s, %s" % (self.address, self.username, self.password)

    def __re_init__(self):
        """
        re initializes the engine
        """
        self.logger.info('sleeping for 1 second to reinit')
        time.sleep(1)
        new_eng = make_ssh_engine(self.address, self.model)
        self.ssh_con = new_eng.ssh_con
        self.username = new_eng.username
        self.password = new_eng.password
        self.session = None

    def get_ssh_connection(self):
        return self.ssh_con

    def do_ssh_command(self, command, time_out=10, wait_for_channel_time_out=True):
        """
        warning doesn't return an error
        :param command:
        :param time_out:
        :param wait_for_channel_time_out:
        :return:
        """
        retval = None
        self.logger.info("running '%s' %s %s %s", command, self.username, self.password, self.address)
        retry = 0
        session = None
        while time_out >= 0 and session is None:
            try:
                session = self.ssh_con.get_transport().open_session()
                retval = ""
            except (socket.error, paramiko.AuthenticationException, paramiko.SSHException) as excep:
                self.logger.error("Exception caught after opening session: %s - %s, re-initialize the engine",
                                  str(type(excep)), excep.message)
                self.__re_init__()
                session = self.ssh_con.get_transport().open_session()
            except Exception as excep:
                # TODO JEFNE narrow exception type socket error/ timeout
                self.logger.error("exception caught of type %s after opening session", str(type(excep)))
                self.logger.error("maybe a reboot was done, will reinitiate session object")
                self.ssh_con = create_ssh_session_obj_from_hostname(self.address, self.username, self.password)
                self.logger.info("ssh_con object recreated")
                session = self.ssh_con.get_transport().open_session()
                self.logger.info("calling ls /bin/ to check if ssh is open")
                time.sleep(1)
                if self.do_ssh_command("ls /bin/").strip() is "":
                    retry += 1
                    if retry > 5:
                        raise paramiko.SSHException("Probably the unit is switched off or rebooting")
                else:
                    break
                retval = ""
            time_out -= 1
        time.sleep(1)
        self.logger.debug("now executing %s" % command)
        session.exec_command(command)
        time.sleep(1)
        while (session.recv_ready() or session.recv_stderr_ready()) and time_out:
            if session.recv_ready():
                line = session.recv(4096).decode('utf-8')
                self.logger.debug("received: %s" % line)
                if retval is None:
                    retval = line
                else:
                    retval += line
            if session.recv_stderr_ready():
                error = session.recv_stderr(4096).decode('utf-8')
                if retval is None:
                    retval = ""
                retval += error
                # TODO research below
                if "unconditionally" not in error:
                    self.logger.error(error)
                    retval += error
            # ready to exit but reading pending
            if session.exit_status_ready() and not session.recv_ready():
                self.logger.debug("exit status: %s", session.recv_exit_status())
                break
            if not wait_for_channel_time_out:
                self.logger.debug("exiting because of wait_for_channel_time_out is False.")
                break
            time.sleep(2)
            time_out -= 1
        self.logger.info("returning %s", retval)
        return retval

    def do_quick_command(self, command):
        """
        runs a quick command
        """
        retval = ""
        try:
            self.logger.debug("executing %s" % command)
            _, stdout, stderr = self.ssh_con.exec_command(command)
        except (socket.error, paramiko.AuthenticationException, paramiko.SSHException) as excep:
            self.logger.error("Exception caught after opening session: %s - %s, re-initialize the engine",
                              str(type(excep)), excep.message)
            self.__re_init__()
            _, stdout, stderr = self.ssh_con.exec_command(command)
        except Exception as excep:
            self.logger.error("do_quick_command: caught exception type %s, message %s", str(type(excep)), excep.message)
            self.ssh_con = create_ssh_session_obj_from_hostname(self.address, self.username, self.password)
            _, stdout, stderr = self.ssh_con.exec_command(command)

        retval += str(stdout.read())
        if stderr:
            retval += str(stderr.read())
        self.logger.info(retval)
        return retval

    def do_webui_helper_command(self, command, params):
        """
        :param command: the cmd that needs to be executed by WebUIHelper(getParameterValue, setParameterValue, commit)
        :param params: which params need to be set or gotten with what value
        :return: the output of the WebUIHelper
        """
        ret_val = self.do_quick_command("/usr/sbin/WebUIHelper command=%s %s" % (command, params))
        if "Could not get owner of name 'com.barco.ClickShare.CentralStore'" in ret_val:
            raise Exception("CentralStore is not running received %s" % ret_val)
        # removing debug strings => no need to do more logging
        ret_val = "".join([elem for elem in ret_val.split("\n") if re.search("^\[(ERR|DEBUG)\].*", elem) is None])
        return ret_val

    def set_parameter(self, param, value):
        """
        sets a central store parameter via webuihelper/ssh
        :param param: which parameter needs to be set
        :param value: to which value
        :return:
        """
        self.logger.debug("using " + self.password + " on " + self.address)
        if type(param) == list and type(value) == list:
            self.logger.debug("a list of commands is detected %s", str(param))
            for param_item, value_item in list(zip(param, value)):
                params = "name=%s value='%s'" % (param_item, str(value_item))
                self.logger.info(self.do_webui_helper_command("setParameterValue", params))
        else:
            value = str(value)
            params = "name=%s value='%s'" % (param, value)
            ret_val = self.do_webui_helper_command("setParameterValue", params)
            self.logger.info(ret_val)

            if "Could not get owner of name 'com.barco.ClickShare.CentralStore'" in ret_val:
                raise Exception("CentralStore is not running received %s" % ret_val)
        ret_val = self.do_webui_helper_command("commit", "")
        self.logger.debug(ret_val)

    def get_parameter(self, param):
        """
        gets a central store parameter via webuihelper/ssh
        :param param: which parameter to get
        :return: the value retrieved from the device
        """
        params = "name=" + param
        ret_val = self.do_webui_helper_command("getParameterValue", params)
        if ret_val.find("[DEBUG] webuihelper triggered") >= 0:
            ret_val = ret_val[:ret_val.find("[DEBUG]")]
        if ret_val == 'true':
            self.logger.info("converting 'true' to True")
            return True
        if ret_val == "false":
            self.logger.info("converting 'false' to False")
            return False
        if ret_val.isdigit():
            self.logger.info("converting '%s' to %s", ret_val, ret_val)
            return int(ret_val)
        if ret_val.replace(".", "", 1).isdigit():
            self.logger.info("converting '%s' to %s", ret_val, ret_val)
            return float(ret_val)
        return ret_val

    def put_files_via_scp(self, source, destination):
        """
        sends a file via scp to a server
        :param source:
        :param destination:
        :return:
        """
        try:
            self.logger.info("putting %s to %s", source, destination)
            scp_conn = scp.SCPClient(self.ssh_con.get_transport(), buff_size=16384, socket_timeout=30.0, progress=None)
            scp_conn.put(source, destination, recursive=True, preserve_times=False)
        except (socket.error, paramiko.AuthenticationException, paramiko.SSHException, scp.SCPException) as excep:
            self.logger.error("Exception caught after opening session: %s - %s, re-initialize the engine",
                              str(type(excep)), excep.message)
            self.__re_init__()
            self.logger.info("putting %s to %s", source, destination)
            scp_conn = scp.SCPClient(self.ssh_con.get_transport(), buff_size=16384, socket_timeout=30.0, progress=None)
            scp_conn.put(source, destination, recursive=True, preserve_times=False)

    def get_files_via_scp(self, remote_path, local_path):
        """
        receives files via scp
        :param remote_path:
        :param local_path:
        :return:
        """
        try:
            self.logger.info("getting from %s to %s", remote_path, local_path)
            scp_conn = scp.SCPClient(self.ssh_con.get_transport(), buff_size=16384, socket_timeout=30.0, progress=None)
            scp_conn.get(remote_path, local_path, recursive=True)
        except (socket.error, paramiko.AuthenticationException, paramiko.SSHException, scp.SCPException) as excep:
            self.logger.error("Exception caught after opening session: %s - %s, re-initialize the engine",
                              str(type(excep)), excep.message)
            self.__re_init__()
            self.logger.info("getting from %s to %s", remote_path, local_path)
            scp_conn = scp.SCPClient(self.ssh_con.get_transport(), buff_size=16384, socket_timeout=30.0, progress=None)
            scp_conn.get(remote_path, local_path, recursive=True)


def create_ssh_session_obj_from_hostname(hostname, username, password, retry=3):
    """
    initiates the ssh_con property
    :param hostname: the hostname of the device you want to connect to
    :param username: the username of the user to log in to via ssh (THIS CAN'T BE EMPTY)
    :param password: the password for the username (if empty set empty string)
    :return: a transport (paramiko)
    """
    ssh_con = None
    try:
        ssh_con = paramiko.SSHClient()
        ssh_con.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        logging.getLogger("ssh").info("creating ssh session %s %s %s", username, password, hostname)
        ssh_con.connect(hostname, username=username, password=password, timeout=10)
    except paramiko.AuthenticationException:
        raise
    except Exception as excep:
        if retry > 0:
            logging.getLogger("ssh").error("caught %s will retry %s time" % (excep, retry))
            retry -= 1
            time.sleep(1)
            ssh_con = create_ssh_session_obj_from_hostname(hostname, username, password, retry)
    return ssh_con


def make_ssh_engine(address, modelname):
    """
    creates an SSH engine object depending on host and modelname
    :param address: IP or hostname as a string
    :param modelname: MODELNAME
    :return:
    """
    creds = ssh_credentials[modelname]
    assert len(creds.passwords) > 0
    for password in creds.passwords:
        try:
            ssh_client = create_ssh_session_obj_from_hostname(address, creds.username, password)
            if ssh_client.get_transport() is None or ssh_client is None:
                raise SSHException()
            logging.getLogger("ssh").info(ssh_client)
            return SshEngine(ssh_client, address, creds.username, password, modelname)
        except paramiko.AuthenticationException:
            logging.getLogger("ssh").info("wrong password for %s with %s and %s will fallback to another one",
                                          address, creds.username, password)
    raise Exception("Not able to log in with " + str(creds) + " on " + address)


def get_interactive_shell_session(address, machine_name):
    """
    Start an interactive shell session on the SSH server.  A new `.Channel`
    is opened and connected to a pseudo-terminal using the requested
    terminal type and size.
    :param address: IP or hostname as a string
    :param machine_name: UP Test machine name
    :return:
    """
    sshcon_server = make_ssh_engine(address, machine_name)
    sshcon_obj = getattr(sshcon_server, 'ssh_con')
    interactive_shell_session = getattr(sshcon_server, 'ssh_con').invoke_shell()
    return sshcon_obj, interactive_shell_session
