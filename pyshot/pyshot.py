# Author: b0yd @rwincey
# Website: securifera.com
#
#         PhantomJS code pulled from webscreenshot 
#         Thomas Debize <tdebize at mail.com>
#         https://github.com/maaaaz/webscreenshot
#
#         Duplicate file removal snippet pulled from 
#         https://stackoverflow.com/questions/748675/finding-duplicate-files-and-removing-them
#
# Setup:
# -------------------------------------------------
# PhantomJS dependencies
# - apt install openssl
#
# Download phantomJS
# - wget https://bitbucket.org/ariya/phantomjs/downloads/phantomjs-2.1.1-linux-x86_64.tar.bz2
#     or
# - wget https://bitbucket.org/ariya/phantomjs/downloads/phantomjs-2.1.1-windows.zip
#
# Move the phantomJS to a directory in the PATH env var
# - move phantomjs.exe C:\\Windows\\System32
#
# Usage:
# -------------------------------------------------
# python3 pyshot.py -u 172.217.12.78 -p 80
# 
#
# Troubleshooting
# -------------------------------------------------
# Error: TypeError: urlopen() got multiple values for keyword argument 'body'
#
# Solution: pip install --upgrade --ignore-installed urllib3
#

import argparse
import sys
import os
import time
import errno
import subprocess
import datetime
import signal
import glob
import traceback

import hashlib
from collections import defaultdict

class ScreenshotError(Exception):
    def __init__(self, message):
        super().__init__(message)

def shell_exec(url, cmd_arr):

    SHELL_EXECUTION_OK = 0
    PHANTOMJS_HTTP_AUTH_ERROR_CODE = 2

    timeout = 15
    start = datetime.datetime.now()
    is_windows = "win32" in sys.platform.lower()

    #print(cmd_arr)
    try :

        if is_windows:
            p = subprocess.Popen(cmd_arr, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:
            my_env = os.environ.copy()
            my_env["OPENSSL_CONF"] = "/etc/ssl/"
            p = subprocess.Popen(cmd_arr, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=my_env)

        # binaries timeout
        stdout = []
        stderr = []
        mix = []
        while p.poll() is None:

            line = p.stdout.read().decode()
            if line != "":
                stdout.append(line)
                mix.append(line)
                print(line, end='')

            line = p.stderr.read().decode()
            if line != "":
                stderr.append(line)
                mix.append(line)
                print(line, end='')

            time.sleep(0.1)
            now = datetime.datetime.now()
            if (now - start).seconds > timeout:
                p.stdout.close()
                p.stderr.close()

                if is_windows:
                    p.send_signal(signal.SIGTERM)
                else:
                    p.send_signal(signal.SIGKILL)

                raise ScreenshotError('[-] PhantomJS job reached timeout. Killing process.')

        retval = p.poll()
        p.stdout.close()
        p.stderr.close()

        if retval != SHELL_EXECUTION_OK:
            msg = ""
            if retval == PHANTOMJS_HTTP_AUTH_ERROR_CODE:
                msg = "[-] HTTP Authentication requested."
            else:
                msg = "[-] PhantomJS failed. error code: '0x%x'" % (retval)

            raise ScreenshotError(msg)
        else:
            return

    except OSError as e:
        if e.errno and e.errno == errno.ENOENT :
            raise ScreenshotError('[-] PhantomJS binary could not be found. Ensure it is in your PATH.')


    except Exception as err:
        raise ScreenshotError('[-] Failed. Error: %s' % err)


def phantomjs_screenshot(url, host_str, output_filename):

    WEBSCREENSHOT_JS = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), './webscreenshot.js'))
    final_bin = []
    final_bin.append('phantomjs')
    bin_path = " ".join(final_bin)

    cmd_parameters = [ bin_path,
                       '--ignore-ssl-errors=true',
                       #'--ssl-protocol=any', #Removed because it was breaking the windows version
                       '--ssl-ciphers=ALL' ]

    #if proxy:
    proxy = '127.0.0.1:8080'
    #cmd_parameters.append("--proxy=%s" % proxy)
    #cmd_parameters.append("--proxy-type=%s" % 'socks4')
    #cmd_parameters.append("--proxy-type=%s" % 'http')

    cmd_parameters.append(WEBSCREENSHOT_JS)
    cmd_parameters.append('url_capture=%s' % url)
    cmd_parameters.append('output_file=%s' % output_filename)

    #cmd_parameters.append('header="Cookie: %s"' % options.cookie.rstrip(';')) if options.cookie != None else None

    cmd_parameters.append('width=%d' % 1200)
    cmd_parameters.append('height=%d' % 800)

    cmd_parameters.append('format=%s' % 'png')
    cmd_parameters.append('quality=%d' % 75)

    # Not exactly a timeout and more static delay until script completes
    cmd_parameters.append('ajaxtimeout=%d' % 4000)
    cmd_parameters.append('maxtimeout=%d' % 5000)

    cmd_parameters.append('header=Host: %s' % host_str)
    cmd_parameters.append('header=Referer: ')

    #print(cmd_parameters)
    return shell_exec(url, cmd_parameters)

def take_screenshot( host, port_arg, query_arg="", dest_dir="", secure=False, port_id=None, domain=None ):

    ret_msg = ""
    port = ""
    if port_arg:
        port = ":" + port_arg

    #Add query if it exists
    path = host + port
    if query_arg:
        path += "/" + query_arg

    #Get the right URL
    #print(path)
    if secure == False:
        url = "http://" + path
    else:
        url = "https://" + path

    if len(dest_dir) > 0:
      dest_dir = dest_dir + os.path.sep

    #Setup filename
    filename = ''
    if port_id:
        filename += port_id + "@"

    #Remove characters that will make save fail
    filename += url.replace('://', '-').replace(':','-').replace('/','-').replace('\\','-')

    #print("Domain: %s" % domain)
    ret = False
    if domain:
        #Replace any wildcards in the certificate
        domain = domain.replace("*.", "")
        url = "https://" + host + ":443"

        #Add domain
        tmp_str = filename
        if domain != host:
            tmp_str += "_" + domain
        filename1 = dest_dir + tmp_str + ".png"
        host = domain
    else:
        #Cleanup filename and save
        filename1 = dest_dir + filename + ".png"


    ret = phantomjs_screenshot(url, host, filename1)

    return

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Screenshot a website.')
    parser.add_argument('-u', dest='host', help='Domain Name or IP', required=False)
    parser.add_argument('-q', dest='query', help='URL Query', required=False)
    parser.add_argument('-p', dest='port', help='Port', required=False)
    parser.add_argument('-d', dest='host_hdr', help='Host Header Value')
    parser.add_argument('-x', dest='proxy', help='Proxy')
    parser.add_argument('-l', dest='host_file', help='Host - Line Delimited File')
    parser.add_argument('--secure', help='HTTPS', action='store_true')
    args = parser.parse_args()

    if args.host == None and args.host_file == None:
        print("[-] Error: Host or File Path Required")
        sys.exit(1)


    secure_flag=False
    if args.secure == True:
        secure_flag = True

    host_list = []
    if args.host_file:
        f = open(args.host_file, "rb")
        lines = f.readlines()
        f.close()

        for line in lines:
            try:
                host = line.strip().decode('utf-8')
                host_list.append(host)
            except Exception as e:
                print(e)
                pass
    else:
        host_list.append(args.host)

    for host in host_list:
        try:
            take_screenshot(host, args.port, args.query, secure=secure_flag, domain=args.host_hdr)
        except Exception as e:
            print(traceback.format_exc())
            pass

