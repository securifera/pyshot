# Author: b0yd @rwincey
# Website: securifera.com
#
#         PhantomJS code pulled from webscreenshot 
#         Thomas Debize <tdebize at mail.com>
#         https://github.com/maaaaz/webscreenshot
#
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
import json
import random
import string

class ScreenshotError(Exception):
    def __init__(self, message):
        super().__init__(message)

class SslSniException(Exception):
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
            elif retval == 6:
                raise SslSniException(msg)
            else:
                msg = "[-] PhantomJS failed. error code: '0x%x'" % (retval)

            raise ScreenshotError(msg)
        else:
            return

    except OSError as e:
        if e.errno and e.errno == errno.ENOENT :
            raise ScreenshotError('[-] PhantomJS binary could not be found. Ensure it is in your PATH.')


def phantomjs_screenshot(url, host_str, output_filename, file_ext):

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
    cmd_parameters.append('output_file_prefix=%s' % output_filename)

    #cmd_parameters.append('header="Cookie: %s"' % options.cookie.rstrip(';')) if options.cookie != None else None

    cmd_parameters.append('width=%d' % 1200)
    cmd_parameters.append('height=%d' % 800)

    cmd_parameters.append('format=%s' % file_ext)
    cmd_parameters.append('quality=%d' % 10)

    # Not exactly a timeout and more static delay until script completes
    cmd_parameters.append('ajaxtimeout=%d' % 4000)
    cmd_parameters.append('maxtimeout=%d' % 5000)

    cmd_parameters.append('header=Host: %s' % host_str)
    cmd_parameters.append('header=Referer: ')

    #print(cmd_parameters)
    return shell_exec(url, cmd_parameters)

def get_file_prefix(dest_dir):


    letters = string.ascii_lowercase + string.digits
    ret_filename = dest_dir
    ret_filename += ''.join(random.choice(letters) for i in range(32))

    return ret_filename


def take_screenshot( host, port_arg, query_arg="", dest_dir="", image_format="jpg", secure=False, port_id=None, output_file=None, domain=None ):


    ret_msg = ""
    port = ""
    if port_arg:
        port = ":" + port_arg

    #Add query if it exists
    full_path = host + port

    path = "/"
    if query_arg:
        path += "/" + query_arg

    full_path += path
    #Get the right URL
    #print(path)
    if secure == False:
        url = "http://" + full_path
    else:
        url = "https://" + full_path

    if len(dest_dir) > 0:
        dest_dir = dest_dir + os.path.sep

    if output_file is None:
        output_file = get_file_prefix(dest_dir)


    screenshot_info = { 'ip' : host, 
                'port' : port_arg,
                'port_id' : port_id,
                'secure': secure,
                'url' : url,
                'path' : path,
                'file_path': None,
                'domain': None,
                'status_code': None }

    #print("Domain: %s" % domain)
    host_hdr = host
    if domain:
        #Replace any wildcards in the certificate
        domain = domain.replace("*.", "")
        host_hdr = domain
        screenshot_info['domain'] = domain
    

    screenshot_metadata_file = ''
    if dest_dir:
        screenshot_metadata_file = dest_dir
    screenshot_metadata_file += 'screenshots.meta'

    #print(url)
    phantomjs_screenshot(url, host_hdr, output_file, image_format)

    output_file_json = output_file + ".json"
    if os.path.exists(output_file_json):
        f = open(output_file_json)
        data = f.read()
        f.close()

        # Add status code
        json_data = json.loads(data)
        status_code = json_data['status_code']
        screenshot_info['status_code'] = status_code
        screenshot_info['file_path'] = output_file + "." + image_format       

    else:
        print("[-] Screenshot failed.")

    
    f = open(screenshot_metadata_file, 'a+')
    f.write(json.dumps(screenshot_info) + "\n")
    f.close()

    #print(url)
    try:
        phantomjs_screenshot(url, host_hdr, output_file, image_format)
    except SslSniException as e:
        url = url.replace(host, host_hdr)
        phantomjs_screenshot(url, host_hdr, output_file, image_format)

    return

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Screenshot a website.')
    parser.add_argument('-u', dest='host', help='Domain Name or IP', required=False)
    parser.add_argument('-q', dest='query', help='URL Query', required=False)
    parser.add_argument('-p', dest='port', help='Port', required=False)
    parser.add_argument('-o', dest='output_file', help='Output File', required=False)
    parser.add_argument('-f', dest='image_format', help='Image Format', default='jpg', required=False)
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
            take_screenshot(host, args.port, args.query, secure=secure_flag, domain=args.host_hdr, image_format=args.image_format, output_file=args.output_file)
        except Exception as e:
            print(traceback.format_exc())
            pass

