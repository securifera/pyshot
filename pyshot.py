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
# Install Selenium
# - pip install selenium
# Chrome dependencies
# - apt install fonts-liberation libgbm1 libappindicator3-1
# PhantomJS dependencies
# - apt install openssl
# Download latest google chrome & install
# - wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
# - dpkg -i ./google-chrome-stable_current_amd64.deb
#
# Identify google version
# - ./google-chrome-stable --version 
#
# Vist http://chromedriver.chromium.org/downloads to identity the right version of driver
#
# Use wget to download the right version
# - wget https://chromedriver.storage.googleapis.com/<version>/chromedriver_linux64.zip
#
# Move the chromedriver to a directory in the PATH env var
# - mv ./chromedriver /usr/bin/
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
import socket
import json
import os
import time
import filecmp
import errno
import subprocess
import datetime
import signal
import glob

import hashlib
from collections import defaultdict

from selenium import webdriver
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from selenium.common.exceptions import TimeoutException

def get_ssl_dns_names(origin, log):

    #Parse through performance logs and attempt to dig out the subject name from the SSL info
    try:
        for entry in log:

            #Get the message
            msg = entry['message']
            inner_msg = json.loads(msg)

            #Get the inner message
            msg = inner_msg['message']
            method = msg['method']
            #Only parse network response msgs
            if method == 'Network.responseReceived':
                data = msg['params']
                #Get response
                response = data['response']
                #Get URL
                url = response['url']
                if origin == url:
                
                    ssl_info = response['securityDetails']
                    subj_name = ssl_info['subjectName']
                    san_list_str = ssl_info['sanList']
                    #print(type(san_list_str))
                    
                    dns_set = set()
                    if "*" not in subj_name:
                        dns_set.add(subj_name)
                        
                    if san_list_str and len(san_list_str) > 0:
                        for san_name in san_list_str:
                            if "*" not in san_name:
                                dns_set.add(san_name)
                                                     
                    return list(dns_set)
    except:
        pass
        
    return None

def navigate_to_url( driver, url, host ):

    ret_host = None
    try:
        driver.get(url)
    except Exception as e:
        print(e)
        pass

    origin = driver.current_url
    ssl_dns_name_arr = get_ssl_dns_names(origin, driver.get_log('performance'))
    if ssl_dns_name_arr and (len(ssl_dns_name_arr) > 1 or host != ssl_dns_name_arr[0]):
        print("[-] Certificate Host Mismatch: %s %s" % ( host, ssl_dns_name_arr ))
        ret_host = ssl_dns_name_arr

    return ret_host

def shell_exec(url, cmd_arr):

    SHELL_EXECUTION_OK = 0
    PHANTOMJS_HTTP_AUTH_ERROR_CODE = 2

    timeout = 60
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
                print("[-] PhantomJS job reached timeout. Killing process.")
                p.stdout.close()
                p.stderr.close()

                if is_windows:
                    p.send_signal(signal.SIGTERM)
                else:
                    p.send_signal(signal.SIGKILL)

                return False
        
        retval = p.poll()
        p.stdout.close()
        p.stderr.close()

        if retval != SHELL_EXECUTION_OK:
            if retval == PHANTOMJS_HTTP_AUTH_ERROR_CODE:
                print("[-] HTTP Authentication requested.")
            else:
                print("[-] PhantomJS failed. error code: '0x%x'" % (retval))                    
            return False        
        else:
            return True
    
    except OSError as e:
        if e.errno and e.errno == errno.ENOENT :
            print('[-] PhantomJS binary could not be found. Ensure it is in your PATH.')
            return False
        
    except Exception as err:
        print('[-] Failed. Error: %s' % err)
        return False

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
    #proxy = '127.0.0.1:8080'
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
    
    cmd_parameters.append('ajaxtimeout=%d' % 2400)
    cmd_parameters.append('maxtimeout=%d' % 3000)
    
    cmd_parameters.append('header=Host: %s' % host_str)
    cmd_parameters.append('header=Referer: ')

    #print(cmd_parameters)
    return shell_exec(url, cmd_parameters)


def chrome_screenshot(url, host, filename1, proxy=None):

    empty_page = '<html><head></head><body></body></html>'
    caps = DesiredCapabilities.CHROME
    caps['loggingPrefs'] = {'performance': 'ALL'}      # Works prior to chrome 75
    caps['goog:loggingPrefs'] = {'performance': 'ALL'} # Updated in chrome 75
    options = webdriver.ChromeOptions()
    if os.name == 'nt':
        options.binary_location = 'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe'
    else:
        options.binary_location = '/usr/bin/google-chrome-stable'

    options.add_argument('--headless')
    options.add_argument('--disable-gpu')
    options.add_argument('--hide-scrollbars')
    options.add_argument('--disable-crash-reporter')
    options.add_argument('--ignore-certificate-errors')
    options.add_argument('--no-sandbox')
    options.add_argument('--user-agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.50 Safari/537.36"')
    
    if proxy:
        #print("Proxy: %s" % proxy)
        options.add_argument('--proxy-server=socks4://' + proxy);

    #Retrieve the page
    ret_err = False
    driver = webdriver.Chrome('chromedriver', options=options, desired_capabilities=caps)
    try:
        driver.set_window_size(1024, 768) # set the window size that you need
        driver.set_page_load_timeout(10)
        source = None

        #Enable network tracking
        driver.execute_cdp_cmd('Network.enable', {'maxTotalBufferSize': 1000000, 'maxResourceBufferSize': 1000000, 'maxPostDataSize': 1000000})

        #Goto page
        ret_host = navigate_to_url(driver, url, host)
        if driver.page_source == empty_page:
            ret_err = True
            print("[-] Empty page")

        if ret_err == False:
            #Save the screenshot
            driver.save_screenshot(filename1)


    except Exception as e:
        print(e)
        pass

    finally:
        driver.close()
        driver.quit()

    return ret_host

def take_screenshot( host, port_arg, query_arg="", dest_dir="", secure=False, port_id=None, domain=None, socks4_proxy=None ):

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
    filename += url.replace('://', '_').replace(':',"_")

    #If the SSL certificate references a different hostname
    #print("Domain: %s" % domain)
    ret = False
    if domain and socks4_proxy == None:

        #Replace any wildcards in the certificate
        domain = domain.replace("*.", "")
        url = "https://" + host + ":443"

        #Add domain 
        tmp_str = filename
        if domain != host:
            tmp_str += "_" + domain
        filename2 = dest_dir + tmp_str + ".png"

        ret = phantomjs_screenshot(url, domain, filename2)

    #if ret == False:
    else:
        #Cleanup filename and save
        filename1 = dest_dir + filename + ".png"
        ret_host_arr = chrome_screenshot(url, host, filename1, socks4_proxy)

        #If the SSL certificate references a different hostname
        if ret_host_arr and socks4_proxy == None:

            #Replace any wildcards in the certificate
            for ret_host in ret_host_arr:
                url = "https://" + host + ":443"
                
                #Add domain
                tmp_str = filename
                if ret_host != host:
                    tmp_str += "_" + ret_host
                filename2 = dest_dir + tmp_str + ".png"
                
                ret = phantomjs_screenshot(url, ret_host, filename2)               

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
        take_screenshot(host, args.port, args.query, secure=secure_flag, domain=args.host_hdr, socks4_proxy=args.proxy)


