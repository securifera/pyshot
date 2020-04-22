# Author: b0yd @rwincey
# Website: securifera.com
#
# Setup:
# -------------------------------------------------
# Install Selenium
# - pip install selenium
# Chrome dependencies
# - apt install fonts-liberation libgbm1 libappindicator3-1
#
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
# Usage:
# -------------------------------------------------
# python3 pyshot.py -u 172.217.12.78 -p 80
# python3 pyshot.py -u securifera.com -p 443 --secure
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
import filecmp
from selenium import webdriver
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from selenium.common.exceptions import TimeoutException

def get_ssl_subject_name(origin, log):

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
                    return ssl_info['subjectName']
    except:
        pass

def navigate_to_url( driver, url, host ):

    ret_host = None
    print(url)
    try:
        driver.get(url)
    except Exception as e:
        print(e)
        pass

    origin = driver.current_url
    ssl_subj_name = get_ssl_subject_name(origin, driver.get_log('performance'))
    if ssl_subj_name and host != ssl_subj_name and "*." not in ssl_subj_name:
        print("Certificate Host Mismatch: %s %s" % ( host, ssl_subj_name ))
        ret_host = ssl_subj_name

    return ret_host

def take_screenshot( host, port_arg, query_arg="", dest_dir="", secure=False, port_id=None ):

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

    driver = webdriver.Chrome('chromedriver', chrome_options=options, desired_capabilities=caps)
    driver.set_window_size(1024, 768) # set the window size that you need
    driver.set_page_load_timeout(10)
    source = None

    port = ""
    if port_arg:
        port = ":" + port_arg

    #Add query if it exists
    path = host + port
    if query_arg:
        path += "/" + query_arg

    #Get the right URL
    if secure == False:
      url = "http://" + path
    else:
      url = "https://" + path

    #Retrieve the page
    ret_err = False

    #Enable network tracking
    driver.execute_cdp_cmd('Network.enable', {'maxTotalBufferSize': 1000000, 'maxResourceBufferSize': 1000000, 'maxPostDataSize': 1000000})

    if len(dest_dir) > 0:
      dest_dir = dest_dir + os.path.sep

    #Goto page
    ret_host = navigate_to_url(driver, url, host)
    try:

        if driver.page_source == empty_page:
            ret_err = True
            print("[-] Empty page")

        filename1 = None
        if ret_err == False:
            #Cleanup filename and save
            filename = ''
            if port_id:
                filename += port_id + "@"
            #Remove characters that will make save fail
            filename += url.replace('://', '_').replace(':',"_")
            filename1 = dest_dir + filename + ".png"
            driver.save_screenshot(filename1)

        filename2 = None
        #If the SSL certificate references a different hostname
        if ret_host:

            #Replace any wildcards in the certificate
            ret_host = ret_host.replace("*.", "")
            url = "https://" + ret_host + port

            navigate_to_url(driver, url, ret_host)
            if driver.page_source != empty_page:
                filename = ''
                if port_id:
                    filename += port_id + "@"
                #Remove characters that will make save fail
                filename += url.replace('://', '_').replace(':',"_")
                filename2 = dest_dir + filename + ".png"
                driver.save_screenshot(filename2)
            else:
                print("[-] Empty page")

        if filename1 and filename2:
           file_match = filecmp.cmp(filename1,filename2)
           if file_match:
               print("[-] Removing duplicate screenshot %s" % (filename2))
               os.remove(filename2)

    except Exception as e:
        print(e)
        pass
    finally:
        source = driver.page_source
        driver.close()
        driver.quit()

    if ret_err == True:
        sys.exit(1)

    return source


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Screenshot a website.')
    parser.add_argument('-u', dest='host', help='Domain Name or IP', required=True)
    parser.add_argument('-q', dest='query', help='URL Query', required=False)
    parser.add_argument('-p', dest='port', help='Port', required=False)
    parser.add_argument('--secure', help='HTTPS', action='store_true')
    args = parser.parse_args()

    secure_flag=False
    if args.secure == True:
      secure_flag = True

    take_screenshot(args.host, args.port, args.query, secure=secure_flag)


