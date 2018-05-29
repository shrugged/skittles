#!/usr/bin/env python
# Python 2.7.x - 3.6.x
# LinkFinder
# By Gerben_Javado

# Fix webbrowser bug for MacOS
import os

# Import libraries
import re, sys, glob, cgi, argparse, jsbeautifier, webbrowser, subprocess, base64, ssl, xml.etree.ElementTree
from string import Template 

from urllib2 import Request, urlopen, HTTPError, URLError

from wt_utils import *

# Parse command line
parser = argparse.ArgumentParser()
parser.add_argument("-d", "--domain",
                    help="Input a domain to recursively parse all javascript located in a page")
parser.add_argument("-r", "--regex",
                    help="RegEx for filtering purposes \
                    against found endpoint (e.g. ^/api/)",
                    action="store")
parser.add_argument("-c", "--cookies",
                    help="Add cookies for authenticated JS files",
                    action="store", default="")
args = parser.parse_args()

addition = ("","")

# Regex used
regex = re.compile(r"""

  (%s(?:"|')                            # Start newline delimiter

  (?:
    ((?:[a-zA-Z]{1,10}://|//)           # Match a scheme [a-Z]*1-10 or //
    [^"'/]{1,}\.                        # Match a domainname (any character + dot)
    [a-zA-Z]{2,}[^"']{0,})              # The domainextension and/or path

    |

    ((?:/|\.\./|\./)                    # Start with /,../,./
    [^"'><,;| *()(%%$^/\\\[\]]          # Next character can't be... 
    [^"'><,;|()]{1,})                   # Rest of the characters can't be

    |

    ([a-zA-Z0-9_\-/]{1,}/               # Relative endpoint with /
    [a-zA-Z0-9_\-/]{1,}\.[a-zA-Z]{1,4}  # Rest + extension
    (?:[\?|/][^"|']{0,}|))              # ? mark with parameters

    |

    ([a-zA-Z0-9_\-]{1,}                 # filename
    \.(?:php|asp|aspx|jsp|json)         # . + extension
    (?:\?[^"|']{0,}|))                  # ? mark with parameters
 
  )             
  
  (?:"|')%s)                            # End newline delimiter

""" % addition, re.VERBOSE)

def send_request(url):
    '''
    Send requests with Requests
    '''
    q = Request(url)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    q.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
        AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36')
    q.add_header('Accept', 'text/html,\
        application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8')
    q.add_header('Accept-Language', 'en-US,en;q=0.8')
    q.add_header('Accept-Encoding', '')
    q.add_header('Cookie', args.cookies)

    return urlopen(q, context=ctx, timeout=3).read().decode('utf-8', 'replace')

def parser_file(content):
    '''
    Parse Input
    '''
    
    if len(content) > 1000000:
        content = content.replace(";",";\r\n").replace(",",",\r\n")
    else:
        content = jsbeautifier.beautify(content)
    
    items = re.findall(regex, content)
    items = list(set(items))
        
    # Match Regex
    filtered_items = []

    for item in items:
        # Remove other capture groups from regex results
        group = list(filter(None, item))

        if args.regex:
            if re.search(args.regex, group[1]):
                filtered_items.append(group)
        else:
            filtered_items.append(group)

    return filtered_items

def html_save(report_dir, host, html):
    '''
    Save as HTML file and open in the browser
    '''
    s = Template(open('%s/template.html' % sys.path[0], 'r').read())
    content = s.substitute(content=html).encode('utf8')

    filename = host + ".html"
    f = Path(report_dir, filename)
    print("Report at: %s, ", f)
    f.write_file(content, mode="wb")

def check_url_js(host, url):
    nopelist = ["node_modules", "jquery.js", "js/client.js", "js/rpc.js", "angular.min.js"]
    if url[-3:] == ".js":
        words = url.split("/")
        for word in words:
            if word in nopelist:
                return False
        if url[:2] == "//":
            url = "https:" + url
        if url[:4] != "http":
            if url[:1] == "/" or url[:2] == "./":
                url = host + url
            else:
                url = host + "/" + url
        return url            
    else:
        return False

def link_dump(report_dir, schema, host):
    url = schema + host
    html = ''

    try:
        file = send_request(url)

        endpoints = parser_file(file)
        new_endpoints = ''

        for endpoint in endpoints:
            endpoint = cgi.escape(endpoint[1]).encode('ascii', 'ignore').decode('utf8')
            endpoint = check_url_js(url, endpoint)
            if endpoint is False:
                continue

            print("Running against: " + endpoint)

            file = send_request(endpoint)
            new_endpoints = parser_file(file)
            html += '''
            <h1>File: <a href="%s" target="_blank" rel="nofollow noopener noreferrer">%s</a></h1>
            ''' % (cgi.escape(endpoint), cgi.escape(endpoint))

            for new_endpoint in new_endpoints:
                url = cgi.escape(new_endpoint[1])
                string = "<div><a href='%s' class='text'>%s" % (
                    cgi.escape(url),
                    cgi.escape(url)
                )
                string2 = "</a><div class='container'>%s</div></div>" % cgi.escape(
                    new_endpoint[0]
                )
                string2 = string2.replace(
                    cgi.escape(new_endpoint[1]),
                    "<span style='background-color:yellow'>%s</span>" %
                    cgi.escape(new_endpoint[1])
                )
                html += string + string2

        if len(new_endpoints) > 0:
            html_save(report_dir, host, html)

    except Exception, e:
        print e


def main():
    go_home(args.domain)
    report_dir = setup_report_dir("linkdump")

    hosts = read_hosts("hosts.json")
    #hosts = read_hosts2("subfinder.json")

    print("Using Report Path : %s", report_dir.absolute())
    print("Link Dump for domain: %s", args.domain)
    print("Number(s) of hosts: %d",len(hosts))

    for host in hosts:
        try:
            print("Scanning host: %s", host)

            # test http vs https
            if check_url("https://" + host):
                link_dump(report_dir, "https://", host)
            else:
                if check_url("http://" + host):
                    link_dump(report_dir, "http://", host)
                else:
                    print("Error connecting to host : %s", host)
                    continue

        except KeyboardInterrupt:
            print("CTRL+C detected.")
            print("Options: [e]xit, [c]ontinue, [s]kip target.")
            option = raw_input()
            if option.lower() == 'e':
                sys.exit()
            if option.lower() == 'c':
                print("Starting over.")
            elif option.lower() == 's':
                print("Skipped host %s: ", host)

if __name__ == "__main__":
    main()