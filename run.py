#!/usr/bin/env
import json
import socket
from datetime import datetime
from flask import Flask, request, jsonify, abort, make_response, render_template
import socket, sys, threading, _thread, queue
import time
import re

# server setup
app = Flask(__name__, template_folder='templates')
app.config["DEBUG"] = 0
threshold = 40
char_list = [['$', '{', 'j', 'n', 'd', 'i', ':', 'l', 'd', 'a', 'p', ':'],
             ['$', '{', 'j', 'n', 'd', 'i', ':', 'l', 'd', 'a', 'p', 's', ':'],
             ['$', '{', 'j', 'n', 'd', 'i', ':', 'r', 'm', 'i', ':'],
             ['$', '{', 'j', 'n', 'd', 'i', ':', 'd', 'n', 's', ':'],
             ['$', '{', 'j', 'n', 'd', 'i', ':', 'n', 'i', 's', ':'],
             ['$', '{', 'j', 'n', 'd', 'i', ':', 'i', 'i', 'o', 'p', ':'],
             ['$', '{', 'j', 'n', 'd', 'i', ':', 'c', 'o', 't', 'b', 'a', ':'],
             ['$', '{', 'j', 'n', 'd', 'i', ':', 'n', 'd', 's', ':'],
             ['$', '{', 'j', 'n', 'd', 'i', ':', 'h', 't', 't', 'p', ':']]


#QUEUE
q = queue.Queue()
log = queue.Queue()

#@app.route('/')
#def index():
#    for item in request.headers:
#        q.put({"ip": request.remote_addr, "type": item[0], "value": item[1]})
#    return ""
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def route(path):
    q.put({"ip": request.remote_addr, "type": "URL_PATH", "value": request.url})

    for item in request.headers:
        q.put({"ip": request.remote_addr, "type": item[0], "value": item[1]})
    return ""


def nslookup(domain):
    ip_list = []
    ais = socket.getaddrinfo(domain, 0, 0, 0, 0)
    for result in ais:
        ip_list.append(result[-1][0])
    ip_list = list(set(ip_list))
    return ip_list


def test(item):
    counter = 0
    count = False
    char_counter = 0
    for char_dict in char_list:
        for char in item["value"]:
            if char == char_dict[char_counter]:
                counter = 0
                count = True
                char_counter += 1
            if count:
                counter += 1
            if counter > threshold:
                return
            if char_counter == len(char_dict):
                log.put(item)
                return

def detector():
    while True:
        item = q.get()
        test(item)

def get_url(item):
    return re.findall('\/\/(.*)\/', item["value"])


def logger():
    while True:
        item = log.get()

        # nslookup domain
        url = get_url(item)
        for item in url:
            item = item.replace('${hostName}', 'ubuntu')
            print(item)
            nslookup(item)


        now = datetime.now()
        with open('attack_log.txt', 'a') as file:
            item["timestamp"] = now.isoformat()
            file.write(json.dumps(item)+ '\n')

def main(port, ssl):
    if ssl:
        app.run(host='0.0.0.0', port=port, ssl_context='adhoc')
    else:
        app.run(host='0.0.0.0', port=port)

if __name__ == '__main__':
    _thread.start_new_thread(detector, ( ))
    _thread.start_new_thread(logger, ( ))
    _thread.start_new_thread(main, (80, False))
    _thread.start_new_thread(main, (8080, False))
    _thread.start_new_thread(main, (443, True))

while True:
    time.sleep(10)





