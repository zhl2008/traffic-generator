#!/usr/bin/env python2

import Queue
import requests
import os
import json
from copy import deepcopy
import Cookie
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import threading
import sys
from urllib import urlencode

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
domain_name = '192.168.244.101'
#domain_name = 'user.ichunqiu.com'
log_dir = '../proxy/logs'
target_dir = log_dir + '/' + domain_name
q = Queue.Queue()
#fuzz_options = ['get','post','header','cookie']
fuzz_options = ['get','post','header','cookie']
payloads = ['A'*16000]
proxies = {
    'http': 'http://127.0.0.1:8080',
    'https': 'http://127.0.0.1:8080'
}


thread_num = 4
timeout = 5



def read_dir_to_queue():
	if not os.path.isdir(target_dir):
		sys.exit('[!] not a dir')

	for dir in os.walk(target_dir):
		pass
	res = dir[2]
	#print res
	for r in res:
		q.put(r)



def send_query(request_hash):
	#print open(target_dir + '/' + request_hash).read()
	info = json.loads(open(target_dir + '/' + request_hash).read())
	for payload in payloads:
		if 'get' in fuzz_options:
			fuzz_get(payload,info)
		if 'post' in fuzz_options:
			fuzz_post(payload,info)
		if 'header' in fuzz_options:
			fuzz_header(payload,info)
		if 'cookie' in fuzz_options:
			fuzz_cookie(payload,info)


def fuzz():
	while not q.empty():
		request_hash = q.get()
		send_query(request_hash)
		


def fuzz_get(payload,info):
	url = info['scheme'] + '://'  + info['host'] + ':' + info['port'] + info['path'] 
	for q in info['query']:
		print url
		tmp = deepcopy(info)
		tmp['query'][q] = payload
		try:
			r = requests.request(tmp['method'],url,params=tmp['query'],data=tmp['content'],headers=tmp['header'],proxies=proxies,verify=False,timeout=timeout)
		except Exception,e:
			print '[!] ' + str(e)
			generate_http_request(tmp['method'],tmp['path'],tmp['query'],tmp['content'],tmp['header'],{})
		#print r.text
		del tmp

def fuzz_post(payload,info):
	url = info['scheme'] + '://'  + info['host'] + ':' + info['port'] + info['path'] 
	for q in info['content']:
		print url
		tmp = deepcopy(info)
		tmp['content'][q] = payload
		try:
			#generate_http_request(tmp['method'],tmp['path'],tmp['query'],tmp['content'],tmp['header'],{})
			r = requests.request(tmp['method'],url,params=tmp['query'],data=tmp['content'],headers=tmp['header'],proxies=proxies,verify=False,timeout=timeout)
		except Exception,e:
			print '[!] ' + str(e)
			generate_http_request(tmp['method'],tmp['path'],tmp['query'],tmp['content'],tmp['header'],{})
		#print r.text
		del tmp

def fuzz_header(payload,info):
	url = info['scheme'] + '://'  + info['host'] + ':' + info['port'] + info['path'] 
	for q in info['header']:
		if q.lower() == 'cookie':
			continue	
		print url
		tmp = deepcopy(info)
		tmp['header'][q] = payload
		try:
			r = requests.request(tmp['method'],url,params=tmp['query'],data=tmp['content'],headers=tmp['header'],proxies=proxies,verify=False,timeout=timeout)
		except Exception,e:
			print '[!] ' + str(e)
			generate_http_request(tmp['method'],tmp['path'],tmp['query'],tmp['content'],tmp['header'],{})
		#print r.text
		del tmp

def fuzz_cookie(payload,info):
	url = info['scheme'] + '://'  + info['host'] + ':' + info['port'] + info['path'] 
	# no cookie return
	if not info['header'].has_key('Cookie'):
		return
	# parse the cookie to dict
	my_cookie = cookie_to_dict(info['header']['Cookie'])
	#print my_cookie

	# to avoid the collision of header and cookie, del the cookie from header
	del info['header']['Cookie']
	for q in my_cookie:	
		print url
		tmp = deepcopy(my_cookie)
		tmp[q] = payload
		#print tmp
		try:
			r = requests.request(info['method'],url,params=info['query'],data=info['content'],cookies=tmp,headers=info['header'],proxies=proxies,verify=False,timeout=timeout)
		except Exception,e:
			print '[!] ' + str(e)
			generate_http_request(info['method'],info['path'],info['query'],info['content'],info['header'],tmp)
		#print r.text
		del tmp

def cookie_to_dict(cookies):
	my_cookie = {}
	cookies = Cookie.SimpleCookie(str(cookies))
	for c in cookies:
		my_cookie[c] = cookies[c].value
	return my_cookie

def generate_http_request(method,path,query,content,headers,cookies):
	if query:
		url = path + '?' + urlencode(query)
	else:
		url = path 
	print method + ' ' + url + ' HTTP/1.1'
	for header in headers:
		print header + ': ' + headers[header]
	if cookies:
		print "Cookie: "
		for cookie in cookies:
			print cookie + '=' + cookies[cookie] + ';',
		print ''
	print ''
	print urlencode(content)


if __name__ == '__main__':
	read_dir_to_queue()
	for i in range(thread_num):
		t = threading.Thread(target=fuzz)
		t.start()
		print ('[*] generator thread -->%s start')% t.ident

	sys.exit()



