#!/usr/bin/env python3
import sys
import string
from pathlib import Path

usage = '''
Usage: ./ekans_decrypt_strings.py [options] filename
Options:
 -s print full strings
 -c print column formatted (tab separated) output
    strings are trimmed to include maximum 20 characters.
 -i output in IDA IDC script format
    useful to bulk rename all functions'''

# Signature used to match a place inside the string decryption routines.
# Used as a reference to access the key and ciphertext by offsets.
fcn_dec_sig = b"\x0f\xb6\x34\x2b\x8d\x34\x6e"

# Bytecodes of [lea eax, lea ebx, lea ecx, lea edx, lea esi, lea edi, lea ebp]
# Used to locate the places containing the addresses to the key and ciphertext
lea_reg_sigs = [b"\x8d\x05", b"\x8d\x1d", b"\x8d\x0d", b"\x8d\x15", b"\x8d\x35", b"\x8d\x3d", b"\x8d\x2d"]

lea_sig = b"\x8d"

# Go function signature for x86_32 windows binary
# Used to locate the base address of the string decryption function
go_fcn_sig = b"\x64\x8b\x0d\x14\x00\x00\x00"

def decrypt_string(enc_str):
	plaintext = ''

	for i in range(enc_str.string_length):
		decrypted_byte = ((enc_str.ciphertext[i] + (i*2)) & 0xff) ^ enc_str.key[i]
		plaintext += chr(decrypted_byte)

	return plaintext

# replace non-alphanumeric characters from ascii string with underscore
def ascii2alnum(ascii_str):
	alnum_str = ""
	for c in ascii_str:
		if c not in (string.ascii_letters + string.digits):
			alnum_str+="_"
		else:
			alnum_str+=c
	return alnum_str

def print_columns(encrypted_strings):
	print("fcn_addr\tfcn_offset\tct_addr\tct_offset\tkey_addr\tkey_offset\tstr_len\tplaintext")
	for enc_str in encrypted_strings:
		print("{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}".format( \
			hex(enc_str.fcn_base_address), \
			hex(enc_str.fcn_base_offset), \
			hex(enc_str.ciphertext_address), \
			hex(enc_str.ciphertext_offset), \
			hex(enc_str.key_address), \
			hex(enc_str.key_offset), \
			enc_str.string_length, \
			enc_str.plaintext[:20] \
		))

def print_strings(encrypted_strings):
	for enc_str in encrypted_strings:
		print(enc_str.plaintext)

def print_ida_idc(encrypted_strings):
	for enc_str in encrypted_strings:
		plaintext = ascii2alnum(enc_str.plaintext)
		ida_fcn_name = "decrypt_str_" + plaintext[:50] + "_" + hex(enc_str.fcn_base_address)
		print('MakeName({}, "{}");'.format(hex(enc_str.fcn_base_address), ida_fcn_name))	

class EncryptedString:
	sig_match_offset = None
	fcn_base_offset = None
	fcn_base_address = None
	key_offset = None
	key_address = None
	ciphertext_offset = None
	ciphertext_adress = None
	string_length = None
	key = None
	ciphertext = None
	plaintext = None

encrypted_strings = []

if len(sys.argv) != 3:
	print("Script accepts two arguments!")
	print(usage)
	sys.exit(1)

option = sys.argv[1]
filename = sys.argv[2]

if option not in ['-s','-c','-i']:
	print("Invalid option!")
	print(usage)
	sys.exit(1)

if not Path(filename).exists() or Path(filename).is_dir():
	print("File '{}' does not exist!".format(filename))
	print(usage)
	sys.exit(1)

file = open(filename,'rb')
file_data = file.read()
file.close()



file_offset = file_data.find(fcn_dec_sig)



while file_offset != -1:
	match_cnt = 0
	# start searching for lea... backwards from the fcn_dec_sig signature match
	lea_offset = file_data.rfind(lea_sig, 0, file_offset)
	while True:
		bytecode = file_data[lea_offset:lea_offset+2]

		# used to check for false positive matches.
		# the lea <reg> instruction should be followed by a 4 byte address
		# in little-endian format. meaning there is very little chance
		# the 2 bytes following lea <reg> to be two null bytes
		bytecode_tmp = file_data[lea_offset+2:lea_offset+4]

		# check if bytecode matches lea <reg>, <addr>
		if (bytecode in lea_reg_sigs) and (bytecode_tmp != b"\x00\x00"):
			# the first valid match contains the virtual address of the key
			if match_cnt == 0:
				match_cnt = match_cnt + 1
				key_address = file_data[lea_offset+2:lea_offset+6][::-1].hex()
				key_address = int(key_address, 16)

			# the second valid match contains the virtual address of the ciphertext
			elif match_cnt == 1:
				ciphertext_address = file_data[lea_offset+2:lea_offset+6][::-1].hex()
				ciphertext_address = int(ciphertext_address, 16)

				# the string length is located 14 bytes after the second lea_reg match
				string_length = file_data[lea_offset+14:lea_offset+18][::-1].hex()
				string_length = int(string_length, 16)

				# filter functions with invalid match for string length
				if string_length > len(file_data): break

				# find the offset to the beginning of the string decryption function
				# by searching for the go_fcn_sig signature backwards from the last
				# lea <reg> signature match
				fcn_base_offset = file_data.rfind(go_fcn_sig, 0, lea_offset)

				enc_str = EncryptedString()
				enc_str.sig_match_offset 	=	file_offset
				enc_str.fcn_base_offset 	=	fcn_base_offset
				enc_str.fcn_base_address 	=	fcn_base_offset + 0x400c00
				enc_str.key_address 		=	key_address
				enc_str.key_offset 		=	key_address - 0x400c00
				enc_str.ciphertext_address 	=	ciphertext_address
				enc_str.ciphertext_offset 	=	ciphertext_address - 0x400c00
				enc_str.string_length 		=	string_length
				enc_str.ciphertext		=	bytearray(file_data[enc_str.ciphertext_offset : enc_str.ciphertext_offset + string_length])
				enc_str.key			=	bytearray(file_data[enc_str.key_offset : enc_str.key_offset + string_length])
				enc_str.plaintext		= 	decrypt_string(enc_str)

				encrypted_strings.append(enc_str) 
				break

		# search for the next lea <reg> signature
		lea_offset = file_data.rfind(lea_sig, 0, lea_offset)

	# search for the next string decryption function using the fcn_dec_sig signature
	file_offset = file_data.find(fcn_dec_sig, file_offset+1)


if option == '-s':
	print_strings(encrypted_strings)
elif option == '-c':
	print_columns(encrypted_strings)
elif option == '-i':
	print_ida_idc(encrypted_strings)
