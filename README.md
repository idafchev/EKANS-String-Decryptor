# EKANS-String-Decryptor
A python script to decrypt the strings inside the EKANS ransomware.  
The script is tested with only two samples, so there might be bugs.  

There are several output formats.  
It can generate an IDA IDC script suitable for bulk renaming all string decryption functions.  
Just Shift+F2, copy/paste and run.

```
Usage: ./ekans_decrypt_strings.py [options] filename
Options:
 -s print full strings
 -c print column formatted (tab separated) output
    strings are trimmed to include maximum 20 characters.
 -i output in IDA IDC script format
    useful to bulk rename all functions
```
