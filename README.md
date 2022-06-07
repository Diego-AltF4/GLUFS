<h1 align="center">
  <br>
    Getting Leaks Using Format String.
   <br>
</h1>


 ```
                     .d8888b.       888       888     888   8888888888   .d8888b.  
                     d88P  Y88b     888       888     888   888         d88P  Y88b 
                     888    888     888       888     888   888         Y88b.      
                     888            888       888     888   8888888      "Y888b.   
                     888  88888     888       888     888   888             "Y88b. 
                     888    888     888       888     888   888               "888 
                     Y88b  d88P     888       Y88b. .d88P   888         Y88b  d88P 
                     "Y8888P88      88888888   "Y88888P"    888          "Y8888P"                                                    
 
                                            By: DiegoAltF4
 ```                                          


## Introduction


GLUFS allows you to automate the tedious process of finding leaks using format string vulnerabilities. 
It will allow you to find stack leaks, pie leaks and canary leaks, in each case indicating the payload providing the leak. 
In addition, it includes a mode that allows you to search for a "flag" string in the leaks. For this mode, the %s or %p specifier can be used. 

           
## Parameters

| Parameter    | Information |
|:-------------|:-------------|
| *-b*          | Select this option to indicate the binary to be exploited. |
| *-max*     | Select this option to indicate the maximum value to be tested. Range: (min, max). By default, max = 40 |
| *-min*     | Select this option to indicate the minimum value to be tested. Range: (min, max). By default, min = 1 |
| *-ip*     | Select this option to specify the ip of the remote server. |
| *-port*     | Select this option to specify the port of the remote server. |
| *-flag*     | Select this option to indicate the start of the flag to search for. |
| *-arch*     | Select this option to set the arch (32 or 64). |
| *--s*     | Select this option to use %s instead of %p. |
| *--canary*     | Select this option to find the position where a canary leak is located. |
| *--leaks*     | Select this option to print all the leaks found. |
| *--pie*     | Select this option to find the position where a pie leak is located. |
| *--stack*     | Select this option to find the position where a stack leak is located. |
| *--v*     | Select this option to set the verbose mode. |

## Examples of use

### 1️⃣ First example ~ TryHackMe room pwn101

For this example, we are going to use GLUFS to get a pie and canary leak.

The binary we are going to take as an example is the one corresponding to challenge 7 of TryHackMe room pwn101 [TryHackMe room pwn101](https://tryhackme.com/room/pwn101).

We will use the ```-b``` option to indicate the binary, the ``` -min``` option to indicate the initial value of the iteration and ```-max``` to indicate the final value of the iteration. In addition, we want to get information about the canaries and about pie. 

```python
./glufs.py -b ./pwn107.pwn107 -min 5 -max 15 --pie --canary
```
![image](https://user-images.githubusercontent.com/55554183/172267534-b101163d-f4af-4598-b675-80243de6ac62.png)

### Demo:

[![asciicast](https://asciinema.org/a/UTAVBUK95n7SUTvDBPKFsXaSJ.svg)](https://asciinema.org/a/UTAVBUK95n7SUTvDBPKFsXaSJ)

### 2️⃣ Second example ~ 247CTF Confused environment read

For this example, we will use GLUFS to obtain the flag.

The challenge we are going to solve is [Confused environment read from the 247CTF platform](https://247ctf.com/dashboard).

For this example we are not going to use binary. We only have an ip and port. Therefore, we are going to use the ```-ip``` option to indicate the address, ```-port``` to indicate the port, ```-flag``` to specify the start of the flag to look for. In addition, as we do not have binary, we have to indicate the architecture, in this case, x86-64 (`-arch 64`). We will also indicate the start of the iteration with ```-min``` and the end of the iteration with ```-max```. In addition, we are going to use the ```-s``` option to use ```%s``` instead of ```%p```.

```python
./glufs.py -ip 3bcbadabd1a7e914.247ctf.com -port 50387 -flag 247CTF -arch 64 -min 1 -max 200 --s
```
![image](https://user-images.githubusercontent.com/55554183/172267389-6828599c-de59-4fb2-a3bb-a1460296db11.png)

### Demo:

[![asciicast](https://asciinema.org/a/58rVZrDPVT4bQOf8uGXi1fnVQ.svg)](https://asciinema.org/a/58rVZrDPVT4bQOf8uGXi1fnVQ)

### 3️⃣ Third example ~ PicoCTF flag leak

For this example, we will use GLUFS to obtain the flag.

The challenge we are going to solve is [flag leak from the PicoCTF platform](https://play.picoctf.org/practice/challenge/269?category=6&page=2).

For this example, we will use the `-ip` option to indicate the server address, `-port` to indicate the server port, `-b` to indicate the binary, `-flag` to indicate the start of the flag, and finally, we specify the start and end of the iteration with `-min` and `-max`. If you do not specify the `--s` option, the `%p` format will be used by default.

```python
./glufs.py -ip saturn.picoctf.net  -port 50563 -b ./vuln  -flag picoCTF -min 20 -max 200
```

![image](https://user-images.githubusercontent.com/55554183/172270682-44c3a300-914c-42bd-8d1c-280c70934aed.png)

### Demo:

[![asciicast](https://asciinema.org/a/EjytzjJcFeyszUVfe1QDBUyDD.svg)](https://asciinema.org/a/EjytzjJcFeyszUVfe1QDBUyDD)

## Installation:

```python
git clone https://github.com/Diego-AltF4/GLUFS.git
cd GLUFS/
pip3 install -r requirements.txt
chmod +x ./glufs.py 
```

## Configuration:

It is very important that you modify the code to be able to adapt it to your binary/challenge. For this, there are two delimited sections of the code in which you have to make changes in order to obtain the leak of the format string as well as to configure when the payload should be sent.

Examples:
For the picoCTF challenge explained above, the following configuration is used:

```python
#######################################################################
#      This is the part that you must modify to fit your binary.      #
#######################################################################
p.sendlineafter(b'>>', payload)
p.recvuntil(b'-')
leak = p.recv().strip(b'\n')
#print(leak) ## For debugging errors
#######################################################################	
```
