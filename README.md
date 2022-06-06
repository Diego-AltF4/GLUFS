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
 
                                            By: DiegoAlt4
 ```                                          


## Introduction


GLUFS allows you to automate the tedious process of finding leaks using format string vulnerabilities. 
It will allow you to find stack leaks, pie leaks, libc leaks, canary leaks and heap leaks, in each case indicating the payload providing the leak. 
In addition, it includes a mode that allows you to search for a "flag" string in the leaks. For this mode, the %s or %p specifier can be used. 

           
## Parameters

| Parameter    | Information |
|:-------------|:-------------|
| *-b*          | Select this option to indicate the binary to be exploited (**mandatory parameter**). |
| *-max*     | Select this option to indicate the maximum value to be tested. Range: (min, max). By default, max = 40 |
| *-min*     | Select this option to indicate the minimum value to be tested. Range: (min, max). By default, min = 1 |
| *-ip*     | Select this option to specify the ip of the remote server. |
| *-port*     | Select this option to specify the port of the remote server. |
| *-flag*     | Select this option to indicate the start of the flag to search for. |
| *--s*     | Select this option to use %s instead of %p. |
| *--canary*     | Select this option to find the position where a canary leak is located. |
| *--leaks*     | Select this option to print all the leaks found. |
| *--pie*     | Select this option to find the position where a pie leak is located. |
| *--stack*     | Select this option to find the position where a stack leak is located. |
| *--v*     | Select this option to set the verbose mode. |



## Examples of use

### 1️⃣ First example ~ TryHackMe room pwn101

For this example, we are going to use GLUFS to get a foot and canary leak.

The binary we are going to take as an example is the one corresponding to challenge 7 of TryHackMe room pwn101 [TryHackMe room pwn101](https://tryhackme.com/room/pwn101).

We will use the ```-b``` option to indicate the binary, the ``` -min``` option to indicate the initial value of the iteration and ```-max``` to indicate the final value of the iteration. In addition, we want to get information about the canaries and about pie. 

```python
./glufs.py -b ./pwn107.pwn107 -min 5 -max 15 --pie --canary
```

[![asciicast](https://asciinema.org/a/UTAVBUK95n7SUTvDBPKFsXaSJ.svg)](https://asciinema.org/a/UTAVBUK95n7SUTvDBPKFsXaSJ)

### 2️⃣ Second example ~ 247CTF Confused environment read

For this example, we will use GLUFS to obtain the flag.

For this example we are not going to use binary. We only have an ip and port. Therefore, we are going to use the ```-ip``` option to indicate the address, ```-port``` to indicate the port, ```-flag``` to specify the start of the flag to look for. In addition, as we do not have binary, we have to indicate the architecture, in this case, x86-64 (-arch 64). We will also indicate the start of the iteration with ```-min``` and the end of the iteration with ```-max```. In addition, we are going to use the ```-s``` option to use ```%s``` instead of ```%p```.

```python
./glufs.py -ip 3bcbadabd1a7e914.247ctf.com -port 50387 -flag 247CTF -arch 64 -min 1 -max 200 --s
```
![image](https://user-images.githubusercontent.com/55554183/172267389-6828599c-de59-4fb2-a3bb-a1460296db11.png)

[![asciicast](https://asciinema.org/a/58rVZrDPVT4bQOf8uGXi1fnVQ.svg)](https://asciinema.org/a/58rVZrDPVT4bQOf8uGXi1fnVQ)
