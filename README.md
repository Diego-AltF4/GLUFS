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
| *-b*          | indicates the binary to be exploited (**mandatory parameter**). |
| *-max*     | indicates maximum value to be tested. Range: (min, max). By default, max = 40 |
| *-min*     | indicates minimum value to be tested. Range: (min, max). By default, min = 1 |
| *-ip*     | indicates remote server's ip. |
| *-port*     | indicates remote server's port. |
| *-flag*     | indicates the start of the flag. |
| *--s*     | indicates to use %s instead of %p. |
| *--canary*     | indicates to find the position where a canary leak is located. |
| *--leaks*     | prints all the leaks found. |
| *--pie*     | indicates to find the position where a pie leak is located. |
| *--stack*     | indicates to find the position where a stack leak is located. |
| *--v*     | set the verbose mode. |
