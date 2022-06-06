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
