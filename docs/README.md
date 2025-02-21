## **Description**

The Alpha Port Scanner (***alpha-psc***) is a command-line tool designed to scan open ports on a target system.    

It supports both TCP and UDP port scanning. The scanner can work with a single target or multiple targets from a file.

Results can be saved in JSON, CSV, or plain text formats.



<br>  

## **Features:**

-***Port Scanning:*** TCP and UDP support.

-***Multithreading:*** Speeds up scanning by processing multiple targets in parallel.

-***Flexible Input:*** Supports both direct target specification and bulk targets via a text file.

-***Output Formats:*** JSON, CSV, or plain text logging.

-***Error Logging:*** Scan results and errors are logged for review.



<br>

## Installation:

*Please follow these steps.*

    git clone https://github.com/loveforbeatrice/alpha-psc.git
    cd alpha-psc
    ./setup.sh

>*make sure that setup.sh has execution permission*

    

<br>

## Usage and syntax:

 ` alpha-psc -t <target> -st <scan_type> -p <ports> -o <output_format>`


**-t**, --target: REQUIRED. Target IP, domain, or path to a file containing a list of targets.

**-st**, --scan-type: REQUIRED. Choose between tcp or udp for the scan type.

**-p**, --ports: Ports to scan. You can specify a range (e.g., 1-1000) or a list (e.g., 80,443).

**-o**, --output: REQUIRED. Output format for the scan results. Can be json, csv, or txt.

Remember -that you can access the help menu by typing ***-h*** or ***--help.***


<br>

## Fundamental Command Examples:

    alpha-psc -t scanme.nmap.org -st tcp -p 80,443 -o json 

 
 > *scan spesific ports with tcp, save results in a json file*   

  <br>   

     alpha-psc -t google.com -st udp -p 1-1024 -o csv 

  >*scan a range of ports with udp, save results in a csv file*   

   <br>     

     alpha-psc -t targets.txt -st tcp -p 80,443 -o txt

 > *scan spesific ports in a list of domains or IP's with tcp, save results in a txt file*





<br>

***

<br>

>Important note <br>This application has been developed purely for personal development purposes. It is probably in your best interest to continue your life using Nmap.










