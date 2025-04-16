# NSSECU3_CTF3: IoC FIle Hash 101

A Python script that queries the VirusTotal API to analyze file hashes and retrieve detailed information about each file, including detection count, file type, and analysis results. The script supports concurrent requests using multiple API keys and saves the analysis results into a CSV file.


## Pre-requisites / Dependencies
1) [Python](https://www.python.org/downloads/)
    - requests  
        ```
        pip install requests
        ```
    - pandas
        ```
        pip install pandas
        ```
2) VirusTotal API keys

## Setup / How to Run
1) Download the python scipt.
2) Put the .txt file containing the hash the VirusTotal API in the same directory as the python script.
3) Run the python script using the command:
    ```
    python ./Script.py <hash_file.txt> <api_file.txt>
    ```
4) The output csv is saved at the same directory as the script and is named "output.csv".

## Acknowledgements
- This script utilizes the VirusTotal API to query and retrieve detailed file analysis results. VirusTotal is a service that provides free and comprehensive file and URL scanning to detect potential threats. Visit their [website](https://docs.virustotal.com/reference/overview) for more information.
