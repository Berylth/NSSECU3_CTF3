import requests
import time
import concurrent.futures
import sys
from datetime import datetime, timezone
import pandas as pd

# List to store VT API Keys
VT_API_KEYS = [] 

# Set up the rate limits
VT_REQUESTS_PER_MIN = 4

# API URL
VT_BASE_URL = "https://www.virustotal.com/api/v3/files/"

# Read the data from file
def read_file(file_path):
    with open(file_path, "r") as file:
        return [line.strip() for line in file.readlines()]

# Make a VirusTotal API request
def lookup_virustotal(hash_value, api_key):
    headers = {
        "x-apikey": api_key
    }
    url = VT_BASE_URL + hash_value
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        print(f"Hash: {hash_value} is been processed")

        names = data.get('data', {}).get('attributes', {}).get('names', [])
        name1 = names[0] if len(names) > 0 else "-"
        name2 = names[1] if len(names) > 1 else "-"
        name3 = names[2] if len(names) > 2 else "-"

        result = {
            "Hash": hash_value,
            "Detection Count": data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0),
            "MD5": data.get('data', {}).get('attributes', {}).get('md5', '-'),
            "SHA1": data.get('data', {}).get('attributes', {}).get('sha1', '-'),
            "SHA256": data.get('data', {}).get('attributes', {}).get('sha256', '-'),
            "File Type": data.get('data', {}).get('attributes', {}).get('type_description', '-'),
            "Magic": data.get('data', {}).get('attributes', {}).get('magic', '-'),
            "Creation Time": datetime.fromtimestamp(data.get('data', {}).get('attributes', {}).get('creation_date', 0), tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),
            "Signature Date": datetime.fromtimestamp(data.get('data', {}).get('attributes', {}).get('last_modification_date', 0), tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),
            "First Seen in The Wild:": datetime.fromtimestamp(data.get('data', {}).get('attributes', {}).get('first_submission_date', 0), tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),
            "First Submission": datetime.fromtimestamp(data.get('data', {}).get('attributes', {}).get('first_submission_date', 0), tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),
            "Last Submission": datetime.fromtimestamp(data.get('data', {}).get('attributes', {}).get('last_submission_date', 0), tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),
            "Last Analysis": datetime.fromtimestamp(data.get('data', {}).get('attributes', {}).get('last_analysis_date', 0), tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),
            "Name1": name1,
            "Name2": name2,
            "Name3": name3,
            "Verdict": "Malicious" if data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0) > 0 else "Benign"
        }
    else:
        print(f"Error fetching data for {hash_value} in virus total: {response.status_code}")
        result =  {
            "Hash": hash_value,
            "Detection Count": "N/A",
            "MD5": "N/A",
            "SHA1": "N/A",
            "SHA256": "N/A",
            "File Type": "N/A",
            "Magic": "N/A",
            "Creation Time": "N/A",
            "Signature Date": "N/A",
            "First Seen In The Wild": "N/A",
            "First Submission": "N/A",
            "Last Submission": "N/A",
            "Last Analysis": "N/A",
            "Name1": "N/A",
            "Name2": "N/A",
            "Name3": "N/A",
            "Verdict": "N/A"
        }
    time.sleep(60 / VT_REQUESTS_PER_MIN)  # To avoid hitting the rate limit, sleepafter each request
    return result

# Function to process the hashes
def process_hashes(hashes):
    all_data = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(VT_API_KEYS)) as executor:
        future_to_hash = {
            executor.submit(lookup_virustotal, hash_val, VT_API_KEYS[i % len(VT_API_KEYS)]): hash_val 
            for i, hash_val in enumerate(hashes)
        }
        for future in concurrent.futures.as_completed(future_to_hash):
            result = future.result()
            all_data.append(result)
    return all_data

# Save the results to a CSV or XLSX file
def save_results(results, output_file='output.csv'):
    df = pd.DataFrame(results)
    df.index = df.index + 1  
    df.index.name = "File#"  
    df.to_csv("output.csv", index=True)
    df.to_csv(output_file, index=True)
    print(f"\nResults saved to {output_file}")


def main():
    if len(sys.argv) != 3:
        print("Invalid program usage...")
        print("Try running the program like this: python ./Script.py <hash_file.txt> <api_file.txt>")
        return

    # Load api keys and hashes from txt file
    global VT_API_KEYS
    hashes = read_file(sys.argv[1])
    VT_API_KEYS = read_file(sys.argv[2])

    # Process each hash in VT API and save results to csv file
    results = process_hashes(hashes)
    save_results(results)

if __name__ == "__main__":
    main()