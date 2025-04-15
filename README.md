# Project2SHER

## Project 2 — NVD CVE Data Analysis  
This Python project collects, processes, and visualizes Common Vulnerabilities and Exposures (CVEs) using the National Vulnerability Database (NVD) API.

---

## Functions

### `request_cve_list(year, month)`  
Fetches CVE data from the NVD API for the given year and month. Results are cached locally as JSON.

```python
import requests
import os
import json

def request_cve_list(year, month):
    api_key = "your_api_key_here"  # Replace with your actual API key
    start_date = f"{year}-{month:02d}-01T00:00:00.000Z"
    end_date = f"{year+1}-01-01T00:00:00.000Z" if month == 12 else f"{year}-{month+1:02d}-01T00:00:00.000Z"
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate={start_date}&pubEndDate={end_date}"
    headers = {"apiKey": api_key}
    filename = f"cve_cache_{year}_{month:02d}.json"

    if os.path.isfile(filename):
        with open(filename, "r") as f:
            return json.load(f)
    else:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            with open(filename, "w") as f:
                json.dump(data, f, indent=2)
            return data
        else:
            print(f"Error fetching data: {response.status_code}")
            return {}
```

---

### `write_CVEs_to_csv(year, month)`  
Parses the CVE JSON data and extracts key fields into a CSV file.

```python
import csv

def write_CVEs_to_csv(year, month):
    data = request_cve_list(year, month)
    filename = f"cve-{year}-{month:02d}.csv"
    fields = [
        'cveid', 'month', 'year', 'publication date', 'modification date',
        'exploitabilityScore', 'impactScore', 'vectorString', 'attackVector',
        'attackComplexity', 'privilegesRequired', 'userInteraction', 'scope',
        'confidentialityImpact', 'integrityImpact', 'availabilityImpact',
        'baseScore', 'baseSeverity', 'description'
    ]

    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()

        for item in data.get("vulnerabilities", []):
            try:
                cve = item.get("cve", {})
                metrics = cve.get("metrics", {})
                cvss_data = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
                row = {
                    'cveid': cve.get("id"),
                    'month': str(month),
                    'year': str(year),
                    'publication date': cve.get("published"),
                    'modification date': cve.get("lastModified"),
                    'exploitabilityScore': metrics.get("cvssMetricV31", [{}])[0].get("exploitabilityScore", ""),
                    'impactScore': metrics.get("cvssMetricV31", [{}])[0].get("impactScore", ""),
                    'vectorString': cvss_data.get("vectorString", ""),
                    'attackVector': cvss_data.get("attackVector", ""),
                    'attackComplexity': cvss_data.get("attackComplexity", ""),
                    'privilegesRequired': cvss_data.get("privilegesRequired", ""),
                    'userInteraction': cvss_data.get("userInteraction", ""),
                    'scope': cvss_data.get("scope", ""),
                    'confidentialityImpact': cvss_data.get("confidentialityImpact", ""),
                    'integrityImpact': cvss_data.get("integrityImpact", ""),
                    'availabilityImpact': cvss_data.get("availabilityImpact", ""),
                    'baseScore': cvss_data.get("baseScore", ""),
                    'baseSeverity': cvss_data.get("baseSeverity", ""),
                    'description': cve.get("descriptions", [{}])[0].get("value", "")
                }
                writer.writerow(row)
            except Exception as e:
                print(f"Skipping entry due to error: {e}")
```

---

### `plot_CVEs(year, month, topnum=40)`  
Reads the CSV and creates two interactive plots using Plotly.

```python
import pandas as pd
from plotly.graph_objs import Bar, Scatter
from plotly import offline

def plot_CVEs(year, month, topnum=40):
    filename = f"cve-{year}-{month:02d}.csv"
    df = pd.read_csv(filename)

    top_df = df.sort_values("baseScore", ascending=False).head(topnum)
    bar_data = Bar(
        x=top_df['cveid'],
        y=top_df['baseScore'],
        text=top_df['description'],
        marker=dict(color='crimson')
    )
    layout = dict(title='Top CVEs by Severity', xaxis=dict(title='CVE ID'), yaxis=dict(title='Base Score'))
    fig = dict(data=[bar_data], layout=layout)
    offline.plot(fig, filename=f"bar_chart_{year}_{month:02d}.html", auto_open=False)

    scatter_data = Scatter(
        x=df['baseScore'],
        y=df['exploitabilityScore'],
        text=df['cveid'],
        mode='markers'
    )
    layout2 = dict(title='Severity vs Exploitability Score', xaxis=dict(title='Base Score'), yaxis=dict(title='Exploitability Score'))
    fig2 = dict(data=[scatter_data], layout=layout2)
    offline.plot(fig2, filename=f"scatter_plot_{year}_{month:02d}.html", auto_open=False)
```

---

## How to Run

### Install Required Libraries

```bash
pip install requests plotly pandas
```

### Run the Script

```bash
python3 main.py
```

### Example

```python
if __name__ == "__main__":
    year = 2022
    month = 2
    write_CVEs_to_csv(year, month)
    plot_CVEs(year, month)
```

---

## Common Issues & Fixes

### API Rate Limiting  
**Fix**: Use a registered API key and implement caching with local files.

### KeyError: 'cvssMetricV31'  
**Fix**: Add error handling or skip entries missing critical data fields.

### Charts Not Displaying  
**Fix**: Ensure valid data is written to CSV before plotting.

### CSV Already Exists  
**Fix**: Manually delete the existing file or add a conditional overwrite option.

---

## Notes

- Fully modular code structure  
- Follows format of `cve-2022-02-sample.csv`
- Plots are interactive HTML files, saved locally

---
