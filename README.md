# Project2SHER

## Project 2 — NVD CVE Data Analysis  
This project collects, processes, and visualizes Common Vulnerabilities and Exposures (CVEs) using the National Vulnerability Database (NVD) API.

---

## Functions

### request_cve_list(year, month)  
Returns a JSON object of all CVEs for the given year and month using the NVD API.

```python
def request_cve_list(year, month):
    '''Get CVE info from NIST using requests and return a JSON object'''
```

---

### write_CVEs_to_csv(year, month)  
Parses the JSON data and writes selected fields to a CSV file in the format `cve-YYYY-MM.csv`.

```python
def write_CVEs_to_csv(year, month):
    '''Extracts and saves CVE data to a formatted CSV file'''
```

**CSV includes:**
- cveid  
- month  
- year  
- publication date  
- modification date  
- exploitabilityScore  
- impactScore  
- vectorString  
- attackVector  
- attackComplexity  
- privilegesRequired  
- userInteraction  
- scope  
- confidentialityImpact  
- integrityImpact  
- availabilityImpact  
- baseScore  
- baseSeverity  
- description  

---

### plot_CVEs(year, month, topnum=40)  
Creates two interactive plots from the generated CSV file.

```python
def plot_CVEs(year, month, topnum=40):
    '''Creates interactive visualizations from the CVE dataset'''
```

- **Bar chart** of top CVEs by severity (hover shows description)  
- **Scatter plot** comparing baseScore vs. exploitabilityScore  

---

## How to Run  

### Install Required Libraries

```bash
pip install requests plotly
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

## Example Output  

- CSV File: `cve-2022-02.csv`  
- Bar Chart: Top 40 CVEs by severity  
- Scatter Plot: Severity vs Exploitability  

---

## Hash Check (Optional)

```python
import hashlib

h = hashlib.new('sha1')
h.update(open("cve-2022-02.csv").read().encode("utf-8"))
print(h.hexdigest())
```

---

## Tests

### test_request_cve_list()

```python
def test_request_cve_list():
    data = request_cve_list(2022, 2)
    assert isinstance(data, dict)
    assert 'vulnerabilities' in data
```

---

### test_write_CVEs_to_csv()

```python
def test_write_CVEs_to_csv():
    with open('cve-2022-02.csv') as f:
        reader = csv.DictReader(f)
        for row in reader:
            assert row['attackComplexity'] in ['LOW', 'HIGH']
            assert re.search(r"[0-9]", row['baseScore'])
```

---

## Common Issues & Fixes

### ❌ API Rate Limit Hit  
**Issue**: Frequent API calls triggered rate limits.  
**Fix**: Registered for an API key and added local JSON caching using `os.path.isfile()` to skip redundant downloads.

---

### ❌ KeyError: 'cvssMetricV31'  
**Issue**: Some CVEs didn’t include this key, causing errors.  
**Fix**: Skipped entries missing the expected fields.

---

### ❌ Charts Not Rendering  
**Issue**: Plotly charts didn’t appear.  
**Fix**: Verified proper use of `offline.plot()` and checked that CSV existed before plotting.

---

### ❌ CSV File Already Exists  
**Issue**: Script wouldn’t overwrite existing files.  
**Fix**: Manually deleted CSV during testing or ensured logic skipped generation if already present.

---

## Notes

- All functions are modular and reusable.
- Output matches example format and plot visuals.
- Compatible with testing via `nvd_cve_testing.py`.

---
