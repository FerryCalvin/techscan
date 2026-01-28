
import pathlib

path = pathlib.Path(r'd:\magang\techscan\app\scan_utils.py')
content = path.read_text(encoding='utf-8')

# Replace en-dash with hyphen
fixed = content.replace('\u2013', '-')

# Also replace any other common non-ascii dashes if present
fixed = fixed.replace('\u2014', '--') # em-dash

if fixed != content:
    print("Found and replaced invalid characters.")
    path.write_text(fixed, encoding='utf-8')
else:
    print("No invalid characters found (programmatically).")
