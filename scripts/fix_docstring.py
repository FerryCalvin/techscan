import pathlib
import sys

path = pathlib.Path(r"d:\magang\techscan\app\scan_utils.py")
content = path.read_text(encoding="utf-8")

# The corrupted or tricky part seems to be the fast_full_scan docstring.
# We will identify it by its header and replace the block until start_all = time.time()

start_marker = "def fast_full_scan(domain: str, wappalyzer_path: str) -> Dict[str, Any]:"
end_marker = "start_all = time.time()"

if start_marker not in content:
    print("Could not find start marker")
    sys.exit(1)

if end_marker not in content:
    print("Could not find end marker")
    sys.exit(1)

# Construct clean docstring (EMPTY for now to fix syntax)
clean_docstring = ""

# Splitting to safe replace
pre = content.split(start_marker)[0] + start_marker + "\n"
post = content.split(end_marker)[1]
middle = content.split(start_marker)[1].split(end_marker)[0]

# verify we aren't eating too much
# middle should contain the corrupted docstring
# We just replace middle with clean docstring
new_content = pre + clean_docstring + end_marker + post

path.write_text(new_content, encoding="utf-8")
print("Successfully replaced docstring.")
