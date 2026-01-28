import pathlib

path = pathlib.Path(r"d:\magang\techscan\app\scan_utils.py")
try:
    content = path.read_text(encoding="utf-8")
except UnicodeDecodeError:
    print("File is not valid utf-8?")
    content = path.read_bytes().decode("utf-8", errors="replace")

for i, line in enumerate(content.splitlines(), 1):
    if "\u2013" in line:
        print(f"Line {i}: Found U+2013 (en-dash)")
        print(f"  {line}")
    if "\u2014" in line:
        print(f"Line {i}: Found U+2014 (em-dash)")
        print(f"  {line}")
