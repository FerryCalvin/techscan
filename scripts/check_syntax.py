
import pathlib

path = pathlib.Path(r'd:\magang\techscan\app\scan_utils.py')
content = path.read_text(encoding='utf-8')

lines = content.splitlines()
in_triple_double = False
in_triple_single = False

start_line = -1

for i, line in enumerate(lines, 1):
    # This is a naive parser, doesn't handle escaping perfectly but good enough for finding mismatched blocks
    # We strip comments to be safer
    code = line.split('#')[0]
    
    # Count occurrences (non-overlapping)
    j = 0
    while j < len(line):
        # Check for triple
        if line[j:].startswith('"""'):
            if not in_triple_single:
                if in_triple_double:
                    in_triple_double = False
                    # print(f"Closed triple-double at {i} col {j}")
                else:
                    in_triple_double = True
                    start_line = i
                    print(f"Opened triple-double at {i} col {j}")
            j += 3
            continue
        
        # Check for triple single
        if line[j:].startswith("'''"):
            if not in_triple_double:
                if in_triple_single:
                    in_triple_single = False
                    # print(f"Closed triple-single at {i} col {j}")
                else:
                    in_triple_single = True
                    start_line = i
                    print(f"Opened triple-single at {i} col {j}")
            j += 3
            continue
            
        j += 1

if in_triple_double:
    print(f"ERROR: Unterminated triple-double quote starting at line {start_line}")
if in_triple_single:
    print(f"ERROR: Unterminated triple-single quote starting at line {start_line}")
