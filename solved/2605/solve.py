import marshal
import dis
import sys

try:
    with open("e67d864b-5342-4f34-b93f-abaf8a97aa9d.pyc", "rb") as f:
        f.seek(16)
        code_obj = marshal.load(f)

    print("=== Disassembly ===")
    dis.dis(code_obj)

    print("\n=== Constants (Consts) ===")
    for i, c in enumerate(code_obj.co_consts):
        print(f"[{i}] {c}")

    print("\n=== Names ===")
    print(code_obj.co_names)

except Exception as e:
    print(f"Error: {e}")

#e67d864b-5342-4f34-b93f-abaf8a97aa9d.pyc file disassemble