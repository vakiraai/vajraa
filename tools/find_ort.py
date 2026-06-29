# tools/find_ort.py
import onnxruntime
import os
import sys

def main():
    ort_path = os.path.dirname(onnxruntime.__file__)
    include_path = os.path.join(ort_path, "capi", "include")
    if not os.path.exists(include_path):
        include_path = os.path.join(ort_path, "include")
        
    if os.path.exists(include_path):
        print(include_path.replace("\\", "/"))
    else:
        print("NOT_FOUND")
        sys.exit(1)

if __name__ == "__main__":
    main()
