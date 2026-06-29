# tools/fetch_headers.py
import urllib.request
import os

HEADERS = {
    "onnxruntime_c_api.h": "https://raw.githubusercontent.com/microsoft/onnxruntime/rel-1.27.0/include/onnxruntime/core/session/onnxruntime_c_api.h",
    "onnxruntime_cxx_api.h": "https://raw.githubusercontent.com/microsoft/onnxruntime/rel-1.27.0/include/onnxruntime/core/session/onnxruntime_cxx_api.h",
    "onnxruntime_cxx_inline.h": "https://raw.githubusercontent.com/microsoft/onnxruntime/rel-1.27.0/include/onnxruntime/core/session/onnxruntime_cxx_inline.h",
    "onnxruntime_ep_c_api.h": "https://raw.githubusercontent.com/microsoft/onnxruntime/rel-1.27.0/include/onnxruntime/core/session/onnxruntime_ep_c_api.h",
    "onnxruntime_float16.h": "https://raw.githubusercontent.com/microsoft/onnxruntime/rel-1.27.0/include/onnxruntime/core/session/onnxruntime_float16.h"
}

def main():
    dest_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../native/include"))
    os.makedirs(dest_dir, exist_ok=True)
    
    print(f"Downloading ONNX Runtime C/C++ API headers to: {dest_dir}")
    
    for filename, url in HEADERS.items():
        dest_path = os.path.join(dest_dir, filename)
        print(f"Fetching {filename}...")
        try:
            urllib.request.urlretrieve(url, dest_path)
            print(f"Successfully downloaded {filename}")
        except Exception as e:
            print(f"Error downloading {filename}: {e}")

if __name__ == "__main__":
    main()
