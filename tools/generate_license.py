# tools/generate_license.py
import argparse
import os
import sys

# Ensure package path is visible
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../python')))

from vajraa.crypto import generate_license

def main():
    parser = argparse.ArgumentParser(description="Vajraa License Generator")
    parser.add_argument("--customer_id", type=str, required=True, help="Unique identifier for the customer")
    parser.add_argument("--master_key", type=str, required=True, help="Master model key (32-byte hex string)")
    parser.add_argument("--customer_key", type=str, required=True, help="Customer specific decryption key (32-byte hex string)")
    parser.add_argument("--output", type=str, default="license.lic", help="Output path for the license file")
    args = parser.parse_args()

    try:
        master_key = bytes.fromhex(args.master_key)
        customer_key = bytes.fromhex(args.customer_key)
        if len(master_key) != 32 or len(customer_key) != 32:
            raise ValueError("Keys must be exactly 32 bytes (64 hex characters).")
    except Exception as e:
        print(f"Error parsing keys: {e}")
        sys.exit(1)

    print(f"Generating wrapped license file for customer '{args.customer_id}'...")
    lic_bytes = generate_license(args.customer_id, master_key, customer_key)
    
    with open(args.output, "wb") as f:
        f.write(lic_bytes)
        
    print(f"License issued successfully! Saved to: {args.output}")

if __name__ == "__main__":
    main()
