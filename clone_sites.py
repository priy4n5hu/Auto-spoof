#!/usr/bin/env python3
import os
import subprocess
import shutil
import sys
import argparse

# Directory where sites are cloned
CLONE_DIR = "cloned_sites"

def clone_site(site: str):
    """Clone a single site into CLONE_DIR/site/"""
    output_path = os.path.join(CLONE_DIR, site)
    os.makedirs(output_path, exist_ok=True)

    # Skip if already cloned
    if os.path.isdir(output_path) and os.listdir(output_path):
        print(f"[-] {site} already cloned, skipping.")
        return

    print(f"[+] Cloning {site} into {output_path}...")
    subprocess.call([
        "wget",
        "--mirror",
        "--convert-links",
        "--adjust-extension",
        "--page-requisites",
        "--no-parent",
        "-P", output_path,
        f"http://{site}/"
    ])

    # Flatten nested directory if needed
    nested = os.path.join(output_path, site)
    if os.path.exists(nested):
        print(f"[+] Flattening files from {nested} to {output_path}")
        for item in os.listdir(nested):
            s = os.path.join(nested, item)
            d = os.path.join(output_path, item)
            if os.path.isdir(s):
                shutil.copytree(s, d, dirs_exist_ok=True)
            else:
                shutil.copy2(s, d)
        shutil.rmtree(nested)

def main():
    parser = argparse.ArgumentParser(
        description="Mirror one or more websites into ./cloned_sites/<domain>/"
    )
    parser.add_argument(
        'domains',
        nargs='+',
        help='Domain(s) to clone (e.g. example.com vulnweb.com)'
    )
    args = parser.parse_args()

    for site in args.domains:
        clone_site(site)

if __name__ == "__main__":
    main()
