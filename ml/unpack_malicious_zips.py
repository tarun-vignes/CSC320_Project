import os
import sys
import zipfile
from pathlib import Path

# Common passwords used for malware datasets
DEFAULT_PASSWORDS = [
    b"infected",
    b"malware",
    b"virus"
]

def try_extract_zip(zip_path: Path, output_dir: Path, passwords=None):
    """
    Attempt to extract a single zip file.
    Tries no password first, then tries common passwords.
    """

    if passwords is None:
        passwords = DEFAULT_PASSWORDS

    # Make sure output folder exists
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        with zipfile.ZipFile(zip_path, "r") as zf:

            # Try extracting without password
            try:
                zf.extractall(output_dir)
                print(f"[OK] Extracted {zip_path.name} (no password)")
                return True
            except RuntimeError:
                pass

            # Try each known password
            for pw in passwords:
                try:
                    zf.extractall(output_dir, pwd=pw)
                    print(f"[OK] Extracted {zip_path.name} (password: {pw.decode()})")
                    return True
                except RuntimeError:
                    continue

            # If all fail
            print(f"[FAIL] Could not extract {zip_path.name}")
            return False

    except zipfile.BadZipFile:
        print(f"[FAIL] Invalid zip file: {zip_path}")
        return False


def unpack_all_zips(input_dir: str, output_dir: str):
    """
    Find all .zip files in a folder and extract them into dataset/malicious
    """

    input_path = Path(input_dir)
    output_path = Path(output_dir)

    if not input_path.exists():
        print(f"Error: input directory not found")
        return 1

    # Find all zip files recursively
    zip_files = list(input_path.rglob("*.zip"))

    if not zip_files:
        print("No zip files found")
        return 1

    success = 0

    for zip_file in zip_files:
        # Each zip gets its own folder
        subfolder = output_path / zip_file.stem

        if try_extract_zip(zip_file, subfolder):
            success += 1

    print(f"\nDone: {success}/{len(zip_files)} extracted")
    return 0


# Entry point
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 unpack_malicious_zips.py <input_zip_folder> <output_folder>")
        sys.exit(1)

    sys.exit(unpack_all_zips(sys.argv[1], sys.argv[2]))
    