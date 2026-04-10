import os
import sys
from pathlib import Path

try:
    import pyzipper
except ImportError:
    print("Error: pyzipper not installed. Run: pip3 install pyzipper")
    sys.exit(1)

DEFAULT_PASSWORDS = [
    b"infected",
    b"malware",
    b"virus",
    b"password",
    b"123456"
]

def try_extract_zip(zip_path: Path, output_dir: Path, passwords=None):
    if passwords is None:
        passwords = DEFAULT_PASSWORDS

    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        with pyzipper.AESZipFile(zip_path, "r") as zf:

            # Try without password first
            try:
                zf.extractall(output_dir)
                print(f"[OK]   {zip_path.name} (no password)")
                return True
            except Exception:
                pass

            # Try each known password
            for pw in passwords:
                try:
                    zf.extractall(output_dir, pwd=pw)
                    print(f"[OK]   {zip_path.name} (password: {pw.decode()})")
                    return True
                except Exception:
                    continue

        print(f"[FAIL] {zip_path.name} — no password worked")
        return False

    except Exception as e:
        print(f"[FAIL] {zip_path.name} — {e}")
        return False


def unpack_all_zips(input_dir: str, output_dir: str):
    input_path  = Path(input_dir)
    output_path = Path(output_dir)

    if not input_path.exists():
        print(f"Error: input directory '{input_dir}' not found.")
        return 1

    zip_files = sorted(input_path.rglob("*.zip"))

    if not zip_files:
        print(f"No .zip files found in '{input_dir}'.")
        return 1

    print(f"Found {len(zip_files)} zip file(s). Extracting to '{output_dir}'...\n")

    success = 0
    for zip_file in zip_files:
        subfolder = output_path / zip_file.stem
        if try_extract_zip(zip_file, subfolder):
            success += 1

    print(f"\nDone: {success}/{len(zip_files)} extracted successfully.")
    return 0 if success > 0 else 1


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 unpack_malicious_zips.py <input_zip_folder> <output_folder>")
        print("Example: python3 unpack_malicious_zips.py zips/ dataset/malware/")
        sys.exit(1)

    sys.exit(unpack_all_zips(sys.argv[1], sys.argv[2]))