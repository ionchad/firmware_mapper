import os
import shutil

def extract_firmware(fake_bin_path, out_dir="extracted"):
    if os.path.exists(out_dir):
        shutil.rmtree(out_dir)
    os.makedirs(out_dir)

    # For now: just unzip fake firmware or copy files for testing
    if fake_bin_path.endswith(".zip"):
        import zipfile
        with zipfile.ZipFile(fake_bin_path, 'r') as zip_ref:
            zip_ref.extractall(out_dir)
    else:
        # Dummy extract (just copies the bin for testing)
        shutil.copy(fake_bin_path, out_dir + "/firmware.bin")

    return out_dir
