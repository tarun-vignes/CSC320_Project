'''
Name: Joseph DiMartino
Program: FTP: Finding covert messages in FTP channels
Date: 3.4.2025
'''
import os
output7_path = os.path.expanduser("~/Desktop/CSC330Files/inputs/out7.txt")
output10_path = os.path.expanduser("~/Desktop/CSC330Files/inputs/out10.txt")
FTPin_path = os.path.expanduser("~/Desktop/CSC330Files/inputs/FTPinput.txt")

from ftplib import FTP

# FTP server details
IP = "10.0.222.38"
PORT = 33333.
USER = "anonymous"
PASSWORD = "simple@abcdefg.com"
FOLDER = "pub/in_here/.now_in_here/.0bee6d0733" # the folder to read from on the FTP server
USE_PASSIVE = True # set to False if the connection times out

# connect and login to the FTP server
ftp = FTP()
ftp.connect(IP, PORT)
ftp.login(USER, PASSWORD)
ftp.set_pasv(USE_PASSIVE)

# navigate to the specified directory and list files
ftp.cwd(FOLDER)
files = []
ftp.dir(files.append)
#files = ftp.retrlines("List -a")
with open(FTPin_path, "w") as f:
    ftp.retrlines("LIST -a", f.write)
# exit the FTP server
ftp.quit()

# sort the files by filename, ignoring case
#files = sorted(files, key=lambda x: x[56:].lower())

# this bit below will read from a file get get it to work here
with open(FTPin_path, "w") as f:
    for entry in files:
        f.write(entry + "\n")


perms1 = ""
for line in files:
    if (line[:3] == "---"):  # this if is for 7bit method, 10 bit method delete this
        perms1 += line[3:10]  # if it's 10 bit method it needs to be [:10]
        perms1 = perms1.replace("-", "0")
        perms1 = perms1.replace("r", "1")
        perms1 = perms1.replace("w", "1")
        perms1 = perms1.replace("x", "1")
        perms1 = perms1.replace("d", "1")

with open(output7_path, "w") as out7_file:
    out7_file.write(perms1)

perms2 = ""
for line in files:
    perms2 += line[:10]  # if it's 10 bit method it needs to be [:10]
    perms2 = perms2.replace("-", "0")
    perms2 = perms2.replace("r", "1")
    perms2 = perms2.replace("w", "1")
    perms2 = perms2.replace("x", "1")
    perms2 = perms2.replace("d", "1")
print(f"7 bit method printed in {output7_path}")

with open(output10_path, "w") as out10_file:
    out10_file.write(perms2)
print(f"10 bit method printed in {output10_path}")


