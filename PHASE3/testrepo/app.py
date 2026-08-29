import subprocess
import hashlib

AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
GITHUB_TOKEN = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"

def run(user_input):
    # injection de commande volontaire, pour le test
    return subprocess.call("echo " + user_input, shell=True)

def weak_hash(pwd):
    return hashlib.md5(pwd.encode()).hexdigest()
