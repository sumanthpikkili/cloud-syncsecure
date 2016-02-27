
#Author: Sumanth Pikkili
#UTA ID: 1001100941
#CSE 6331 - Cloud Computing
#Assignment - 1
#The Program encrypts a file using AES Algorithm and syncs with Google Drive / Dropbox

import os, random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import dropbox
import getpass
import httplib2
import pprint
from apiclient.discovery import build
from apiclient.http import MediaFileUpload
from oauth2client.client import OAuth2WebServerFlow

#Encryption
def encrypt(key, filename):
	chunksize = 64*1024
	outputFile = "(encrypted)"+filename
	filesize = str(os.path.getsize(filename)).zfill(16)
	IV = ''

	for i in range(16):
		IV += chr(random.randint(0, 0xFF))

	encryptor = AES.new(key, AES.MODE_CBC, IV)

	with open(filename, 'rb') as infile:
		with open(outputFile, 'wb') as outfile:
			outfile.write(filesize)
			outfile.write(IV)
			
			while True:
				chunk = infile.read(chunksize)
				
				if len(chunk) == 0:
					break
				elif len(chunk) % 16 != 0:
					chunk += ' ' * (16 - (len(chunk) % 16))

				outfile.write(encryptor.encrypt(chunk))

#Decryption
def decrypt(key, filename):
	chunksize = 64*1024
	outputFile = filename[11:]
	
	with open(filename, 'rb') as infile:
		filesize = long(infile.read(16))
		IV = infile.read(16)

		decryptor = AES.new(key, AES.MODE_CBC, IV)

		with open(outputFile, 'wb') as outfile:
			while True:
				chunk = infile.read(chunksize)

				if len(chunk) == 0:
					break

				outfile.write(decryptor.decrypt(chunk))
			outfile.truncate(filesize)


def getKey(password):
	hasher = SHA256.new(password)
	return hasher.digest()

def Main():
	
# App Key and Secret obtained from the Dropbox developer website
	app_key = raw_input("Please enter your app key")
	app_secret = raw_input("Please enter your app secret)
	flow = dropbox.client.DropboxOAuth2FlowNoRedirect(app_key, app_secret)
	access_token = raw_input("Please enter your access token")

choice = raw_input("Which action would you like to perform? :\n\nA: Upload to Dropbox \nB: Download from Dropbox to Local  \nC: Upload to Google Drive\nD: Sync with Google Drive and Dropbox\n")
if choice == 'A':
		#Uploading to DropBox
		# App Key and Secret obtained from the Dropbox developer website
        	app_key = raw_input("Please enter your app key")
        	app_secret = raw_input("Please enter your app secret)
        	flow = dropbox.client.DropboxOAuth2FlowNoRedirect(app_key, app_secret)
      	        access_token = raw_input("Please enter your access token")
		#Accessing Drop Box Client
                client = dropbox.client.DropboxClient(access_token)
		filename = raw_input("File to encrypt: ")
		password = getpass.getpass("Password: ")
		encrypt(getKey(password), filename)
		encrypted_file = "(encrypted)"+filename
                f = open(encrypted_file, 'rb')
		response = client.put_file(encrypted_file, f)
                print "File uploaded to Dropbox"
		
elif choice == 'B':
		#Download from DropBox to Local
		# App Key and Secret obtained from the Dropbox developer website
                app_key = raw_input("Please enter your app key")
                app_secret = raw_input("Please enter your app secret)
                flow = dropbox.client.DropboxOAuth2FlowNoRedirect(app_key, app_secret)
                access_token =raw_input("Please enter your access token")
                #Accessing Drop Box Client
                client = dropbox.client.DropboxClient(access_token)
		filename = raw_input("File to decrypt: ")
		encrypted_file = "(encrypted)"+filename
                f,metadata = client.get_file_and_metadata(encrypted_file)
                out = open(encrypted_file, 'wb')
                out.write(f.read())
                out.close()
		password = getpass.getpass("Password: ")
		decrypt(getKey(password), encrypted_file)
		print "Decrypted version of File downloaded to the local machine"

elif choice == 'C':
		#Upload to Google Drive
		# Credentials from the Console
		CLIENT_ID = raw_input("Please enter the google client ID")
		CLIENT_SECRET = raw_input("Please enter the client secret")

		# Checking https://developers.google.com/drive/scopes for all available scopes
		OAUTH_SCOPE = 'https://www.googleapis.com/auth/drive'
		REDIRECT_URI = 'https://www.example.com/oauth2callback'
		filename =  raw_input("Please enter the name of the File to Encrypt and Upload to Google Drive\n")
		password = getpass.getpass("Password: ")
		encrypt(getKey(password), filename)
		encrypted_file = "(encrypted)"+filename
		# Run through the OAuth flow and retrieve credentials
		flow = OAuth2WebServerFlow(CLIENT_ID, CLIENT_SECRET, OAUTH_SCOPE,
                           redirect_uri=REDIRECT_URI)
		authorize_url = flow.step1_get_authorize_url()
		print 'Go to the following link in your browser:\n ' + authorize_url
		code = raw_input('Enter verification code:\n ').strip()
		credentials = flow.step2_exchange(code)

		# Creating an httplib2.Http object and authorize it with our credentials
		http = httplib2.Http()
		http = credentials.authorize(http)
		drive_service = build('drive', 'v2', http=http)

		# Insert a file
		media_body = MediaFileUpload(encrypted_file, mimetype='text/plain', resumable=True)
		body = {
  		'title': encrypted_file,
  		'description': 'A test document',
  		'mimeType': 'text/plain'
		}

		file = drive_service.files().insert(body=body, media_body=media_body).execute()
		print "The file has been encrypted and uploaded to Google Drive"

elif choice == 'D':
		#Sync with DropBox and Google Drive
		#Uploading to Dropbox
		app_key = raw_input("Please enter your app key")
        	app_secret = raw_input("Please enter your app secret")
        	flow = dropbox.client.DropboxOAuth2FlowNoRedirect(app_key, app_secret)
      	        access_token = raw_input("Please enter your access token")
		#Accessing Drop Box Client
                client = dropbox.client.DropboxClient(access_token)
		filename = raw_input("Please enter the name of the file to be uploaded\n")
		password = getpass.getpass("Password (Digital Signature):\n")
		encrypt(getKey(password), filename)
		encrypted_file = "(encrypted)"+filename
		f = open(encrypted_file, 'rb')
		response = client.put_file(encrypted_file, f)

		#Uploading to Google Drive
                CLIENT_ID = raw_input("Please enter your client ID")
		CLIENT_SECRET = raw_input("Please enter your client secret")
		# Checking https://developers.google.com/drive/scopes for all available scopes
		OAUTH_SCOPE = 'https://www.googleapis.com/auth/drive'
		REDIRECT_URI = 'https://www.example.com/oauth2callback'
		# Run through the OAuth flow and retrieve credentials
		flow = OAuth2WebServerFlow(CLIENT_ID, CLIENT_SECRET, OAUTH_SCOPE,
                           redirect_uri=REDIRECT_URI)
		authorize_url = flow.step1_get_authorize_url()
		print 'Go to the following link in your browser:\n ' + authorize_url
		code = raw_input('Enter verification code:\n ').strip()
		credentials = flow.step2_exchange(code)
		# Creating an httplib2.Http object and authorize it with our credentials
		http = httplib2.Http()
		http = credentials.authorize(http)
		drive_service = build('drive', 'v2', http=http)

		# Insert a file
		media_body = MediaFileUpload(encrypted_file, mimetype='text/plain', resumable=True)
		body = {
  		'title': encrypted_file,
  		'description': 'A test document',
  		'mimeType': 'text/plain'
		}

		file = drive_service.files().insert(body=body, media_body=media_body).execute()
		print "The file has been synced with DropBox and Google Drive"


else:
		print "Wrong / No Option selected, Exiting..."

if __name__ == '__main__':
	Main()
