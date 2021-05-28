import json

from sendsafely import SendSafely, Package

# Edit these variables
api_key = ""
api_secret = ""
base_url = "https://companyabc.sendsafely.com"
# Make sure all directories exist on your file system
upload_file = "fileToUpload.txt"
download_filename = "fileDownloaded.txt"
download_dir = "."
recipient = "user@foobar.com"

def main():
    sendsafely = SendSafely(base_url, api_key, api_secret)
    package = Package(sendsafely)

    with open(upload_file, 'wb') as file:
        content = bytes("SendSafely lets you easily exchange encrypted files and information with anyone on any device.", "utf-8")
        file.write(content)

    f = package.encrypt_and_upload_file(upload_file)
    file_id = f["fileId"]
    print("Successfully encrypted and uploaded file id " + str(file_id))

    package.encrypt_and_upload_message("hello this is a message")
    print("Successfully encrypted and uploaded secure message")

    package.add_recipient(recipient)
    print("Successfully added recipient " + recipient)

    response = package.finalize()
    print("Successfully submitted package - link for sending: " + response["message"])

    package.download_and_decrypt_file(file_id, download_directory=download_dir, file_name=download_filename)
    print("Successfully downloaded and decrypted file " + download_filename)

    print("Package Info: ")
    print(json.dumps(package.get_info(), indent=4, sort_keys=True))

if __name__ == '__main__':
    main()