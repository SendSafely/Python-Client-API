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
directory_id = ""

def main():
    sendsafely = SendSafely(base_url, api_key, api_secret)
    workspace_package = Package(sendsafely, workspace=True)
    print("Successfully created new workspace " + workspace_package.package_id)

    workspace_package.update_workspace_name("MyWorkspace")
    print("Successfully updated Workspace name")

    secure_link = base_url + "/receive/?thread=" + workspace_package.package_id + "&packageCode=" + workspace_package.package_code + "#keyCode=" + workspace_package.client_secret
    print("Secure link is " + secure_link)

    directory_id = workspace_package.create_directory("MyDirectory")["directoryId"]
    print("Successfully created new directory " + directory_id)

    with open(upload_file, 'wb') as file:
        content = bytes("SendSafely lets you easily exchange encrypted files and information with anyone on any device.", "utf-8")
        file.write(content)

    f = workspace_package.encrypt_and_upload_file(upload_file, directory_id=directory_id)
    file_id = f["fileId"]
    print("Successfully encrypted and uploaded file id " + str(file_id) + " to " + directory_id)

    workspace_package.add_recipient(recipient)
    print("Successfully added recipient " + recipient)

    new_directory_id = workspace_package.create_directory("MyNewDirectory")["directoryId"]
    print("Successfully created new directory " + new_directory_id)

    workspace_package.move_file(file_id, new_directory_id)
    print("Moved file " + file_id + " to " + new_directory_id + "")

    workspace_package.move_directory(directory_id, new_directory_id)
    print("Moved directory " + directory_id + " to " + new_directory_id + "")

    workspace_package.download_and_decrypt_file(file_id, directory_id=new_directory_id, download_directory=download_dir, file_name=download_filename)
    print("Successfully downloaded and decrypted file " + download_filename)

    print("Package Info: ")
    print(json.dumps(workspace_package.get_info(), indent=4, sort_keys=True))

if __name__ == '__main__':
    main()