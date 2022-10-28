import json

from Workspace import Workspace
from sendsafely import SendSafely, Package

# Edit these variables
api_key = ""
api_secret = ""
packageCode = ""
keyCode = ""
base_url = "https://companyabc.sendsafely.com"
# Make sure all directories exist on your file system
upload_file = "fileToUpload.txt"
download_filename = "fileDownloaded.txt"
download_dir = "."
workspace_label = 'New Workspace'

def main():
    sendsafely = SendSafely(base_url, api_key, api_secret)
    workspace = Workspace(sendsafely, packageCode=packageCode,
                          keyCode=keyCode)

    with open(upload_file, 'wb') as file:
        content = bytes("SendSafely lets you easily exchange encrypted files and information with anyone on any device.", "utf-8")
        file.write(content)


    response=workspace.create_directory('new_folder')
    print(json.dumps(response, indent=4, sort_keys=True))

    f = workspace.encrypt_and_upload_file(upload_file, directory_name='new_folder')
    file_id = f["fileId"]
    print("Successfully encrypted and uploaded file id " + str(file_id))

    files = workspace.list_workspace_files()
    print(json.dumps(files, indent=4, sort_keys=True))

    workspace.download_workspace_file(workspace_directory='new_folder', file_name=upload_file,
                                      download_filename=download_filename)
    print("Successfully downloaded and decrypted file " + download_filename)

    response = workspace.delete_workspace_file(workspace_directory='new_folder', file_name=upload_file)
    print("Successfully removed file")

if __name__ == '__main__':
    main()
