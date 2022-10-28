import json

import requests

from exceptions import DeleteFileException
from sendsafely import Package
from utilities import _generate_keycode, make_headers


class Workspace(Package):
    def __init__(self, sendsafely_instance, packageCode, keyCode):
        """
        The packageCode and keyCode are obtained from the Workspace page, inside https://corp.sendsafely.com/secure/workspace/
        :param sendsafely_instance: The authenticated SendSafely object.
        """
        self.sendsafely = sendsafely_instance
        package_variables = {}
        package_variables["packageId"] = packageCode
        package_variables["packageCode"] = packageCode
        package_variables["clientSecret"] = keyCode
        package_variables["serverSecret"] = ''
        super().__init__(sendsafely_instance, package_variables)
        self.initialized_via_keycode = True
        self.info = self.get_info()
        self.package_id = self.info["packageId"]
        self.server_secret = self.info["serverSecret"]
        self.root_directory = self.info["rootDirectoryId"]

    def get_workspaces(self, workspace_label: str = None, row_index: int = 0, page_size: int = 100):
        """
        :returns: The a list of workspaces in the account
        """
        endpoint = f'/package/workspaces/'
        url = self.sendsafely.BASE_URL + endpoint
        headers = make_headers(self.sendsafely.API_SECRET, self.sendsafely.API_KEY, endpoint)
        response = requests.get(url, headers=headers, params={'rowIndex': row_index, 'pageSize': page_size}).json()
        workspace_packages = response['packages']
        if workspace_label is not None:
            workspace_packages = [x for x in workspace_packages if x['packageLabel'] == workspace_label]

        return workspace_packages

    def list_workspace_files(self):
        """
        List all the files stored in the workspace
        :return: The JSON response
        """
        info = self.get_info()
        files_list = self._extract_files(info)
        return files_list

    def _extract_files(self, files_info: dict, parent_folder='/', directory_id=None):
        out_files = []
        files_list = files_info.get('files')
        if files_list is not None:
            for file in files_list:
                file['directory'] = parent_folder
                file['directoryId'] = directory_id
            out_files.extend(files_list)

        directory = files_info.get('directories') \
            if files_info.get('subDirectories') is None else files_info.get('subDirectories')
        if directory is None:
            return []
        else:
            for subfolder in directory:
                name = subfolder['name']
                subfolder_files = self._extract_files(subfolder, parent_folder=parent_folder + name + '/',
                                                      directory_id=subfolder['directoryId'])
                out_files.extend(subfolder_files)
        return out_files

    def _get_file_directory_id(self, file_name, workspace_directory):
        package_info = self.get_info()
        files = []
        if workspace_directory is None or workspace_directory in ('.', '/'):
            files = package_info.get('files')
            directory_id = None
        else:
            directories = package_info.get('directories')
            folders_list = [x for x in workspace_directory.split('/') if len(x) > 0]
            for sub_folder in folders_list:
                for dir in directories:
                    if dir['name'] == sub_folder:
                        if sub_folder == folders_list[-1]:
                            files = dir['files']
                            directory_id = dir['directoryId']
                        else:
                            directories = dir['subDirectories']

        assert len(files) > 0, f"No files found. File {file_name} not found"
        file_id = None
        for file in files:
            if file_name == file['fileName']:
                file_id = file['fileId']
        return file_id, directory_id

    def download_workspace_file(self, file_name, workspace_directory: str = None,
                                download_directory: str = ".", download_filename: str = None):
        """
        Downloads & decrypts the specified file to the path specified.

        :param file_name: Name of file to download
        :param workspace_directory: Subdirectory where the file is stored. Write folders like this /directory/sublevel1/sublevel2
        :param download_directory: Destination folder where the file will be downloaded

        """
        file_id, directory_id = self._get_file_directory_id(file_name, workspace_directory)
        if download_filename is None:
            download_filename = file_name
        self.download_and_decrypt_file(file_id,
                                       directory_id=directory_id,
                                       download_directory=download_directory,
                                       file_name=download_filename)

    def create_directory(self, directory_name):
        """
        Creates a new subdirectory in the workspace.
        :param directory_name: Nama of the new subdirectory
        :return: The JSON response
        """
        body = {"directoryName": directory_name}
        endpoint = '/package/' + self.package_id + '/directory/' + self.root_directory + '/subdirectory/'
        url = self.sendsafely.BASE_URL + endpoint
        headers = make_headers(self.sendsafely.API_SECRET, self.sendsafely.API_KEY, endpoint,
                               request_body=json.dumps(body))
        response = requests.put(url=url, headers=headers, json=body).json()
        return response

    def encrypt_and_upload_file(self, filepath, directory_name=None, directory_id=None, progress_instance=None):
        """
        Adds the passed file to the package with the specified workspace
        If bigger than 2621440 Bytes, split the file by 2621440 Bytes and set parts according to the amount of splits
        :param filepath: The path of the file we're uploading
        :param directory_name: The subdirectory where the file will be uploaded
        :return: The JSON response
        """
        if directory_name is not None and directory_id is None:
            directory_id = None
            package_info = self.get_info()
            directories = package_info.get('directories')
            folders_list = [x for x in directory_name.split('/') if len(x) > 0]
            for sub_folder in folders_list:
                for dir in directories:
                    if dir['name'] == sub_folder:
                        if sub_folder == folders_list[-1]:
                            directory_id = dir['directoryId']
            assert directory_id is not None, f"Error directory {directory_name} not found"

        response = super().encrypt_and_upload_file(filepath=filepath,
                                                   directory_id=directory_id,
                                                   progress_instance=progress_instance)
        return response

    def delete_workspace_file(self, file_name, workspace_directory):
        """
        Deletes the file with the specified name from the specified directory
        """
        file_id, directory_id = self._get_file_directory_id(file_name, workspace_directory)
        if directory_id is None:
            directory_id = self.root_directory

        endpoint = '/package/' + self.package_id + '/directory/' + directory_id + '/file/' + file_id
        url = self.sendsafely.BASE_URL + endpoint
        headers = make_headers(self.sendsafely.API_SECRET, self.sendsafely.API_KEY, endpoint)
        try:
            response = requests.delete(url=url, headers=headers).json()
        except Exception as e:
            raise DeleteFileException(details=e)
        if response["response"] != "SUCCESS":
            raise DeleteFileException(details=response["message"])
        return response
