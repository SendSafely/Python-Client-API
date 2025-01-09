import json
import math
import os
import re

import requests
import cryptography
major, minor, patch = [int(x, 10) for x in cryptography.__version__.split('.')]
if major < 41:
    from cryptography import CryptographyDeprecationWarning
else:
    from cryptography.utils import CryptographyDeprecationWarning
from pgpy import PGPMessage
from sendsafely.Progress import Progress
import warnings

from sendsafely.exceptions import CreatePackageFailedException, FinalizePackageFailedException, DownloadFileException, \
    UploadFileException, DeletePackageException, KeycodeRequiredException, GetPackageInformationFailedException, \
    UploadKeycodeException, AddRecipientFailedException, UpdateRecipientFailedException, UploadMessageException, \
    GetPublicKeysFailedException, GetFileInformationException, DeleteFileException, GetPackageMessageException, \
    AddFileFailedException, MoveFileException, GetDirectoryException, DeleteDirectoryException, \
    RenameDirectoryException, UpdatePackageException, MoveDirectoryException, CreateDirectoryException

from sendsafely.utilities import _generate_keycode, make_headers, _encrypt_message, _encrypt_file_part, _upload_file_part_to_s3, \
    _calculate_package_checksum, _decrypt_message, _get_upload_urls, _get_download_urls, _update_file_completion_status, _encrypt_keycode, \
    delete_request, get_request


class Package:
    """
    To be used in conjunction with it's handler the SendSafely object. Should not be instantiated directly.
    """

    def __init__(self, sendsafely_instance, package_variables=None, workspace=False):
        """
        :param sendsafely_instance: The authenticated SendSafely object.
        :param package_variables:
        """
        super().__init__()
        warnings.filterwarnings('ignore', category=CryptographyDeprecationWarning)
        self.initialized_via_keycode = True
        if package_variables is None:
            self.client_secret = _generate_keycode()
            self.sendsafely = sendsafely_instance
            if workspace:
                data = {"vdr": "true"}
            else:
                data = {"vdr": "false"}
            endpoint = "/package"
            url = self.sendsafely.BASE_URL + endpoint
            headers = make_headers(self.sendsafely.API_SECRET, self.sendsafely.API_KEY, endpoint,
                                   request_body=json.dumps(data))
            response = requests.put(url, headers=headers, json=data).json()
            try:
                self.server_secret = response["serverSecret"]
                self.package_id = response["packageId"]
                self.package_code = response["packageCode"]
            except KeyError:
                raise CreatePackageFailedException(details=response["message"])
        else:
            self.sendsafely = sendsafely_instance
            self.package_id = package_variables["packageId"]
            self.package_code = package_variables["packageCode"]
            self.client_secret = package_variables["clientSecret"]
            if not self.client_secret:
                self.initialized_via_keycode = False
            self.server_secret = package_variables["serverSecret"]

    def delete_package(self):
        """
        Delete this package.
        """
        try:
            response = delete_request(self.sendsafely, "/package/" + self.package_id)
        except Exception as e:
            raise DeletePackageException(details=str(e))
        if response["response"] != "SUCCESS":
            raise DeletePackageException(response["message"])
        return response

    def get_info(self):
        """
        Get a detailed status of a given package
        :return: The detailed status as a JSON response.
        """
        try:
            response = get_request(self.sendsafely, "/package/" + self.package_id)
        except Exception as e:
            raise GetPackageInformationFailedException(details=str(e))
        if response["response"] != "SUCCESS":
            raise GetPackageInformationFailedException(details=response["message"])
        return response

    def add_recipient(self, email):
        """
        Adds a recipient to this package
        :param email: The email to add to this package
        :return:
        """
        sendsafely = self.sendsafely
        endpoint = "/package/" + self.package_id + "/recipient"
        url = sendsafely.BASE_URL + endpoint
        body = {'email': email}
        headers = make_headers(sendsafely.API_SECRET, sendsafely.API_KEY, endpoint, request_body=json.dumps(body))
        try:
            response = requests.put(url, headers=headers, json=body).json()
        except Exception as e:
            raise AddRecipientFailedException(details=str(e))
        if response["response"] != "SUCCESS":
            raise AddRecipientFailedException(details=response["message"])
        return response

    def update_recipient_phone_number(self, recipient_id, phone, country_code="US"):
        """
        Update a recipient phone number
        :param recipient_id: The id of the recipient
        :param phone: The desired phone number, string in the form "(123) 456-7890"
        :param country_code: The country code
        :return:
        """
        sendsafely = self.sendsafely
        endpoint = "/package/" + self.package_id + "/recipient/" + recipient_id
        url = sendsafely.BASE_URL + endpoint
        body = {'phoneNumber': phone, 'countrycode': country_code}
        headers = make_headers(sendsafely.API_SECRET, sendsafely.API_KEY, endpoint, request_body=json.dumps(body))
        try:
            response = requests.post(url, headers=headers, json=body).json()
        except Exception as e:
            raise UpdateRecipientFailedException(details=str(e))
        if response["response"] != "SUCCESS":
            raise UpdateRecipientFailedException(details=response["message"])
        return response

    def encrypt_and_upload_message(self, message):
        """
        Adds a message to this package
        :param message: the message to add
        :return: the JSON response
        """
        self._block_operation_without_keycode()
        try:
            encrypted_message = _encrypt_message(message_to_encrypt=message, server_secret=self.server_secret,
                                             client_secret=self.client_secret)
            body = {'message': encrypted_message}
            endpoint = "/package/" + self.package_id + "/message/"
            url = self.sendsafely.BASE_URL + endpoint
            headers = make_headers(self.sendsafely.API_SECRET, self.sendsafely.API_KEY, endpoint, request_body=json.dumps(body))
            response = requests.put(url, headers=headers, json=body).json()
        except Exception as e:
            raise UploadMessageException(details=str(e))
        if response["response"] != "SUCCESS":
            raise UploadMessageException(details=response["message"])
        return response

    def encrypt_and_upload_file(self, filepath, directory_id=None, progress_instance=None):
        """
        Adds the passed file to the package with the specified ID
        If bigger than 2621440 Bytes, split the file by 2621440 Bytes and set parts according to the amount of splits
        :param filepath: The path of the file we're uploading
        :return: The JSON response
        """
        self._block_operation_without_keycode()
        # TODO Throw an exception when 107.4Gb limit exceeded
        PART_SIZE = 2621440
        filesize = os.stat(filepath).st_size
        num_parts = 1
        if filesize > (PART_SIZE / 4):
            num_parts = 1 + math.ceil((filesize - (PART_SIZE / 4)) / PART_SIZE)
        filename = os.path.basename(filepath)
        add_file = self._add_file(filename, filesize, parts=num_parts, directory_id=directory_id)
        file_id = add_file["fileId"]
        file = open(filepath, 'rb')
        part = 1
        progress = 1
        try:
            while part <= num_parts:
                upload_urls = _get_upload_urls(self, file_id, part=part)
                for parts in upload_urls:
                    url = parts["url"]
                    chunk = file.read(PART_SIZE)
                    encrypted_bytes = _encrypt_file_part(chunk, server_secret=self.server_secret,
                                                         client_secret=self.client_secret, path=False)
                    _upload_file_part_to_s3(encrypted_file_part=encrypted_bytes, url=url)
                    if not progress_instance:
                        progress_instance = Progress()
                    self.calculate_progress(file_id, progress, num_parts, progress_instance)
                    progress = progress + 1
                part = part + 25
            file.close()
            response = _update_file_completion_status(self, file_id=file_id, directory_id=directory_id, complete=True)
            response["fileId"] = file_id
            return response
        except Exception as e:
            raise UploadFileException(details=str(e))

    def get_public_keys(self):
        endpoint = '/package/' + self.package_id + '/public-keys/'
        url = self.sendsafely.BASE_URL + endpoint
        headers = make_headers(self.sendsafely.API_SECRET, self.sendsafely.API_KEY, endpoint)
        response = requests.get(url=url, headers=headers).json()
        if response["response"] != "SUCCESS":
            raise GetPublicKeysFailedException(details=response["message"])
        return response["publicKeys"]

    def _upload_keycodes(self):
        # Get public keys available for the users
        public_keys = self.get_public_keys()
        uploaded = []
        # Upload keycodes
        for key in public_keys:
            public_key_id = key["id"]
            encrypted_keycode = _encrypt_keycode(self.client_secret, key["key"])
            endpoint = '/package/' + self.package_id + '/link/' + public_key_id
            url = self.sendsafely.BASE_URL + endpoint
            body = {"keycode": encrypted_keycode}
            headers = make_headers(self.sendsafely.API_SECRET, self.sendsafely.API_KEY, endpoint, request_body=json.dumps(body))
            response = requests.put(url=url, headers=headers, json=body).json()
            if response["response"] != "SUCCESS":
                raise UploadKeycodeException(details=response["message"])
            uploaded.append(public_key_id)
        return {"uploadedPublicKeyIds": uploaded}

    def finalize(self):
        """
        Finalizes the package, returns a link, including the keycode
        :returns: A link the recipient can access it with if successful
        """
        self._upload_keycodes()
        checksum = _calculate_package_checksum(package_code=self.package_code, keycode=self.client_secret)
        endpoint = '/package/' + self.package_id + '/finalize'
        url = self.sendsafely.BASE_URL + endpoint
        headers = make_headers(self.sendsafely.API_SECRET, self.sendsafely.API_KEY, endpoint, request_body=json.dumps(checksum))
        response = requests.post(url=url, json=checksum, headers=headers).json()
        if "errors" not in response:
            if self.initialized_via_keycode:
                keycode = "#keyCode=" + self.client_secret
                response["message"] = response["message"] + keycode
        else:
            raise FinalizePackageFailedException(details=str(response))
        return response

    def get_package_message(self):
        """
        :returns: The decrypted message
        """
        self._block_operation_without_keycode()
        try:
            checksum = _calculate_package_checksum(package_code=self.package_code, keycode=self.client_secret)
            endpoint = '/package/' + self.package_id + '/message/' + checksum["checksum"]
            url = self.sendsafely.BASE_URL + endpoint
            headers = make_headers(self.sendsafely.API_SECRET, self.sendsafely.API_KEY, endpoint)
            response = requests.get(url, headers=headers).json()
            message = _decrypt_message(response["message"], server_secret=self.server_secret,
                                       client_secret=self.client_secret)
            return message
        except Exception as e:
            raise GetPackageMessageException(details=str(e))

    def _add_file(self, filename, filesize, parts=1, directory_id=None):
        """
        Adds the passed file to the package with the specified ID
        If bigger than 2.5 MBs, split the file by 2.5 MBs and set parts according to the amount of splits
        """
        part_size = 2621440
        if filesize > part_size:
            parts = 1 + math.ceil((filesize - (part_size / 4)) / part_size)
        body = {
            'filename': filename,
            'parts': parts,
            'filesize': filesize
        }
        if directory_id:
            body["directoryId"] = directory_id
        endpoint = "/package/" + self.package_id + "/file"
        url = self.sendsafely.BASE_URL + endpoint
        headers = make_headers(self.sendsafely.API_SECRET, self.sendsafely.API_KEY, endpoint, request_body=json.dumps(body))
        try:
            response = requests.put(url=url, json=body, headers=headers).json()
        except Exception as e:
            raise AddFileFailedException(details=str(e))
        if response["response"] != "SUCCESS":
            raise AddFileFailedException(details=response["message"])
        return response

    def delete_file_from_package(self, file_id, directory_id=None):
        """
        Deletes the file with the specified id from the package with the specified ID
        """
        if directory_id:
            endpoint = "/package/" + self.package_id + "/directory/" + directory_id + "/file/" + file_id
        else:
            endpoint = "/package/" + self.package_id + "/file/" + file_id
        url = self.sendsafely.BASE_URL + endpoint
        headers = make_headers(self.sendsafely.API_SECRET, self.sendsafely.API_KEY, endpoint)
        try:
            response = requests.delete(url=url, headers=headers).json()
        except Exception as e:
            raise DeleteFileException(details=str(e))
        if response["response"] != "SUCCESS":
            raise DeleteFileException(details=response["message"])
        return response

    def get_file_information(self, file_id, directory_id=None):
        """
        Return the file information for a specified fileId
        """
        if directory_id:
            endpoint = "/package/" + self.package_id + "/directory/" + directory_id + "/file/" + file_id
        else:
            endpoint = "/package/" + self.package_id + "/file/" + file_id
        url = self.sendsafely.BASE_URL + endpoint
        headers = make_headers(self.sendsafely.API_SECRET, self.sendsafely.API_KEY, endpoint)
        response = requests.get(url=url, headers=headers).json()
        if response["response"] != "SUCCESS":
            raise GetFileInformationException(details=response["message"])
        return response["file"]

    def download_and_decrypt_file(self, file_id, directory_id=None, download_directory=".", file_name=None, progress_instance=None):
        """
        Downloads & decrypts the specified file to the path specified
        """
        self._block_operation_without_keycode()
        file_info = self.get_file_information(file_id, directory_id)
        if not file_name:
            file_name = file_info["fileName"]
        total = file_info["fileParts"]
        file_name = re.sub(r'[<>:\"/\\|?*]', '_', file_name)
        file_path = download_directory + "/" + file_name
        passphrase = self.server_secret + self.client_secret
        progress = 1
        start, end = 1, 25
        try:
            with open(file_path, "wb") as file:
                while start <= total:
                    parts = _get_download_urls(self, file_id, directory_id, start=start, end=end)
                    for part in parts:
                        response = bytes(requests.get(url=part["url"]).content)
                        ba = bytearray()
                        ba.extend(response)
                        message = PGPMessage.from_blob(ba)
                        decrypted = message.decrypt(passphrase=passphrase).message
                        if isinstance(decrypted, str):
                            decrypted = bytes(decrypted, "utf-8")
                        file.write(decrypted)
                        self.calculate_progress(file_id, progress, total, progress_instance)
                        progress = progress + 1
                    start, end = start + 25, end + 25
        except Exception as e:
            raise DownloadFileException(details=str(e))

    def update_workspace_name(self, workspace_name):
        """
        Rename a Workspace (packageLabel)
        """
        endpoint = "/package/" + self.package_id
        url = self.sendsafely.BASE_URL + endpoint
        body = {"label": workspace_name}
        headers = make_headers(self.sendsafely.API_SECRET, self.sendsafely.API_KEY, endpoint, request_body=json.dumps(body))
        try:
            response = requests.post(url=url, headers=headers, json=body).json()
        except Exception as e:
            raise UpdatePackageException(details=str(e))

        if response["response"] != "SUCCESS":
            raise UpdatePackageException(details=response["message"])
        return response

    def move_file(self, file_id, destination_directory_id):
        """
        Moves a Workspace file with the specified id to the directory with the specified ID
        """
        endpoint = "/package/" + self.package_id + "/directory/" + destination_directory_id + "/file/" + file_id
        url = self.sendsafely.BASE_URL + endpoint
        headers = make_headers(self.sendsafely.API_SECRET, self.sendsafely.API_KEY, endpoint)
        try:
            response = requests.post(url=url, headers=headers).json()
        except Exception as e:
            raise MoveFileException(details=str(e))

        if response["response"] != "SUCCESS":
            raise MoveFileException(details=response["message"])
        return response

    def create_directory(self, directory_name, source_directory_id=None):
        if not source_directory_id:
            source_directory_id = self.sendsafely.get_package_information(self.package_id)["rootDirectoryId"]
        endpoint = "/package/" + self.package_id + "/directory/" + source_directory_id + "/subdirectory/"
        url = self.sendsafely.BASE_URL + endpoint
        body = {"directoryName": directory_name}
        headers = make_headers(self.sendsafely.API_SECRET, self.sendsafely.API_KEY, endpoint, request_body=json.dumps(body))
        try:
            response = requests.put(url=url, headers=headers, json=body).json()
        except Exception as e:
            raise CreateDirectoryException(details=str(e))

        if response["response"] != "SUCCESS":
            raise CreateDirectoryException(details=response["message"])
        return response

    def move_directory(self, source_directory_id, target_directory_id):
        """
        Moves a Workspace directory with the specified id to the directory with the specified ID
        """
        endpoint = "/package/" + self.package_id + "/move/" + source_directory_id + "/" + target_directory_id
        url = self.sendsafely.BASE_URL + endpoint
        headers = make_headers(self.sendsafely.API_SECRET, self.sendsafely.API_KEY, endpoint)
        try:
            response = requests.post(url=url, headers=headers).json()
        except Exception as e:
            raise MoveDirectoryException(details=str(e))

        if response["response"] != "SUCCESS":
            raise MoveDirectoryException(details=response["message"])
        return response

    def get_directory_information(self, directory_id):
        endpoint = "/package/" + self.package_id + "/directory/" + directory_id
        url = self.sendsafely.BASE_URL + endpoint
        headers = make_headers(self.sendsafely.API_SECRET, self.sendsafely.API_KEY, endpoint)
        try:
            response = requests.get(url=url, headers=headers).json()
        except Exception as e:
            raise GetDirectoryException(details=str(e))

        if response["response"] != "SUCCESS":
            raise GetDirectoryException(details=response["message"])
        return response

    def delete_directory(self, directory_id):
        endpoint = "/package/" + self.package_id + "/directory/" + directory_id
        url = self.sendsafely.BASE_URL + endpoint
        headers = make_headers(self.sendsafely.API_SECRET, self.sendsafely.API_KEY, endpoint)
        try:
            response = requests.delete(url=url, headers=headers).json()
        except Exception as e:
            raise DeleteDirectoryException(details=str(e))

        if response["response"] != "SUCCESS":
            raise DeleteDirectoryException(details=response["message"])
        return response

    def rename_directory(self, directory_id, directory_name):
        endpoint = "/package/" + self.package_id + "/directory/" + directory_id
        url = self.sendsafely.BASE_URL + endpoint
        body = {"directoryName": directory_name}
        headers = make_headers(self.sendsafely.API_SECRET, self.sendsafely.API_KEY, endpoint, request_body=json.dumps(body))
        try:
            response = requests.post(url, headers=headers, json=body).json()
        except Exception as e:
            raise RenameDirectoryException(details=str(e))

        if response["response"] != "SUCCESS":
            raise RenameDirectoryException(details=response["message"])
        return response

    def _block_operation_without_keycode(self):
        if not self.initialized_via_keycode:
            raise KeycodeRequiredException()

    def calculate_progress(self, file_id, current, total, progress_instance):
        if not progress_instance:
            progress_instance = Progress()
        percent = (current / total) * 100
        percent = str(round(percent, 1))
        progress_instance.update_progress(file_id, percent)



