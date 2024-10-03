import json
import re
import warnings

import requests
import pgpy
import cryptography
major, minor, patch = [int(x, 10) for x in cryptography.__version__.split('.')]
if major < 41:
    from cryptography import CryptographyDeprecationWarning
else:
    from cryptography.utils import CryptographyDeprecationWarning
from pgpy import PGPMessage
from pgpy.constants import KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm, PubKeyAlgorithm
from sendsafely.Package import Package
from sendsafely.exceptions import GetPackagesException, GetUserInformationException, TrustedDeviceException, \
    DeletePackageException, GetPackageInformationFailedException, GetKeycodeFailedException
from sendsafely.utilities import make_headers, _get_string_from_file


class SendSafely:
    """
    Class used to setup authentication and interface with the REST API
    Acts as a handler for the specific queries one may perform either on packages, or more generally as a user
    """
    API_URL = "/api/v2.0"
    BASE_URL = None
    API_KEY = None
    API_SECRET = None
    KEY_PAIR = None
    KEY_ID = None

    def __init__(self, url, api_key, api_secret):
        super().__init__()
        warnings.filterwarnings('ignore', category=CryptographyDeprecationWarning)
        self.BASE_URL = url + self.API_URL
        self.API_KEY = api_key
        self.API_SECRET = api_secret

    def load_package_from_link(self, link):
        """
        Creates a package object from a secure link
        :param link: The link
        :return: The Package associated with that link.
        """
        tokens = re.split('[?&#]', link)
        package_code = [item for item in tokens if item.startswith("packageCode=")][0].split("packageCode=")[-1]
        try:
            client_secret = [item for item in tokens if item.startswith("keyCode=")][0].split("keyCode=")[-1]
        except IndexError:
            client_secret = [item for item in tokens if item.startswith("keycode=")][0].split("keycode=")[-1]
        if "#" in package_code:
            package_code = re.split('#', package_code)[0]
        package_information = self.get_package_information(package_code)
        package_id = package_information["packageId"]
        return self.load_package(package_id=package_id, key_code=client_secret)

    def get_user_information(self):
        endpoint = "/user"
        url = self.BASE_URL + endpoint
        headers = make_headers(self.API_SECRET, self.API_KEY, endpoint)
        try:
            response = requests.get(url, headers=headers).json()
        except Exception as e:
            raise GetUserInformationException(details=str(e))
        if response["response"] != "SUCCESS":
            raise GetUserInformationException(details=response["message"])
        return response

    def generate_trusted_device_key_pair(self, description):
        """
       Adds a public key to this user
       :param description: A description of this public key to submit to SendSafely
       :return: The response, including key pair
       """
        email = self.get_user_information()["email"]
        key = pgpy.PGPKey.new(pgpy.constants.PubKeyAlgorithm.RSAEncryptOrSign, 2048)
        uid = pgpy.PGPUID.new('Trusted Browser', email=email)
        key.add_uid(uid=uid, usage={KeyFlags.Sign, KeyFlags.Certify},
                    hashes=[HashAlgorithm.SHA256],
                    ciphers=[SymmetricKeyAlgorithm.AES256],
                    compression=[CompressionAlgorithm.Uncompressed])
        subkey = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
        key.add_subkey(subkey, usage={KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage})
        public_key = str(key.pubkey)
        endpoint = "/public-key"
        url = self.BASE_URL + endpoint
        body = {
          "publicKey": public_key,
          "description": description
        }
        headers = make_headers(self.API_SECRET, self.API_KEY, endpoint, request_body=json.dumps(body))
        response = requests.put(url, headers=headers, json=body).json()
        if response["response"] != "SUCCESS":
            raise TrustedDeviceException(details=response["message"])
        self.KEY_ID = response["id"]
        self.KEY_PAIR = key
        result = {"response": response, "privateKey": str(key), "publicKey": public_key}
        return result

    def revoke_trusted_device_key(self, public_key_id):
        """
        Removes the public key with public_key_id from this account.
        :param public_key_id: The public key ID
        :return: the JSON response
        """
        endpoint = "/public-key/" + public_key_id
        url = self.BASE_URL + endpoint
        headers = make_headers(self.API_SECRET, self.API_KEY, endpoint)
        try:
            response = requests.delete(url, headers=headers).json()
        except Exception as e:
            raise TrustedDeviceException(details=str(e))
        if response["response"] != "SUCCESS":
            raise TrustedDeviceException(details=response["message"])
        return response

    def get_package_keycode(self, package_id, public_key_id=None, private_key=None):
        """
        Gets the decrypted package keycode using trusted device keys.
        Trusted device must have been assigned prior to the package being uploaded.
        :param package_id: The package Id
        :param public_key_id: The public key id for the trusted device
        :param private_key: The private trusted device key
        :return:
        """
        #if path_to_keys:
        #    data = read_key_pair(path_to_keys)
        #    public_key_id = data["publicKeyId"]
        #    private_key = data["privateKey"]
        if public_key_id is None or private_key is None:
            public_key_id = self.KEY_ID
            private_key = self.KEY_PAIR
        endpoint = '/package/' + package_id + '/link/' + public_key_id
        url = self.BASE_URL + endpoint
        headers = make_headers(self.API_SECRET, self.API_KEY, endpoint)
        try:
            keycode_json = requests.get(url, headers=headers).json();
            keycode = keycode_json['message'];
            if keycode_json['response'] == 'FAIL':
                raise GetKeycodeFailedException(details=str(keycode))

            key_pair = pgpy.PGPKey.from_blob(str(private_key))[0]
            keycode_message = PGPMessage.from_blob(keycode)
            decrypted_keycode = key_pair.decrypt(keycode_message).message
            return {"keyCode": decrypted_keycode}
        except Exception as e:
            raise GetKeycodeFailedException(details=str(e))

    def load_package(self, package_id, key_code=None):
        """
        Builds a Package object from information about that package
        :param package_id: The Package ID
        :param key_code: The client secret/keycode for this package (optional)
        :return: The Package Object.
        """
        package_information = self.get_package_information(package_id)
        server_secret = package_information["serverSecret"]
        package_code = package_information["packageCode"]
        if key_code:
            key_code = _get_string_from_file(key_code)
        package_variables = {
            "packageId": package_id,
            "serverSecret": server_secret,
            "packageCode": package_code,
            "clientSecret": key_code
        }
        return Package(self, package_variables=package_variables)

    def delete_package(self, package_id):
        """
        Deletes a given package.
        :param package_id: the package you desire to delete.
        :return: the JSON response.
        """
        endpoint = "/package/" + package_id
        url = self.BASE_URL + endpoint
        headers = make_headers(self.API_SECRET, self.API_KEY, endpoint)
        try:
            response = requests.delete(url, headers=headers).json()
        except Exception as e:
            raise DeletePackageException(details=str(e))
        if response["response"] != "SUCCESS":
            raise DeletePackageException(details=response["message"])
        return response

    def get_package_information(self, package_id):
        """
        Get a detailed status of a given package
        :param package_id: The package you desire to inquire about.
        :return: The detailed status as a JSON response.
        """
        endpoint = "/package/" + package_id
        url = self.BASE_URL + endpoint
        headers = make_headers(self.API_SECRET, self.API_KEY, endpoint)
        try:
            response = requests.get(url, headers=headers).json()
        except Exception as e:
            raise GetPackageInformationFailedException(details=str(e))
        if response["response"] != "SUCCESS":
            raise GetPackageInformationFailedException(details=response["message"])
        return response

    def get_package_information_from_link(self, link):
        """
        Get a detailed status of a given package given a secure link
        :param link: The secure link.
        :return: The detailed status as a JSON response.
        """
        tokens = re.split('[?&#]', link)
        package_code = [item for item in tokens if item.startswith("packageCode=")][0].split("packageCode=")[-1]
        return self.get_package_information(package_code)

    def get_received_packages(self, row_index=0, page_size=100):
        """
        Get all packages received by this user.
        :param row_index: The row to start at
        :param page_size: The number of pages to fetch at a time
        :return: The JSON response as a list of packages
        """
        endpoint = "/package/received"
        url = self.BASE_URL + endpoint
        all_packages = []
        pagination_data = []
        try:
            while True:
                params = {
                    "rowIndex": row_index,
                    "pageSize": page_size
                }
                headers = make_headers(self.API_SECRET, self.API_KEY, endpoint)
                response = requests.get(url, headers=headers, params=params).json()
                pagination = response["pagination"]
                pagination_data.append(pagination)
                packages = response["packages"]
                all_packages.extend(packages)
                if len(packages) < page_size:
                    return {"packages": all_packages, "pagination": pagination_data}
                row_index += page_size
        except Exception as e:
            raise GetPackagesException(details=str(e))

    def get_sent_packages(self, row_index=0, page_size=100):
        """
        Get all packages sent by this user
        :param row_index: The row to start at
        :param page_size: The number of pages to fetch at a time
        :return: The JSON response as a list of packages
        """
        endpoint = "/package"
        url = self.BASE_URL + endpoint
        all_packages = []
        pagination_data = []
        try:
            while True:
                params = {
                    "rowIndex": row_index,
                    "pageSize": page_size
                }
                headers = make_headers(self.API_SECRET, self.API_KEY, endpoint)
                response = requests.get(url, headers=headers, params=params).json()
                pagination = response["pagination"]
                pagination_data.append(pagination)
                packages = response["packages"]
                all_packages.extend(packages)
                if len(packages) < page_size:
                    return {"packages": all_packages, "pagination": pagination_data}
                row_index += page_size
        except Exception as e:
            GetPackagesException(details=str(e))
