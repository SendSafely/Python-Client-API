#################################################
#
# Note to Developer
#
# The functions in this file prefixed with an underscore 
#   are intended for internal use only.
#
#################################################

import base64
import binascii
import datetime
import hashlib
import hmac
import json
import os
import secrets

import pgpy
import requests
from pgpy import PGPMessage
from pgpy.constants import HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm, KeyFlags
from pgpy.packet.subpackets.signature import FlagList

def _encrypt_file_part(file, server_secret, client_secret, path=True):
    """
    Encrypts a given file part for uploading to SendSafely.
    :param file: The path of the file (as a String) or a file as bytes. Set path param to False if using bytes.
    :param server_secret: The server secret, may be obtained through using
    SendSafely.get_package_information(package_id)
    :param client_secret: The client_secret (a.k.a. keycode) used to ensure only the holders of the link
    are able to decrypt.
    :return: The encrypted file (as bytes)
    """
    passphrase = server_secret + client_secret
    message = PGPMessage.new(
        file=path,
        message=file,
        compression=CompressionAlgorithm.Uncompressed)
    cipher_message = message.encrypt(passphrase=passphrase,
                                     cipher=SymmetricKeyAlgorithm.AES256,
                                     hash=HashAlgorithm.SHA256)
    return cipher_message.__bytes__()


def _generate_keycode():
    """
    Generates client_secret that is used for encrypting files
    as well as keycode for finalize package
    :returns: A random 256-bit alphanumerical string in hex
    """

    keycode = secrets.token_bytes(32)
    return _make_safe_for_urlsafebase64(str(base64.urlsafe_b64encode(keycode).decode('utf-8')))


def make_headers(api_secret, api_key, endpoint, request_body=None):
    """
    Makes headers used for secure requests against the SendSafely API
    :param api_secret: Your API secret, from the SendSafely handler.
    :param api_key: Your API_KEY, from the SendSafely handler.
    :param endpoint: Everything after the Fully Qualified Domain Name.
    :param request_body: The request body. If you're passing in a JSON object, make sure you wrap it in json.dumps()
    :return: The headers appropriate for the HTTP Request you're about to make.
    """
    if request_body is None:
        request_body = ""
    timestamp = (datetime.datetime.utcnow().isoformat())[0:19] + '+0000'
    endpoint = "/api/v2.0" + endpoint
    message_string = api_key + endpoint + timestamp + str(request_body)
    signature = _sign_message(api_secret, message_string)
    headers = {
        'ss-api-key': api_key,
        'ss-request-timestamp': timestamp,
        'ss-request-signature': signature,
        'ss-request-api': "PYTHON_API"
    }
    return headers


def _sign_message(api_secret, message_string):
    """
    Signs a message to ensure the server knows it's us that made the request.
    :param api_secret: Your API secret, obtained from creating a new API Key+secret in the edit profile page.
    :param message_string: The message we're signing.
    :return:
    """
    secret = bytes(api_secret, 'utf-8')
    signature = hmac.new(secret, bytes(message_string, 'utf-8'), digestmod=hashlib.sha256).hexdigest()
    return signature


def _encrypt_message(message_to_encrypt, server_secret, client_secret):
    """
    Encrypts a message (from a String)
    :param message_to_encrypt: The message we're encrypting
    :param server_secret: The server secret, obtained by inspecting a package
    :param client_secret: The client secret, obtained by inspecting a package
    :return: The encrypted message
    """
    passphrase = server_secret + client_secret
    message = PGPMessage.new(message_to_encrypt, compression=CompressionAlgorithm.Uncompressed)
    cipher_message = message.encrypt(passphrase=passphrase, cipher=SymmetricKeyAlgorithm.AES256,
                                     hash=HashAlgorithm.SHA256)
    return base64.b64encode(bytes(cipher_message)).decode('utf-8')

def _inject_encryption_flags(user, key_flags=True, hash=True, symmetric=True, compression=True):
    if not key_flags:
        user.selfsig._signature.subpackets.addnew('KeyFlags', hashed=True,
                                              flags={KeyFlags.EncryptCommunications,
                                                     KeyFlags.EncryptStorage})
        user.selfsig._signature.subpackets['h_KeyFlags'] = user.selfsig._signature.subpackets['KeyFlags'][0]
    if not hash:
        user.selfsig._signature.subpackets.addnew('PreferredHashAlgorithms', hashed=True, flags=[HashAlgorithm.SHA256])
    if not symmetric:
        user.selfsig._signature.subpackets.addnew('PreferredSymmetricAlgorithms', hashed=True,
                                                  flags=[SymmetricKeyAlgorithm.AES256])
    if not compression:
        user.selfsig._signature.subpackets.addnew('PreferredCompressionAlgorithms', hashed=True,
                                                  flags=[CompressionAlgorithm.Uncompressed])

def _enforce_encryption_flags(user):
    # https://github.com/SecurityInnovation/PGPy/issues/257
    # PGPY requires KeyFlags.EncryptCommunications and KeyFlags.EncryptStorage for public key to encrypt
    # which we are not setting in our current APIs
    # the following code injects the require attributes to the public key signature to bypass PGPY check
    has_key_flags, has_hash, has_symmetric, has_compression = True, True, True, True
    key_flags = user.selfsig._signature.subpackets['h_KeyFlags']
    hash = user.selfsig._signature.subpackets['h_PreferredHashAlgorithms']
    symmetric = user.selfsig._signature.subpackets['h_PreferredSymmetricAlgorithms']
    compression = user.selfsig._signature.subpackets['h_PreferredCompressionAlgorithms']
    if (len(key_flags) > 0 and len(hash) > 0 and len(symmetric) > 0 and len(compression) > 0):
        key_flags, hash, symmetric, compression = key_flags[0], hash[0], symmetric[0], compression[0]
    else:
        _inject_encryption_flags(user, False, False, False, False)
        return

    if not (KeyFlags.EncryptStorage in key_flags.__flags__ and KeyFlags.EncryptCommunications in key_flags.__flags__):
        has_key_flags = False
    if not HashAlgorithm.SHA256 in hash.__flags__:
        has_hash = False
    if not SymmetricKeyAlgorithm.AES256 in symmetric.__flags__:
        has_symmetric = False
    if not CompressionAlgorithm.Uncompressed in compression.__flags__:
        has_compression = False

    _inject_encryption_flags(user, has_key_flags, has_hash, has_symmetric, has_compression)
    return user

def _encrypt_keycode(keycode, public_key):
    """
    Encrypts a keycode with a public key
    :param keycode
    :param public_key
    :return: The encrypted keycode
    """
    key_pair = pgpy.PGPKey.from_blob(public_key)[0]
    user = None
    if key_pair.is_primary:
        if user is not None:
            user = key_pair.get_uid(user)
        else:
            user = next(iter(key_pair.userids))

    if user is not None:
        _enforce_encryption_flags(user)
        message = PGPMessage.new(keycode, compression=CompressionAlgorithm.Uncompressed,
                                 cipher=SymmetricKeyAlgorithm.AES256,
                                 hash=HashAlgorithm.SHA256)
        cipher_message = key_pair.encrypt(message)
        return str(cipher_message)


def _decrypt_message(message_to_decrypt, server_secret, client_secret):
    """
    Decrypts a message
    :param message_to_decrypt: The string you'd like decrypted.
    :param server_secret: The server secret, obtained by inspecting a package
    :param client_secret: The client_secret (a.k.a. keycode) used to ensure only the holders of the link
    are able to decrypt.
    :return: The decrypted message.
    """
    passphrase = server_secret + client_secret
    message_bytes = base64.b64decode(bytes(message_to_decrypt, 'utf-8'))
    pgpmessage = PGPMessage.from_blob(message_bytes)
    decrypted = pgpmessage.decrypt(passphrase=passphrase).message
    return decrypted


def _upload_file_part_to_s3(encrypted_file_part, url):
    """
    Upload a file/part of a file to the Amazon S3 Bucket used by SendSafely
    Body must ONLY include file in binary format
    Content-Type must NOT be specified
    :param encrypted_file_part: Part of a file to upload to S3. Must not exceed 2621440 Bytes.
    :param url: The S3 URL we're uploading to
    :return: The JSON response from S3.
    """
    return requests.put(url=url, data=encrypted_file_part)


def _calculate_package_checksum(package_code, keycode):
    """
    Calculates the checksum of a package using keycode (Client Secret) and Package Code
    Checksum is generated using PBKDF2-HMAC-SHA256 with keycode as the password, and Package Code as salt.
    :param keycode: Use the keycode as password
    :param package_code: Use the package code as salt
    :returns: The calculated checksum
    """
    password = bytes(keycode, 'utf-8')
    salt = bytes(package_code, 'utf-8')
    checksum = binascii.hexlify(hashlib.pbkdf2_hmac('sha256', password, salt, 1024))
    return {'checksum': checksum.decode('utf-8')}


def _get_upload_urls(package, file_id, part=1):
    """
    Retrieves the S3 upload URLs from SendSafely
    :param file_id: The file_id (string) we're querying for, as there may be many files in a single package.
    May retrieve file_id from SendSafely.get_package function
    :param part: The part index (int) to start from.
    :return: the URLs, as a list.
    """
    sendsafely = package.sendsafely
    endpoint = "/package/" + package.package_id + "/file/" + file_id + "/upload-urls/"
    url = sendsafely.BASE_URL + endpoint
    body = {'part': part}
    headers = make_headers(sendsafely.API_SECRET, sendsafely.API_KEY, endpoint, request_body=json.dumps(body))
    upload_urls = requests.post(url=url, json=body, headers=headers).json()["uploadUrls"]
    return upload_urls


def _update_file_completion_status(package, file_id, directory_id=None, complete=False):
    """
    Sets the file upload status as complete, the server will verify if all segments have been uploaded
    :param file_id: The ID (string) of the file we're updating (must be associated with the package_id from previously)
    :param complete: Whether the file is complete or not (boolean).
    :return: The response from SendSafely (JSON)
    """
    endpoint = '/package/' + package.package_id + '/file/' + file_id + '/upload-complete'
    url = package.sendsafely.BASE_URL + endpoint
    body = {'complete': complete}
    if directory_id is not None:
        body['directoryId'] = directory_id
    headers = make_headers(package.sendsafely.API_SECRET, package.sendsafely.API_KEY, endpoint, request_body=json.dumps(body))
    return requests.post(url=url, json=body, headers=headers).json()


def _get_download_urls(package, file_id, directory_id=None, start=1, end=25):
    checksum = _calculate_package_checksum(package_code=package.package_code, keycode=package.client_secret)
    sendsafely = package.sendsafely
    endpoint = "/package/" + package.package_id + "/file/" + file_id + "/download-urls"
    if directory_id:
        endpoint = "/package/" + package.package_id + "/directory/" + directory_id + "/file/" + file_id + "/download-urls"
    url = sendsafely.BASE_URL + endpoint
    body = {
        "checksum": checksum["checksum"],
        "startSegment": start,
        "endSegment": end
    }
    headers = make_headers(sendsafely.API_SECRET, sendsafely.API_KEY, endpoint, request_body=json.dumps(body))
    response = requests.post(url=url, json=body, headers=headers).json()
    return response["downloadUrls"]


def get_request(sendsafely, endpoint):
    url = sendsafely.BASE_URL + endpoint
    headers = make_headers(sendsafely.API_SECRET, sendsafely.API_KEY, endpoint)
    response = requests.get(url, headers=headers).json()
    return response


def delete_request(sendsafely, endpoint):
    url = sendsafely.BASE_URL + endpoint
    headers = make_headers(sendsafely.API_SECRET, sendsafely.API_KEY, endpoint)
    response = requests.delete(url, headers=headers).json()
    return response


def post_request(sendsafely, endpoint, body):
    url = sendsafely.BASE_URL + endpoint
    headers = make_headers(sendsafely.API_SECRET, sendsafely.API_KEY, endpoint, request_body=json.dumps(body))
    response = requests.post(url, json=body, headers=headers).json()
    return response


def put_request(sendsafely, endpoint, body):
    url = sendsafely.BASE_URL + endpoint
    headers = make_headers(sendsafely.API_SECRET, sendsafely.API_KEY, endpoint, request_body=json.dumps(body))
    response = requests.put(url, json=body, headers=headers).json()
    return response


def patch_request(sendsafely, endpoint, body):
    url = sendsafely.BASE_URL + endpoint
    headers = make_headers(sendsafely.API_SECRET, sendsafely.API_KEY, endpoint, request_body=json.dumps(body))
    response = requests.patch(url, json=body, headers=headers).json()
    return response


def _get_string_from_file(filename):
    if os.path.exists(os.path.dirname(filename)):
        with open(filename) as f:
            result = f.readline()
            return result
    return filename


def _pretty_print(json_response):
    json.dumps(json_response, indent=2)
    json_object = json.loads(json_response)
    pretty = json.dumps(json_object, indent=2)
    print(pretty)


def save_key_pair(key_id, key_pair, path_to_save):
    file = open(path_to_save, "w+")
    information = {
        "publicKeyId": key_id,
        "privateKey": str(key_pair)
    }
    file.write(json.dumps(information))
    file.close()


def read_key_pair(path):
    file = open(path, "r+")
    data = json.load(file)
    file.close()
    return data


def _make_safe_for_urlsafebase64(client_secret):
    client_secret = client_secret.replace("=", "")
    client_secret = client_secret.replace("+", "-")
    client_secret = client_secret.replace("/", "_")
    return client_secret