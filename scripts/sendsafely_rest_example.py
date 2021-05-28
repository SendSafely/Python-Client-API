from sendsafely import SendSafely, Package, utilities

# Edit these variables
api_key = ""
api_secret = ""
base_url = "https://companyabc.sendsafely.com"


def rest_get_example_user_information(sendsafely):
    get_endpoint = "/user/"
    response = utilities.get_request(sendsafely, get_endpoint)
    print(response)


def rest_post_example_update_package_life(sendsafely):
    package = Package(sendsafely)
    post_endpoint = "/package/" + package.package_id
    body = {"life": 10}
    response = utilities.post_request(sendsafely, post_endpoint, body)
    print(response)


def rest_delete_example_delete_package(sendsafely):
    package = Package(sendsafely)
    delete_endpoint = "/package/" + package.package_id
    response = utilities.delete_request(sendsafely, delete_endpoint)
    print(response)


def rest_put_example_add_recipients(sendsafely):
    package = Package(sendsafely)
    put_endpoint = "/package/" + package.package_id + "/recipients/"
    response = utilities.put_request(sendsafely, put_endpoint,
                                     {'emails': ['user@foobar.com', 'user2@foobar.com']})
    print(response)


def rest_patch_example_update_file(sendsafely):
    # Edit
    package_id = 'packageId of Dropzone package'
    file_id = 'fileId of Dropzone package'
    body = {'fileName': 'new file name'}

    patch_endpoint = "/package/" + package_id + "/file/" + file_id
    response = utilities.patch_request(sendsafely, patch_endpoint, body)
    print(response)


def main():
    sendsafely = SendSafely(base_url, api_key, api_secret)
    print("GET: User Information")
    rest_get_example_user_information(sendsafely)
    print("POST: Update Package Life")
    rest_post_example_update_package_life(sendsafely)
    print("PUT: Add Recipients")
    rest_put_example_add_recipients(sendsafely)
    print("DELETE: Delete Package")
    rest_delete_example_delete_package(sendsafely)
    # print("PATCH: Update Dropzone File")
    # rest_patch_example_update_file(sendsafely)


if __name__ == '__main__':
    main()
