# SendSafely Python API
The SendSafely Python API lets you integrate SendSafely secure data transfer capabilities directly into your Python application. 

## Quickstart
The example below shows you how to install the `sendsafely` package, import it as a module, and use it to create a package. Make sure that you have [Python 3 or higher installed, as well as pip and Setuptools](https://packaging.python.org/tutorials/installing-packages/). 

To install the SendSafely Python API, simply run
```buildoutcfg
pip install sendsafely
```

Import the SendSafely modules to start making your API calls

```python
from sendsafely import SendSafely, Package
```
Create a Sendsafely instance object
```python
sendsafely = SendSafely("https://your-company.sendsafely.com", "API_KEY", "API_SECRET")
```
Create a new package
```python
package = Package(sendsafely)
```
Add a secure message to the package
```python
package.encrypt_and_upload_message("hello this is a message")
```
Add a recipient to the package
```python
package.add_recipient("user@foobar.com")
```
Finalize the package so it can be delivered to the recipients. The returned response contains the Secure Link needed for recipients to access the package. 
```python
response = package.finalize()
```
*You will need to generate your own API_KEY and API_SECRET from the API Keys section of your Profile page when logged into your SendSafely portal.*

## Examples
**sendsafely_python_example.py** - demonstrates how the SendSafely Python API can be used to create packages and handle encrypt/upload and download/decrypt operations without the API developer having to implement these complex operations.
```
python3 sendsafely_python_example.py
```

**sendsafely_rest_example.py** - demonstrates how the SendSafely Python API can be used to call SendSafely REST API endpoints directly. This is useful for cases where the SendSafely Python API does not currently implement a function for calling the endpoint. 
```
python3 sendsafely_rest_example.py
```

*Before running the example scripts, you will need to update the `api_key`, `api_secret`, and `base_url` variables in the script before running it.*

For more information, please refer to our [Developer Website](https://sendsafely.github.io) to familiarize yourself with the core SendSafely API and common operations. You can find our documented REST API endpoints [here](https://bump.sh/doc/sendsafely-rest-api). 

## Support
For support, please contact support@sendsafely.com. 