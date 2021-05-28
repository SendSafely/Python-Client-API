from distutils.core import setup

setup(
	name='SendSafely-Python-API',
	version='1.0.0',
	packages=['sendsafely'],
	description='The SendSafely Client API allows programmatic access to SendSafely and provides a layer of abstraction from our REST API, which requires developers to perform several complex tasks in a correct manner.',
	long_description='file: README.md',
	author='SendSafely',
	author_email='support@sendsafely.com',
	url='https://developer.sendsafely.com/',
	install_requires=[
		'requests',
		'PGPy'
	],
	python_requires='>=3',
	classifiers=[
		'Development Status :: 5 - Production/Stable',
		'Intended Audience :: Developers',
		'Topic :: Software Development :: Build Tools',
		'Programming Language :: Python :: 3'
	],
)
