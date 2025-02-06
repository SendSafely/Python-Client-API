from setuptools import setup

setup(
	name='sendsafely',
	version='1.0.8',
	packages=['sendsafely'],
	description='The SendSafely Client API allows programmatic access to SendSafely and provides a layer of abstraction from our REST API, which requires developers to perform several complex tasks in a correct manner.',
	long_description_content_type="text/markdown",
	author='SendSafely',
	author_email='support@sendsafely.com',
	url='https://github.com/SendSafely/Python-Client-API',
	install_requires=[
		'standard-imghdr',
		'requests',
		'PGPy'
	],
	python_requires='>=3',
	license='Apache License Version 2.0',
	classifiers=[
		'Development Status :: 5 - Production/Stable',
		'Intended Audience :: Developers',
		'Topic :: Software Development :: Libraries :: Application Frameworks',
		'Programming Language :: Python :: 3',
		'License :: OSI Approved :: Apache Software License'
	],
)
