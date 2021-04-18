import setuptools

setuptools.setup(
    name='grinpy',
    version='1.0.0',
    packages=['grinpy',],
    license='MIT',
    description = 'Python wrappers around the Grin wallet V3 and Grin node V2 APIs',
    long_description=open('README.md').read(),
    long_description_content_type="text/markdown",
    author = '',
    author_email = '',
    install_requires=['requests', 'eciespy', 'coincurve', 'Crypto'],
    url = 'https://github.com/grinfans/grinpy',
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 2",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    )
