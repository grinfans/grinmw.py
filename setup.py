import setuptools

setuptools.setup(
    name='grinmw',
    version='0.1.0',
    packages=['grinmw',],
    license='MIT',
    description = 'Python wrappers around the Grin wallet V3 and Grin node V2 APIs',
    long_description=open('README.md').read(),
    long_description_content_type="text/markdown",
    author = 'xiaojay, Blade M. Doyle, marekyggdrasil',
    author_email = 'xiaojay@gmail.com, bladedoyle@gmail.com, marek.yggdrasil@gmail.com',
    install_requires=['requests', 'eciespy', 'coincurve', 'Crypto'],
    url = 'https://github.com/grinfans/grinmw.py',
    download_url = 'https://github.com/grinfans/grinmw.py/archive/refs/tags/v0.1.0.tar.gz',
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 2",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    )
