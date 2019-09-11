from setuptools import setup

setup(
    name='easy_gpg',
    version='0.0.1',
    description='Python service to GPG encrypt files',
    url='git@github.com:loyaltycorp/easy_gpg',
    author='Damian Sloane',
    author_email='damian.sloane@loyaltycorp.com.au',
    license='proprietary',
    packages=['easy_gpg'],
    zip_safe=False,
    install_requires=['paramiko', 'PGPy==0.5.2']
)
