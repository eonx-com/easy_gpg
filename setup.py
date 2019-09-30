from setuptools import setup

setup(
    name='EasyGpg',
    version='0.0.1',
    description='Python service to GPG encrypt files',
    url='git@github.com:loyaltycorp/EasyGpg',
    author='Damian Sloane',
    author_email='damian.sloane@loyaltycorp.com.au',
    license='proprietary',
    packages=['EasyGpg'],
    zip_safe=False,
    install_requires=['paramiko', 'PGPy==0.5.2']
)
