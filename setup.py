from setuptools import setup

setup(
    name='EasyGpg',
    version='2.0.0',
    description='Python service to GPG encrypt files',
    url='git@github.com:loyaltycorp/EasyGpg',
    author='Damian Sloane',
    author_email='damian.sloane@eonx.com',
    license='proprietary',
    packages=['EasyGpg'],
    zip_safe=False,
    install_requires=['paramiko', 'PGPy==0.5.2']
)
