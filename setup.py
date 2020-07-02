from setuptools import setup

setup(
    name="monet",
    version='0.0.2',
    py_modules=['monet'],
    install_requires=[
        'Click',
        'scapy-python3',
        'terminaltables',
        'requests',
        'colorclass'
    ],
    entry_points='''
        [console_scripts]
        monet=monet:network
    ''',
)
