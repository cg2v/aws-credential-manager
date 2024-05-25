from setuptools import setup, find_packages

setup(
    name='multicred',
    version='0.1',
    packages=find_packages(exclude=['test*']),
    install_requires=[
        'chardet',
        'sqlalchemy',
        'boto3',
    ],
    entry_points={
        'console_scripts': [
            'multicred-import = multicred.importer:main',
            'multicred-get = multicred.credhelper:main',
        ],
    },
)
