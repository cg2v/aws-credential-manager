from setuptools import setup, find_packages

# Loads _version.py module without importing the whole package.
def get_version_and_cmdclass(pkg_path):
    import os
    from importlib.util import module_from_spec, spec_from_file_location
    spec = spec_from_file_location(
        'version', os.path.join(pkg_path, '_version.py'),
    )
    if spec is None:
        raise ValueError(f'No version file found in {pkg_path}')
    if spec.loader is None:
        raise ValueError(f'No loader found in {spec}')
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.__version__, module.get_cmdclass(pkg_path)


version, cmdclass = get_version_and_cmdclass('multicred')

setup(
    name='multicred',
    version=version,
    cmdclass=cmdclass,
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
            'multicred-manage = multicred.manager:main',
        ],
    },
)
