from setuptools import setup, find_packages

setup(
    name='angr_ebpf',
    version='0.1',
    description='eBPF backend for angr (Heimdall artifact)',
    packages=find_packages(),
    install_requires=[
        'angr',
        'cle',
        'archinfo',
        'pyvex',
    ],
)
