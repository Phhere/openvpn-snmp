from setuptools import setup


setup(
    name="openvpn-snmp",
    version="0.1.0",
    description="let's shutdown this machine",
    author="Philipp Helo Rehs",
    author_email="philipp@rehs.me",
    url="https://github.com/Phhere/openvpn-snmp",
    license="MIT",
    packages=['openvpn-snmp'],
    scripts=['openvpn-agent.py'],
    zip_safe=False,
    install_requires=['netsnmpagent'],
    extras_require={
        'daemon mode': ['python-daemon'],
    }
)