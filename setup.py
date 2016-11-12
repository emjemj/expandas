from setuptools import setup

setup(name="expandas",
    version="0.1",
    description="A python lib for expanding your ASNs",
    url="https://github.com/emjemj/expandas",
    author="Eric Lindsjö",
    author_email="eric@emj.se",
    packages=["expandas"],
    install_requires=["requests"],
    scripts=["expandas-cli.py"]
)
