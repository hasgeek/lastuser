import os
from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))
README = open(os.path.join(here, 'README.rst')).read()
CHANGES = open(os.path.join(here, 'CHANGES.rst')).read()

requires = [
    'Flask',
    'Flask-SQLAlchemy',
    'SQLAlchemy>=0.6',
    'Flask-WTF',
    'Flask-OpenID',
    'Flask-OAuth',
    'Markdown',
    'ordereddict'
    ]

setup(name='lastuser',
      version='0.1',
      description='User management app',
      long_description=README + '\n\n' + CHANGES,
      license='BSD',
      classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Environment :: Web Environment",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
        "Programming Language :: JavaScript",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2.6",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: JavaScript",
        "Topic :: Internet",
        "Topic :: Internet :: WWW/HTTP :: Site Management",
        ],
      author='HasGeek',
      url='https://github.com/hasgeek/lastuser',
      keywords='',
      packages=find_packages(),
      include_package_data=True,
      zip_safe=False,
      test_suite='lastuserapp',
      install_requires=requires,
      )
