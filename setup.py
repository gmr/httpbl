import setuptools

from httpbl import __version__

setuptools.setup(
  name='httpbl',
  version=__version__,
  description='Project Honeypot Http:BL API Client',
  classifiers=[
    'Development Status :: 5 - Production/Stable',
    'Intended Audience :: Developers',
    'License :: OSI Approved :: BSD License',
    'Programming Language :: Python :: 2',
    'Programming Language :: Python :: 2.7',
    'Programming Language :: Python :: 3',
    'Programming Language :: Python :: 3.4',
    'Programming Language :: Python :: 3.5',
    'Programming Language :: Python :: 3.6',
    'Programming Language :: Python :: Implementation :: CPython',
    'Programming Language :: Python :: Implementation :: PyPy',
    'Topic :: Database',
    'Topic :: Software Development :: Libraries'],
  keywords='honeypot',
  author='Gavin M. Roy',
  author_email='gavinmroy@gmail.com',
  long_description=open('README.rst').read(),
  url='https://github.com/gmr/httpbl',
  license='BSD',
  py_modules=['httpbl'],
  package_data={'': ['LICENSE', 'README.rst']},
  include_package_data=True,
  zip_safe=True)
