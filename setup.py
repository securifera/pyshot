#!/usr/bin/env python


from setuptools import setup, find_packages


setup(name='pyshot',

      version='1.0',

      description='Website Screenshot Utility',

      author='Ryan Wincey (b0yd)',

      author_email='rwincey@securifera.com',

      url='https://www.securifera.com',

      packages=find_packages(),
      zip_safe=False,
      include_package_data=True,
      package_data={'': ['webscreenshot.js']},

     )
