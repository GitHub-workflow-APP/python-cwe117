from setuptools import setup

with open('requirements.txt', 'r') as f:
    requirements_txt = [s.strip() for s in f.readlines()]

# with open('README.md', 'r') as f:
#     long_desc = f.read()

setup(
    name='cwe117_fix_with_anticrlf_module',
    version='1.20190520',
    description='Test CWE-117 fixes for AntiCRLF module',
    scripts=['cwe117_fix_with_anticrlf_module.py'],
    install_requires=requirements_txt,
    # long_description=long_desc,
    # long_description_content_type="text/markdown",
)
