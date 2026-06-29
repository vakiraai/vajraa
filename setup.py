# setup.py
from setuptools import setup, find_packages
from setuptools.dist import Distribution

class BinaryDistribution(Distribution):
    def has_ext_modules(foo):
        return True

setup(
    name="vajraa",
    version="0.1.0",
    description="Vajraa: Cross-platform AI model encryption, licensing, and memory protection framework.",
    author="Vajraa Team",
    packages=find_packages(where="python"),
    package_dir={"": "python"},
    distclass=BinaryDistribution,
    install_requires=[
        "numpy",
        "cryptography",
        "onnx",
        "onnxruntime",
        "torch",
    ],
    package_data={
        "vajraa": ["*.dll", "*.so", "*.dylib"],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
)
