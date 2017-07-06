# Panic Button

The **Panic Button** is a windows application aiming to preserve cryptographic information used by ransomware operations. If you suspect a ransomware is running on your pc, then hit the **Panic Button**! Panic Button will dump all of your memory (and potentially the encryption keys of the ransomware) to a file and hibernate your system. Then you should call the IT guys :)

We recommend installing this program and executing a dry run, before you are affected... :|

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. See deployment for notes on how to deploy the project on a live system.

### Prerequisites

To setup the development environment for the project you will need the following:
 * mingw 
 * cmake

### Installing

Clone the repository

```commandline
git clone https://www.github.com/twelvesec/panicbutton.git
```

Cd in to the cloned directory

```commandline
cd panicbutton
```

Create the build directory

```commandline
mkdir build
```

Cd in the build directory

```commandline
cd build
```

Crate project configuration

```commandline
cmake ..
```

Build project

```commandline
make
```

## Deployment

TODO

## Built With

* [Winpmem](https://github.com/google/rekall/tree/master/tools/windows/winpmem) - Memory dumping functionality

## Contributing

TODO

## Versioning

### Semantic Versioning 2.0.0

Given a version number MAJOR.MINOR.PATCH, increment the:

* MAJOR version when you make incompatible API changes
* MINOR version when you add functionality in a backwards-compatible manner
* PATCH version when you make backwards-compatible bug fixes.

Additional labels for pre-release and build metadata are available as extensions to the MAJOR.MINOR.PATCH format. 

## Authors

* **Yiannis Koukouras**      - *Concept and design*
* **Panagiotis Papantoniou** - *Initial work*

See also the list of [contributors](https://github.com/twelvesec/panicbutton/contributors) who participated in this project.

## License

This project is licensed under the GPL v3 License - see the [LICENSE.txt](LICENSE.txt) file for details

## Acknowledgments

* Hat tip to anyone who's code was used
