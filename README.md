# Panic Button

The **Panic Button** is a windows application aiming to preserve cryptographic information used by ransomware operations.

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

TODO 

## Authors

* **Yiannis Koukouras**      - *Concept and design*
* **Panagiotis Papantoniou** - *Initial work*

See also the list of [contributors](https://github.com/twelvesec/panicbutton/contributors) who participated in this project.

## License

This project is licensed under the GPL v3 License - see the [LICENSE.txt](LICENSE.txt) file for details

## Acknowledgments

* Hat tip to anyone who's code was used
