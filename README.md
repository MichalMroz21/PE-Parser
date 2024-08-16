# PE-Parser
C++ Library for Parsing Windows Portable Executables

## Technologies
<img src="https://github.com/MichalMroz21/Redundant-Coding-Visualization/assets/125133223/f782c426-6b9d-4d09-8623-c731b5bd1829" alt="drawing" width="75"/>
<img src="https://github.com/MichalMroz21/Redundant-Coding-Visualization/assets/125133223/64806fd9-9e9b-40fa-b43c-080922bb2279" alt="drawing" width="75"/>
<img src="https://github.com/MichalMroz21/Redundant-Coding-Visualization/assets/125133223/fc76fa58-56e3-48e7-8242-e3a295b127f7" alt="drawing" width="75"/>
<img src="https://github.com/MichalMroz21/Redundant-Coding-Visualization/assets/125133223/87cb231e-0d10-4dd5-8dd1-3b06cb9c896c" alt="drawing" width="75"/>

## Dependencies

### CMake
* Download the installer from the [CMake page](https://cmake.org/download/)

### Boost
* Install Boost Libraries from the [Boost page](https://www.boost.org/)

### GoogleTest
* Downloaded automatically if You decide to run tests
* Not needed to just use the library

## Building & Installation
```
git clone https://github.com/MichalMroz21/PE-Parser
cd PE-Parser
cmake -B build -S . -G "MinGW Makefiles" && cd build && make && cd ..
cmake --install build
```
After that add the ../PE-Parser/bin/ directory in PATH Environment Variables.<br> 
The exact path should be printed out by ```cmake --install```<br><br>
Using the library after installation is simple:
```
cmake_minimum_required(VERSION 3.24)
project(TestProject VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find the PE-Parser package
find_package(PE-Parser REQUIRED)

# Add the executable
add_executable(TestProject main.cpp)

# Link against PE-Parser
target_link_libraries(TestProject PRIVATE PE-Parser::PE-Parser)
```

## Running Tests
To run Google Tests, turn on "MAKE_TEST_EXE" option in root CMakeLists.txt.<br>
Then run:
```
cmake -B build -S . -G "MinGW Makefiles" && cd build && make && cd tests && export GTEST_COLOR=1 && ./Tester.exe
```
