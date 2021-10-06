# This is a client and server application for safe calculations

### To build and run these applications use following instructions.

---

**0. Install WSL and Linux distribution (optional)**

* Install [WSL](https://docs.microsoft.com/en-us/windows/wslinstall)
* Setup Linux distribution (tested on Ubuntu 20.04 LTS and Debian Bullseye)

---

**1. Update data base with packages and install them**

	sudo apt update
	sudo apt upgrade

---

**2. Install additional packages and libraries**

	sudo apt install libboost-all-dev	// install boost
	sudo apt install libssl-dev		    // install openssl
	sudo apt install cmake			    // install cmake
	sudo apt install build-essential	// install compiler
	sudo apt install git			    // install git (for Debian)

---

**3. Clone git repo**
    
   * git clone https://github.com/stokado/ClientServerSSL.git

---

**4. Change directory**

	* cd ClientServerSSL/

---

**5. Change branch**

	* git checkout linux

---

**6. Build project and compile code**

	* mkdir build/          // create directory for project
	* cmake -B build/       // CMake command to build project to build/ directory
	* cd build/             // enter directory with project
	* cmake --build .       // CMake command to run compilation with native compiler from current directory
	* cd ../install/bin     // enter directory with installed executables

---

**7. Run executables (I used Windows Terminal to run multiple executables)**

- Run server

        sudo ./server <adress> <port> <number_of_clients>
    
**./server takes 3 arguments:**

- `<adress>` - IP adress of server
- `<port>` - port that server will use to listen to new connections
- `<number_of_clients>` - maximum number of threads for server (maximum number of connections)
		
If there are no errors, then server is running and waiting for new connections.

 **_sudo_** is used to use ports < 1024. We use port 443 for HTTPS.
	
- Change terminal

- Run client

        ./client <adress> <port> <path_to_file>

    **./client takes 3 arguments:**
- `<host>` - IP adress of server
- `<port>` - port to connect to and send messages
- `<path_to_data>` - path to local storage with data to send (relative to executable)

---

## Example

- Run server

        sudo ./server 127.0.0.1 443 5

- Run client

        ./client 127.0.0.1 443 ../../data/test0.json

---

## Test files to send

In root directory with project there is a _**data**_ directory. Test files to send to server are stored in this drectory. One can use these files to run client.

        ./client 127.0.0.1 443 ../../data/test0.json
            > max {1, 2, 0} - answer 2, status 0 - ok

        ./client 127.0.0.1 443 ../../data/test1.json
            > test {1, 2, 0} - answer 0, status 2 - unknown command

        ./client 127.0.0.1 443 ../../data/test2.json
            > avg { } - answer 0, status 1 - no numbers provided

        ./client 127.0.0.1 443 ../../data/test3.json
            > avg {1, 2, 4, 5} - answer 3, status 0 - ok 

        ./client 127.0.0.1 443 ../../data/test4.json
            > median {4, 9} - answer 6.5 (even number of numbers), status 0 - ok 

        ./client 127.0.0.1 443 ../../data/test5.json
            > median {4, 9, 5} - ответ 5 (odd number of numbers), status 0 - ok 