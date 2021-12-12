# Ett
Encrypted Tcp Tunnel  

This project provides a simple implementation of a TCP tunnel encrypted via GCM EAS.  
Ett presented as a single binary application that can run multiple input and output tunnel nodes in a single process.  

## Usage
### Runing
Ett accepts two optional command line parameters:  
 + conf - String parameter shows location of the config file. By default "~/.config/ett/ett.toml".
 + first - Indicates the need to stop the entire process if at least one node is stopped. By default false.

Example:  
```
$ ett --conf ./config.toml --first
```
### Config
Ett uses config files in toml format.  
Config file contains an array of "Tunnels" blocks.  
Each block must contain the this fields:  
+ Source - Address for listening to incoming connections. String with uri format like "tcp://127.0.0.1:9051".
+ Destination - Address to which incoming connections should be proxied. String with uri format like "tcp://127.0.0.1:9051".

The block may also contain optional parameters:  
+ Encrypt/Decrypt - 128 or 256 bit key for tunnel encryption. String in base64 format.
+ Seed - Seed for the PRNG algorithm whose output will be xor with the transmitted data. 64 bit int.
+ Buff - Buffer size. a 16-bit unsigned int. By default 1024.
Of the two parameters "Encrypt" and "Decrypt", only one should be specified.  

Example:  
```
[[ Tunnels ]]
    Source = "tcp://127.0.0.1:9051"
    Destination = "tcp://127.0.0.1:9052"
    Buff = 5120
    Encrypt = "MI/zwbvsFuuUfcLAZAJ9C4w+tAsfnYUwg3/xcZ0kgZI="

[[ Tunnels ]]
    Source = "tcp://127.0.0.1:9052"
    Destination = "tcp://127.0.0.1:9050"
    Buff = 5120
    Decrypt = "MI/zwbvsFuuUfcLAZAJ9C4w+tAsfnYUwg3/xcZ0kgZI="

[[ Tunnels ]]
    Source = "tcp://127.0.0.1:9051"
    Destination = "tcp://127.0.0.1:9050"
    Buff = 5120
```
A separate server will be launched for each block.  
## Usecases
Ett can be used in two modes.  
### Tunnel mode
This is the main mode.  
It involves running two nodes. The first node accepts the plain connection, encrypts it and passes it to the second node, which decrypts it and passes it to the addressee.  
In the config of the first node there should be parameter "Encrypt", in the config of the second node there should be parameter "Decrypt".  

![UML](https://i.imgur.com/MkpEt9v.png)  
Node A config:  
```
[[ Tunnels ]]
    Source = "tcp://127.0.0.1:7777"
    Destination = "tcp://192.168.8.1:8888"
    Encrypt = "MI/zwbvsFuuUfcLAZAJ9C4w+tAsfnYUwg3/xcZ0kgZI="
```
Node B config:  
```
[[ Tunnels ]]
    Source = "tcp://0.0.0.0:8888"
    Destination = "tcp://127.0.0.1:9999"
    Decrypt = "MI/zwbvsFuuUfcLAZAJ9C4w+tAsfnYUwg3/xcZ0kgZI="
```
### Proxy mode
In this mode, only one node is started that proxies plain tcp connections from the sender to the recipient without performing encryption.  

![UML](https://i.imgur.com/kiSrusY.png)  
Node config: 
```
[[ Tunnels ]]
    Source = "tcp://127.0.0.1:8888"
    Destination = "tcp://127.0.0.1:9999"
```
### Reasons for using PRNG XOR
There is unconfirmed information that the use of xor with prng bits to the transmitted data makes it possible to bypass some types of DPI filters with greater success.  
In any case, this is a very computationally cheap task.  
## Instalation
```
$ git clone https://github.com/DomesticMoth/ett.git
$ cd ett
$ go build -o ett *.go
```
