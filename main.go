/*
    This file is part of Ett.

    Ett is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Ett is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Ett.  If not, see <https://www.gnu.org/licenses/>.
*/
package main

import (
	"io"
	"net"
	"flag"
	"net/url"
	"math/rand"
	"encoding/binary"
	"encoding/base64"
	"github.com/BurntSushi/toml"
	log "github.com/sirupsen/logrus"
)

// Represet uri like "tcp://127.0.0.0:8888"
type Addr struct {
	network string
	addr string
}

// Convert string to Addr: "tcp://127.0.0.0:8888" -> {"tcp", "127.0.0.1:8888"}
func AddrFromString(s string) Addr {
	u, err := url.Parse(s)
	if err != nil {
		log.Fatal(err)
	}
	return Addr{u.Scheme, u.Host}
}

// Move data from inp to out without any changes or with PRNG XOR
func shift(input io.ReadCloser, output io.WriteCloser, bufSize uint16, seed *int64){
	// Buffer to reading
	buf := make([]byte, bufSize)
	// Close streams on exit
	defer input.Close()
	defer output.Close()
	// If seed passed wrap output stream in XorWriter
	var out io.Writer
	if seed == nil {
		out = output
	}else{
		out = NewXorWriter(output, rand.New(rand.NewSource(*seed)))
	}
	// Working loop
	for {
		// Read data drom input stream
		size, err := input.Read(buf)
		if err != nil {
			return
		}
		data := buf[:size]
		// Write data to out stream
		_, err = out.Write(data)
		if err != nil {
			return
		}
	}
}

// Move data from input to output with encryption it by encryptor
func encr(input io.ReadCloser, output io.WriteCloser, bufSize, minimal_chunk uint16, encryptor Encryptor, seed *int64) {
	// Buffer to reading
	buf := make([]byte, bufSize)
	// Close streams on exit
	defer input.Close()
	defer output.Close()
	// If seed passed wrap output stream in XorWriter
	var out io.Writer
	if seed == nil {
		out = output
	}else{
		out = NewXorWriter(output, rand.New(rand.NewSource(*seed)))
	}
	// Working loop
	for {
		// Read data drom input stream
		size, err := input.Read(buf)
		if err != nil {
			return
		}
		plainData := buf[:size]
		// Encrypt data
		cryptedData, err := encryptor.Encrypt(plainData)
		if err != nil {
			log.Error(err)
			return
		}
		// Add length header
		ln := uint32(len(cryptedData))
		lnb := make([]byte, 4)
		binary.BigEndian.PutUint32(lnb, ln)
		toWrite := append(lnb, cryptedData ...)
		// Write data to out stream
		_, err = out.Write(toWrite)
		if err != nil {
			return
		}
	}
}

// Move data from input to output with decryption it by decryptor
func decr(input io.ReadCloser, output io.WriteCloser, bufSize uint16, decryptor Decryptor, seed *int64) {
	// Buffer to reading
	buf := make([]byte, bufSize*2)
	// Close streams on exit
	var lnb [4]byte
	defer input.Close()
	defer output.Close()
	// If seed passed wrap input stream in XorReader
	var inp io.Reader
	if seed == nil {
		inp = input
	}else{
		inp = NewXorReader(input, rand.New(rand.NewSource(*seed)))
	}
	// Working loop
	for {
		// Read length header from input stream
		_, err := io.ReadFull(inp, lnb[:])
		if err != nil {
			return
		}
		// Decode length header
		ln := binary.BigEndian.Uint32(lnb[:])
		// Read encrypted data drom input stream
		_, err = io.ReadFull(inp, buf[:ln])
		if err != nil {
			return
		}
		cryptedData := buf[:ln]
		// Decrypt data
		plainData, err := decryptor.Decrypt(cryptedData)
		if err != nil {
			log.Error(err)
			return
		}
		// Write data to out stream
		_, err = output.Write(plainData)
		if err != nil {
			return
		}
	}
}

// Accept handler for connections with encryption
func acceptEncrypted(inp net.Conn, destination Addr, bufSize, minimal_chunk uint16, encrypt, decrypt []byte, seed *int64) {
	// Close incoming connection on exit
	defer inp.Close()
	// Open outgoing connection
	out, err := net.Dial(destination.network, destination.addr)
	if err != nil {
		log.Error(err)
		return
	}
	// Close outgoing connection on exit
	defer out.Close()
	// Write log message on exit
	defer log.Debug("Connection closed")
	// If "Encrypt" config param passed
	if len(encrypt) > 0 {
		// Create cryptor object
		cr, err := newAESCrypt(encrypt)
		if err != nil {
			log.Error(err)
			return
		}
		// Run outgoing stream handler in new coroutine
		go decr(out, inp, bufSize, cr, seed)
		// Run incoming stream handler
		encr(inp, out, bufSize, minimal_chunk, cr, seed)
	// If "Decrypt" config param passed
	}else{
		// Create cryptor object
		cr, err := newAESCrypt(decrypt)
		if err != nil {
			log.Error(err)
			return
		}
		// Run incoming stream handler in new coroutine
		go decr(inp, out, bufSize, cr, seed)
		// Run outgoing stream handler
		encr(out, inp, bufSize, minimal_chunk, cr, seed)
	}
}

// Accept handler for connections with no encryption
func acceptNonEncrypted(inp net.Conn, destination Addr, buf_size uint16, seed *int64) {
	// Close incoming connection on exit
	defer inp.Close()
	// Open outgoing connection
	out, err := net.Dial(destination.network, destination.addr)
	if err != nil {
		log.Error(err)
		return
	}
	// Close outgoing connection on exit
	defer out.Close()
	// Write log message on exit
	defer log.Debug("Connection closed")
	// Run outgoing stream handler in new coroutine
	go shift(out, inp, buf_size, seed)
	// Run incoming stream handler
	shift(inp, out, buf_size, seed)
}

// Send stop signall to main thread
func stop(stCh chan int) {
	stCh <- 0
}

// Crypted connections handler
func listenEncrypted(source, destination Addr, buf_size, minimal_chunk uint16, encrypt, decrypt []byte, seed *int64, stCh chan int) {
	// Send stop signall to main thread on exit
	defer stop(stCh)
	// Listen on passed address
	socket, err := net.Listen(source.network, source.addr)
	if err != nil {
		log.Error(err)
		return
	}
	// Close socket on exit
	defer socket.Close()
	// Write log message
	log.Info("Listening at "+source.network+"://"+source.addr)
	// Accept loop
	for {
		// Accept new connection
		conn, err := socket.Accept()
		if err != nil {
			log.Error(err)
			return
		}
		// Write log message
		log.Debug("New connection to "+source.network+"://"+source.addr)
		// Send connection to accept handler
		go acceptEncrypted(conn, destination, buf_size, minimal_chunk, encrypt, decrypt, seed)
	}
}

// Connections handler
func listenNonEncrypted(source, destination Addr, buf_size uint16, seed *int64, stCh chan int) {
	// Send stop signall to main thread on exit
	defer stop(stCh)
	// Listen on passed address
	socket, err := net.Listen(source.network, source.addr)
	if err != nil {
		log.Error(err)
		return
	}
	// Close socket on exit
	defer socket.Close()
	// Write log message
	log.Debug("Listening at "+source.network+"://"+source.addr)
	for {
		// Accept new connection
		conn, err := socket.Accept()
		if err != nil {
			log.Error(err)
			return
		}
		// Write log message
		log.Info("New connection to "+source.network+"://"+source.addr)
		// Send connection to accept handler
		go acceptNonEncrypted(conn, destination, buf_size, seed)
	}
}


// Config element struct
type tunnel struct {
	Source string
	source Addr
	Destination string
	destination Addr
	Encrypt *string
	encrypt []byte
	Decrypt *string
	decrypt []byte
	Seed *int64
	Buff uint16
}

// Config struct
type Config struct {
	Tunnels []tunnel
}

func main() {
	// Read args
	filename := flag.String("conf", "~/.config/ett/ett.toml", "Path to config file")
	exitOnFirst := flag.Bool("first", false, "Stop the whole process if at least one server stops")
	flag.Parse()
	// Read config
	var conf Config
	_, err := toml.DecodeFile(*filename, &conf)
	if err != nil {
		log.Fatal(err)
	}
	// Postprocess config
	for i, tun := range conf.Tunnels {
		// Default buff
		if tun.Buff == 0 {
			tun.Buff = 1024
		}
		// Parse "Source" and "Destination" params 
		tun.source = AddrFromString(tun.Source)
		tun.destination = AddrFromString(tun.Destination)
		// If "Encrypt" param passed parse it
		if tun.Encrypt != nil {
			key, err := base64.StdEncoding.DecodeString(*tun.Encrypt)
			if err != nil {
				log.Fatal(err)
			}
			tun.encrypt = key
		}
		// If "Decrypt" param passed parse it
		if tun.Decrypt != nil {
			key, err := base64.StdEncoding.DecodeString(*tun.Decrypt)
			if err != nil {
				log.Fatal(err)
			}
			tun.decrypt = key
		}
		conf.Tunnels[i] = tun
	}
	// Create stop chain
	stCh := make(chan int)
	// Run handlers for all tunnels passed in config
	for _, tun := range conf.Tunnels {
		// Tunnel with encryption
		if tun.Encrypt != nil || tun.Decrypt != nil {
			go listenEncrypted(
				tun.source,
				tun.destination,
				tun.Buff,
				tun.Buff,
				tun.encrypt,
				tun.decrypt,
				tun.Seed,
				stCh,
			)
		// Tunnel without encryption
		}else{
			go listenNonEncrypted(
				tun.source,
				tun.destination,
				tun.Buff,
				tun.Seed,
				stCh,
			)
		}
	}
	// Waiting for other threads to stop
	for _, _ = range conf.Tunnels {
		<- stCh
		if *exitOnFirst{ break }
	}
}
