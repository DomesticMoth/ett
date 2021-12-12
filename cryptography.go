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
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"errors"
)

type Encryptor interface{
	Encrypt(plain []byte) ([]byte, error)
}

type Decryptor interface{
	Decrypt(crypted []byte) ([]byte, error)
}

type AESCrypt struct {
	gcm cipher.AEAD
}

func newAESCrypt(key []byte) (*AESCrypt, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ret := new(AESCrypt)
	ret = &AESCrypt{gcm}
	return ret, nil
}

func (c *AESCrypt) Encrypt(plain []byte) ([]byte, error){
	nonce := make([]byte, c.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return []byte{}, err
	}
	crypted := c.gcm.Seal(nonce, nonce, plain, nil)
	return crypted, nil
}

func (c *AESCrypt) Decrypt(crypted []byte) ([]byte, error){
	nonceSize := c.gcm.NonceSize()
	if len(crypted) < nonceSize {
		return []byte{}, errors.New("Too short crypted text")
	}
	nonce, crypted := crypted[:nonceSize], crypted[nonceSize:]
	return c.gcm.Open(nil, nonce, crypted, nil)
}

// Writer wrapper that does xor with prng bits
type XorWriter struct {
	entopy io.Reader
	out io.Writer
	buf []byte
}

func NewXorWriter(out io.Writer, entopy io.Reader) XorWriter {
	return XorWriter{
		entopy,
		out,
		make([]byte, 512),
	}
}

func (w XorWriter) Write(p []byte) (n int, err error) {
	if len(w.buf) < len(p){
		w.buf=  make([]byte, len(p))
	}
	io.ReadFull(w.entopy, w.buf[:len(p)])
	for i := range p {
		p[i] = p[i] ^ w.buf[i]
	}
	return w.out.Write(p)
}

// Reader wrapper that does xor with prng bits
type XorReader struct {
	entopy io.Reader
	inp io.Reader
	buf_inp []byte
	buf_en []byte
}

func NewXorReader(inp io.Reader, entopy io.Reader) XorReader {
	return XorReader{
		entopy,
		inp,
		make([]byte, 2048),
		make([]byte, 2048),
	}
}

func (r XorReader) Read(p []byte) (n int, err error) {
	if len(r.buf_inp) < len(p) {
		r.buf_inp =  make([]byte, len(p))
		r.buf_en =  make([]byte, len(p))
	}
	size, err := r.inp.Read(r.buf_inp[:len(p)])
	if err != nil {
		return 0, err
	}
	io.ReadFull(r.entopy, r.buf_en[:size])
	for i := range r.buf_inp[:size] {
		p[i] = r.buf_inp[i] ^ r.buf_en[i]
	}
	return size, nil
}
