package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"

	"aesgo/cipher"
	"crypto/aes"
)

var decryptFlag bool
var password string

func init() {
	flag.BoolVar(&decryptFlag, "decrypt", false, "set to decrypt source file(s) (defaults to false)")
	flag.StringVar(&password, "pwd", "", "the password for this encryption tool")
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "\tencrypt [flags] [source file] [destination file] # operation on a single file\n")
	fmt.Fprintf(os.Stderr, "\tencrypt [flags] [source directory] [destination directory] # operation on all files within a directory\n")
	fmt.Fprintf(os.Stderr, "Flags:\n")
	flag.PrintDefaults()
}

func main() {
	flag.Usage = usage
	flag.Parse()

	if flag.NArg() != 2 {
		// Expect two arguments, input and output destinations
		usage()
	} else {
		var inputfilename string
		var outputfilename string
		var args []string

		args = flag.Args()

		inputfilename = args[0]
		outputfilename = args[1]

		// TODO: handle directories and multiple files

		// Encrypt file
		processFile(inputfilename, outputfilename)
	}
}

func processFile(inputfilename string, outputfilename string) {

	// Set up input and output targets
	inputfile, err := os.Open(inputfilename)
	check(err)

	outputfile, err := os.Create(outputfilename)
	check(err)

	// Deferred call to clean up input and output targets
	defer func() {
		err := inputfile.Close()
		check(err)
	}()
	defer func() {
		err := outputfile.Close()
		check(err)
	}()

	// Buffered reader and writer
	fileReader := bufio.NewReader(inputfile)

	fileWriter := bufio.NewWriter(outputfile)

	// Handle initialisation vector processing
	var iv []byte

	if decryptFlag {
		// Read the IV from the file
		// The IV needs to be unique, but not secure. Therefore it's common to
		// include it at the beginning of the ciphertext
		ivBuffer := make([]byte, aes.BlockSize)
		chunk, err := fileReader.Read(ivBuffer)
		iv = ivBuffer[:chunk]
		check(err)

	} else {
		// Generate and write the IV to file
		iv = cipher.GenerateInitVec()
		_, err = fileWriter.Write(iv)
		check(err)
	}

	fmt.Printf("Initialisation vector: %s\n", iv)

	bufferSize := 1024
	buffer := make([]byte, bufferSize)
	for {
		// Read a chunk and fill the buffer
		// this is to make sure every read on encrypt and decrypt is the same length
		chunk, err := io.ReadFull(fileReader, buffer)
		if err != nil {
			if err == io.ErrUnexpectedEOF {
				// ignore, buffer was partially filled but that's ok, final read
			} else if err == io.EOF {
				// End of file
				break
			} else {
				panic(err)
			}
		} else if chunk == 0 {
			// No more data to read
			break
		}

		// Encrypt or decrypt chunk
		bytes, err := cipher.AesEncrypt(buffer[:chunk], decryptFlag, password, iv)

		check(err)

		// Write the chunk to the output file
		_, err = fileWriter.Write(bytes)
		check(err)
	}

	// Clean up
	defer func() {
		err := fileWriter.Flush()
		check(err)
	}()
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}
