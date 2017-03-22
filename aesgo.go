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

	// open input file
	inputfile, err := os.Open(inputfilename)
	check(err)

	// deferred call to close the input file and check for errors
	defer func() {
		err := inputfile.Close()
		check(err)
	}()

	// create a buffered file reader
	fileReader := bufio.NewReader(inputfile)

	// open output file
	outputfile, err := os.Create(outputfilename)
	check(err)

	// deferred call to close the output file and check for errors
	defer func() {
		err := outputfile.Close()
		check(err)
	}()

	// create a file writer
	fileWriter := bufio.NewWriter(outputfile)

	// Handle initialisation vector processing
	var iv []byte
	if decryptFlag {
		// Read the IV from the file
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
		// read a chunk
		chunk, err := fileReader.Read(buffer)
		if err != nil {
			if err == io.EOF {
				// End of file
				break
			}
			panic(err)
		} else if chunk == 0 {
			// No more data to read
			break
		}

		// encrypt or decrypt chunk
		bytes, err := cipher.AesEncrypt(buffer[:chunk], decryptFlag, password, iv)

		check(err)

		// write the chunk to the output file
		_, err = fileWriter.Write(bytes)
		check(err)
	}

	// clean up
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
