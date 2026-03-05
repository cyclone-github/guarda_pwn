package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/pbkdf2"
)

/*
Cyclone's Guarda Wallet Decryptor
POC tool to decrypt Guarda wallet backups

coded by cyclone in Go

GNU General Public License v2.0

version history
v0.1.0; 2026-02-16
	initial version
v0.2.0; 2026-03-05
	github release
*/

const (
	guardaSalt = "XB7sHH26Hn&FmPLxnjGccKTfPV(yk"
)

var postfixes = []string{
	"(tXntTbJFzh]4EuQVmjzM9GXHCth8)",
	"(tXntTbJFzh]4EuQVmjzM9GXHCth8",
}

// Guarda wallet backup
type GuardaHash struct {
	Raw       string // original base64 string
	Salt      []byte // 8-byte OpenSSL salt
	Encrypted []byte // ciphertext (after "Salted__" + salt)
	Decrypted bool
}

func versionFunc() {
	fmt.Fprintln(os.Stderr, "Cyclone's Guarda Wallet Decryptor v0.2.0; 2026-03-05\nhttps://github.com/cyclone-github/guarda_pwn\n")
}

func helpFunc() {
	versionFunc()
	str := `Guarda Wallet backup decryptor

The hash file should contain one base64-encoded Guarda wallet backup per line.
Guarda backups use CryptoJS AES encryption.

Example Usage:
./guarda_pwn.bin -h guarda-wallet.txt -w wordlist.txt
./guarda_pwn.bin -h guarda-wallet.txt -w wordlist.txt -t 16 -s 10`
	fmt.Fprintln(os.Stderr, str)
}

// normalize base64
func normB64(s string) string {
	s = strings.TrimSpace(s)
	// remove all whitespace
	s = strings.NewReplacer("\r", "", "\n", "", "\t", "", " ", "").Replace(s)
	// URL-safe to standard base64
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")
	// fix padding
	for len(s)%4 != 0 {
		s += "="
	}
	return s
}

// derive key and IV using OpenSSL's EVP_BytesToKey with MD5
func evpBytesToKey(passphrase, salt []byte, keyLen, ivLen int) ([]byte, []byte) {
	totalLen := keyLen + ivLen
	var derived []byte
	var lastBlock []byte

	for len(derived) < totalLen {
		h := md5.New()
		if lastBlock != nil {
			h.Write(lastBlock)
		}
		h.Write(passphrase)
		h.Write(salt)
		lastBlock = h.Sum(nil)
		derived = append(derived, lastBlock...)
	}

	return derived[:keyLen], derived[keyLen : keyLen+ivLen]
}

// removes PKCS7 padding
func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, fmt.Errorf("invalid data length")
	}

	padLen := int(data[len(data)-1])
	if padLen == 0 || padLen > blockSize || padLen > len(data) {
		return nil, fmt.Errorf("invalid padding byte")
	}

	for i := len(data) - padLen; i < len(data); i++ {
		if data[i] != byte(padLen) {
			return nil, fmt.Errorf("invalid padding")
		}
	}

	return data[:len(data)-padLen], nil
}

// PBKDF2(password, guardaSalt, iterations=1, keyLen=16, SHA1) hex + postfix
func patchPassphrase(password string, postfix string) string {
	key := pbkdf2.Key([]byte(password), []byte(guardaSalt), 1, 16, sha1.New)
	return hex.EncodeToString(key) + postfix
}

// OpenSSL-compatible AES-256-CBC decryption (EVP_BytesToKey with MD5)
func tryDecrypt(hash *GuardaHash, passphrase string) (string, bool) {
	// derive AES-256 key (32 bytes) and IV (16 bytes) from passphrase + salt
	key, iv := evpBytesToKey([]byte(passphrase), hash.Salt, 32, aes.BlockSize)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", false
	}

	if len(hash.Encrypted)%aes.BlockSize != 0 || len(hash.Encrypted) == 0 {
		return "", false
	}

	decrypted := make([]byte, len(hash.Encrypted))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(decrypted, hash.Encrypted)

	// PKCS7 unpad
	decrypted, err = pkcs7Unpad(decrypted, aes.BlockSize)
	if err != nil {
		return "", false
	}

	if len(decrypted) == 0 {
		return "", false
	}

	// validate as UTF-8
	if !utf8.Valid(decrypted) {
		return "", false
	}

	return string(decrypted), true
}

// decrypt GuardaHash with password candidate
func decryptGuarda(password string, hash *GuardaHash) bool {
	for _, postfix := range postfixes {
		passphrase := patchPassphrase(password, postfix)
		text, ok := tryDecrypt(hash, passphrase)
		if ok && len(text) > 0 {
			fmt.Printf("\nPassword:\t'%s'\nDecrypted:\t'%s'\n", password, text)
			return true
		}
	}
	return false
}

// read and parse Guarda wallet backup hashes from file
func readGuardaHashes(filePath string) ([]GuardaHash, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var hashes []GuardaHash
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(file)

	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 10*1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		b64 := normB64(line)

		// deduplicate
		if seen[b64] {
			continue
		}
		seen[b64] = true

		// decode base64
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: skipping invalid base64 line: %v\n", err)
			continue
		}

		// verify OpenSSL "Salted__" header (8 bytes) + 8-byte salt + at least 16 bytes ciphertext
		if len(raw) < 32 {
			fmt.Fprintf(os.Stderr, "Warning: skipping line, decoded data too short (%d bytes)\n", len(raw))
			continue
		}

		if string(raw[:8]) != "Salted__" {
			fmt.Fprintf(os.Stderr, "Warning: skipping line, missing 'Salted__' header\n")
			continue
		}

		hashes = append(hashes, GuardaHash{
			Raw:       b64,
			Salt:      raw[8:16],
			Encrypted: raw[16:],
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return hashes, nil
}

// display startup info
func printWelcomeScreen(hashFileFlag, wordlistFileFlag *string, validHashCount, numThreads int) {
	fmt.Fprintln(os.Stderr, " ------------------------------------ ")
	fmt.Fprintln(os.Stderr, "| Cyclone's Guarda Wallet Decryptor  |")
	fmt.Fprintln(os.Stderr, " ------------------------------------ ")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "Hash file:\t%s\n", *hashFileFlag)
	fmt.Fprintf(os.Stderr, "Valid Hashes:\t%d\n", validHashCount)
	fmt.Fprintf(os.Stderr, "CPU Threads:\t%d\n", numThreads)
	fmt.Fprintf(os.Stderr, "Wordlist:\t%s\n", *wordlistFileFlag)
	fmt.Fprintln(os.Stderr, "Working...")
}

// processe password candidates from channel
func startWorker(ch <-chan string, stopChan chan struct{}, hashes []GuardaHash, crackedCountCh chan int, linesProcessedCh chan int) {
	for {
		select {
		case <-stopChan:
			return
		case password, ok := <-ch:
			if !ok {
				time.Sleep(100 * time.Millisecond)
				close(stopChan)
				return
			}
			allDecrypted := true
			for i, hash := range hashes {
				if !hash.Decrypted {
					if decryptGuarda(password, &hashes[i]) {
						crackedCountCh <- 1
						hashes[i].Decrypted = true
					} else {
						allDecrypted = false
					}
				}
			}
			linesProcessedCh <- 1

			if allDecrypted {
				select {
				case <-stopChan:
				default:
					close(stopChan)
				}
				return
			}
		}
	}
}

// CPU thread count
func setNumThreads(userThreads int) int {
	if userThreads <= 0 || userThreads > runtime.NumCPU() {
		return runtime.NumCPU()
	}
	return userThreads
}

// watch for Ctrl+C
func handleGracefulShutdown(stopChan chan struct{}) {
	interruptChan := make(chan os.Signal, 1)
	signal.Notify(interruptChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-interruptChan
		fmt.Fprintln(os.Stderr, "\nCtrl+C pressed. Shutting down...")
		close(stopChan)
	}()
}

// periodically print cracking stats
func monitorPrintStats(crackedCountCh, linesProcessedCh <-chan int, stopChan <-chan struct{}, startTime time.Time, validHashCount int, wg *sync.WaitGroup, interval int) {
	crackedCount := 0
	linesProcessed := 0
	var ticker *time.Ticker
	if interval > 0 {
		ticker = time.NewTicker(time.Duration(interval) * time.Second)
		defer ticker.Stop()
	}

	for {
		select {
		case <-crackedCountCh:
			crackedCount++
		case <-linesProcessedCh:
			linesProcessed++
		case <-stopChan:
			printStats(time.Since(startTime), crackedCount, validHashCount, linesProcessed, true)
			wg.Done()
			return
		case <-func() <-chan time.Time {
			if ticker != nil {
				return ticker.C
			}
			return nil
		}():
			if interval > 0 {
				printStats(time.Since(startTime), crackedCount, validHashCount, linesProcessed, false)
			}
		}
	}
}

// display current cracking statistics
func printStats(elapsedTime time.Duration, crackedCount, validHashCount, linesProcessed int, exitProgram bool) {
	hours := int(elapsedTime.Hours())
	minutes := int(elapsedTime.Minutes()) % 60
	seconds := int(elapsedTime.Seconds()) % 60
	linesPerSecond := float64(linesProcessed) / elapsedTime.Seconds()
	fmt.Fprintf(os.Stderr, "\nDecrypted: %d/%d", crackedCount, validHashCount)
	fmt.Fprintf(os.Stderr, "\t%.2f p/s", linesPerSecond)
	fmt.Fprintf(os.Stderr, "\t%02dh:%02dm:%02ds", hours, minutes, seconds)
	if exitProgram {
		fmt.Println("")
		os.Exit(0)
	}
}

func main() {
	wordlistFileFlag := flag.String("w", "", "Wordlist file")
	hashFileFlag := flag.String("h", "", "Guarda wallet backup file (base64, one per line)")
	cycloneFlag := flag.Bool("cyclone", false, "")
	versionFlag := flag.Bool("version", false, "Program version")
	helpFlag := flag.Bool("help", false, "Program usage instructions")
	threadFlag := flag.Int("t", runtime.NumCPU(), "CPU threads to use (optional)")
	statsIntervalFlag := flag.Int("s", 60, "Interval in seconds for printing stats (default: 60)")
	flag.Parse()

	if *versionFlag {
		versionFunc()
		os.Exit(0)
	}
	if *cycloneFlag {
		line := "Q29kZWQgYnkgY3ljbG9uZSA7KQo="
		str, _ := base64.StdEncoding.DecodeString(line)
		fmt.Println(string(str))
		os.Exit(0)
	}
	if *helpFlag {
		helpFunc()
		os.Exit(0)
	}

	if *wordlistFileFlag == "" || *hashFileFlag == "" {
		fmt.Fprintln(os.Stderr, "Both -w (wordlist file) and -h (hash file) flags are required")
		fmt.Fprintln(os.Stderr, "Try running with -help for usage instructions")
		os.Exit(1)
	}

	startTime := time.Now()

	numThreads := setNumThreads(*threadFlag)

	crackedCountCh := make(chan int)
	linesProcessedCh := make(chan int)
	stopChan := make(chan struct{})
	var wg sync.WaitGroup

	handleGracefulShutdown(stopChan)

	hashes, err := readGuardaHashes(*hashFileFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error reading hash file:", err)
		os.Exit(1)
	}
	validHashCount := len(hashes)

	if validHashCount == 0 {
		fmt.Fprintln(os.Stderr, "No valid hashes found in hash file")
		os.Exit(1)
	}

	printWelcomeScreen(hashFileFlag, wordlistFileFlag, validHashCount, numThreads)

	workerChannels := make([]chan string, numThreads)
	for i := range workerChannels {
		workerChannels[i] = make(chan string, 1000)
	}

	for _, ch := range workerChannels {
		wg.Add(1)
		go func(ch <-chan string) {
			defer wg.Done()
			startWorker(ch, stopChan, hashes, crackedCountCh, linesProcessedCh)
		}(ch)
	}

	// reader goroutine
	wg.Add(1)
	go func() {
		defer func() {
			for _, ch := range workerChannels {
				close(ch)
				return
			}
		}()
		defer wg.Done()

		wordlistFile, err := os.Open(*wordlistFileFlag)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error opening wordlist file:", err)
			return
		}
		defer wordlistFile.Close()

		scanner := bufio.NewScanner(wordlistFile)
		workerIndex := 0
		for scanner.Scan() {
			word := strings.TrimRight(scanner.Text(), "\n")
			workerChannels[workerIndex] <- word
			workerIndex = (workerIndex + 1) % len(workerChannels)
		}
	}()

	// monitor stats
	wg.Add(1)
	go monitorPrintStats(crackedCountCh, linesProcessedCh, stopChan, startTime, validHashCount, &wg, *statsIntervalFlag)

	wg.Wait()
}
