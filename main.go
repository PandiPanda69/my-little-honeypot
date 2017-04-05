package main

/****************************************************
 *				my-little-honeypot                  *
 *           Educational purposes only              *
 *                                                  *
 * This code aims to show how easy it is to code a  *
 * telnet honeypot in order to track IOT botnets.   *
 ***************************************************/

import (
	"github.com/Sirupsen/logrus"

	"io"
	"io/ioutil"
	"net"
	"strconv"
	"time"
)

var (
	Logger     *logrus.Logger
	ReportChan chan []byte
)

// Initialize logger & report channel
func init() {
	Logger = logrus.New()
	Logger.Formatter = &logrus.TextFormatter{
		FullTimestamp: true,
	}

	ReportChan = make(chan []byte, 10)
}

// Entry point
func main() {
	// Bind on telnet port (23)
	server, err := net.Listen("tcp4", "0.0.0.0:23")
	if err != nil {
		Logger.WithError(err).Fatalf("Error while starting honeypot.")
	}

	// Close socket on exit
	defer server.Close()

	Logger.Infof("My little honeypot has been started on 0.0.0.0:23.")

	// Pull report in another goroutine
	go pullReport()

	// Accept connections ad vitam eternam.
	for {
		client, err := server.Accept()
		if err != nil {
			Logger.WithError(err).Errorf("Error while accepting client.")
			continue
		}

		// Handle client connection in another goroutine
		go handleClient(client)
	}
}

func handleClient(conn net.Conn) {
	var (
		IACS_PAK     = []byte{0xff, 0xfd, 0x01}
		LOGIN_PAK    = []byte{0x6c, 0x6f, 0x67, 0x69, 0x6e, 0x3a}                                     // login:
		PASSWORD_PAK = []byte{0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x3a}                   // password:
		PROMPT_PAK   = []byte{0x61, 0x64, 0x6d, 0x69, 0x6e, 0x40, 0x64, 0x74, 0x63, 0x20, 0x24, 0x3e} // admin@dtc $>
	)

	// Allocate buffer
	report := make([]byte, 2048)

	// On return, post the buffer in the chan and close the socket
	defer func() {
		ReportChan <- report
		conn.Close()
	}()

	Logger.Infof("New incoming connection from %s on %s.", conn.RemoteAddr().String(), conn.LocalAddr().String())

	// Send IACS (read telnet RFC for further details)
	buffer, res := writeData(conn, IACS_PAK)
	report = append(report, buffer...)
	if !res {
		return
	}

	// Login
	buffer, res = writeData(conn, LOGIN_PAK)
	report = append(report, buffer...)
	if !res {
		return
	}

	// Password
	buffer, res = writeData(conn, PASSWORD_PAK)
	report = append(report, buffer...)
	if !res {
		return
	}

	// Read 10 shell commands or until the remote device closes the connection.
	for i := 0; i < 10; i++ {
		if !res {
			break
		}

		buffer, res = writeData(conn, PROMPT_PAK)
		report = append(report, buffer...)
	}
}

// Write data and read the answer
func writeData(conn net.Conn, data []byte) ([]byte, bool) {
	_, err := conn.Write(data)
	if err != nil {
		Logger.Errorf("[%s] Error while writing pak: %s", conn.RemoteAddr().String(), err.Error())
		return []byte{}, false
	}

	res, succeed := readData(conn)
	if !succeed {
		return res, false
	}

	return res, true
}

// Read data sent by the remote client
func readData(conn net.Conn) ([]byte, bool) {
	// Wait 250ms. Dirty as hell yeah. But it does work :)
	<-time.After(250 * time.Millisecond)

	bufSize := 129 // why not?
	buf := make([]byte, bufSize)
	data := make([]byte, 0, 4096)

	// Read all the data sent by the client.
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if err != io.EOF {
				Logger.Errorf("[%s] Error while reading data: %s", conn.RemoteAddr().String(), err.Error())
				return data, false
			}

			break
		}

		data = append(data, buf[:n]...)

		// We probably read all the data sent, we can leave now.
		if n < bufSize {
			break
		}
	}

	return data, true
}

// Pull reports from the chan and write them in a file
func pullReport() {
	i := 0
	for {
		report := <-ReportChan
		ioutil.WriteFile(strconv.Itoa(i), report, 0644)
		Logger.Infof("Logs written.")
		i++
	}
}
