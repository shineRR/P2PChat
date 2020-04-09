package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strings"
)

const Port = "8080"
const BroadcastAdr = "192.168.0.255:8080"

func getLocalIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

func createTCPConnection(IP string) {
	fmt.Print(IP)
	conn, err := net.Dial("tcp", IP)
	if err != nil {
		// handle error
	}
	for {
		enc:=json.NewEncoder(conn)
		enc.Encode("privet")
	}
}

func listenTCPConnection(IP string) {
	// Start listening to port 8080 for TCP connection
	listener, err := net.Listen("tcp", IP + ":" + Port)
	if err != nil {
		fmt.Println(err)
		return
	}

	defer func() {
		listener.Close()
		fmt.Println("Listener closed")
	}()

	for  {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println(err)
			break
		}

		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {

	fmt.Println("Handling new connection...")
	bufferBytes, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		log.Println("client left..")
		conn.Close()

		return
	}
	message := string(bufferBytes)
	clientAddr := conn.RemoteAddr().String()
	fmt.Println(message + " from " + clientAddr + "\n")

	newmessage := strings.ToUpper(message)
	conn.Write([]byte(newmessage + "\n"))
}

func listenUDP() {
	pc, err := net.ListenPacket("udp4", ":" + Port)
	if err != nil {
		panic(err)
	}
	defer pc.Close()

	buf := make([]byte, 1024)
	n, addr, err := pc.ReadFrom(buf)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s sent this: %s\n", addr, buf[:n])

	go createTCPConnection(addr.String())
}

func sendUDP(name string) {
	listenAddr, err := net.ResolveUDPAddr("udp4", ":" + Port)
	if err != nil {
		panic(err)
	}
	list, err := net.ListenUDP("udp4", listenAddr)
	if err != nil {
		panic(err)
	}
	defer list.Close()

	addr, err := net.ResolveUDPAddr("udp4", BroadcastAdr)
	if err != nil {
		panic(err)
	}

	_, err = list.WriteTo([]byte(name + " Connected :)"), addr)
	if err != nil {
		panic(err)
	}
}

func introduceMyself() {
	fmt.Print("Enter your name: ")
	var name string
	fmt.Scanln(&name)
	sendUDP(name)
}

func main() {
	introduceMyself()
	go listenTCPConnection(getLocalIP())
	for {
		listenUDP()
	}
}