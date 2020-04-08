package main

import (
	"fmt"
	"net"
)

const Port = ":8080"
const BroadcastAdr = "192.168.0.255:8080"

func listenUDP() {
	pc, err := net.ListenPacket("udp4", Port)
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
}

func sendUDP(name string) {
	listenAddr, err := net.ResolveUDPAddr("udp4", Port)
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

func introduceMe() {
	fmt.Print("Enter your name: ")
	var name string
	fmt.Scanln(&name)
	sendUDP(name)
}

func main() {
	introduceMe()
	for true {
		listenUDP()
	}
}