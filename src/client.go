package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
)

const Port = "8080"
const BroadcastAdr = "192.168.0.255:8080"
const CONNECT = "CONNECT"
const RESPONSE = "RESPONSE"
const RESPONSEUDP = "RESPONSEUDP"
const PUBLIC  = "PUBLIC"
const DISCONNECT = "DISCONNECT"

type Message struct {
	Kind      string //
	Username  string //my username
	IP        string //Ip address of my computer
	MSG       string //message
}

var (
	mutex = new(sync.Mutex)
	myName string = ""
	listConnections map[string]net.Conn = make(map[string]net.Conn)//list of users connections connected to mel
	listIPs map[string]string = make(map[string]string)//list of users IPS connected to me
)

func createMessage(Kind string, Username string, IP string, Msg string) (msg *Message) {
	msg = new(Message)
	msg.Kind = Kind
	msg.Username = Username
	msg.IP = IP
	msg.MSG = Msg
	return
}

func getLocalIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

func createTCPConnection(IP string) (conn net.Conn) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", IP)
	if err != nil {
		fmt.Println(err)
	}
	conn, err = net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		fmt.Println(err)
	}
	return
}

func listenTCPConnection(IP string) {
	//log.Println("Server started \n")
	tcpAddr, err := net.ResolveTCPAddr("tcp4", IP + ":" + Port)
	if err != nil {
		fmt.Println(err)
		return
	}
	listener, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		fmt.Println(err)
		return
	}

	defer func() {
		listener.Close()
		fmt.Println("Listener closed")
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println(err)
			break
		}

		go receive(conn)
	}
}

func receive(conn net.Conn) {
	defer func() {
		conn.Close()
		fmt.Println("closed")
	}()

	dec := json.NewDecoder(conn)
	msg := new(Message)
	for {
		if err := dec.Decode(msg); err != nil {
			fmt.Println(err)
			return
		}

		switch msg.Kind {
		case CONNECT:
			if !handleConnection(*msg, conn) {
				return
			}
		case RESPONSE:
			fmt.Println(msg.Username + " [" + msg.IP + "]" + " - " + msg.MSG)

		case PUBLIC:
			fmt.Println(msg.Username + " [" + msg.IP + "]" + " - " + msg.MSG)

		case DISCONNECT:
			//disconnect(*msg)
			break
		}
	}
}

func disconnect(msg Message) {

}

func handleConnection(msg Message, conn net.Conn) bool {
	mutex.Lock()
	listConnections[msg.Username] = conn
	listIPs[msg.Username] = msg.IP
	mutex.Unlock()
	return true
}

func (msg *Message) sendMessage() {
	for _,peerConnection := range listConnections{
		enc:=json.NewEncoder(peerConnection)
		enc.Encode(msg)
	}
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
	fmt.Printf("%s connected and ready to chat :)\n", buf[:n])

	receivedMsg := createMessage(CONNECT, string(buf[:n]), addr.String(), "123")
	conn := createTCPConnection(addr.String())
	handleConnection(*receivedMsg, conn)
	enc:= json.NewEncoder(conn)
	introMessage := createMessage(CONNECT, myName, getLocalIP(), "Response for UDP packet\n")
	enc.Encode(introMessage)
	go listenUDP()
	go receive(conn)
}

func (MSG *Message) sendUDP() {
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

	_, err = list.WriteTo([]byte(MSG.Username), addr)
	if err != nil {
		panic(err)
	}
}

func introduceMyself() {
	fmt.Print("Enter your name: ")
	var name string
	fmt.Scanln(&name)
	fmt.Println("Server - Welcome to the chat " + name + " :)")
	msg := createMessage("CONNECT", name, getLocalIP(), "Hello, my friend\n")
	myName = name
	msg.sendUDP()
}

func server() {
	go listenTCPConnection(getLocalIP())
}

func userInput() {
	msg := new(Message)
	for {
		var message string
		//fmt.Print("Message: ")x
		fmt.Scanln(&message)
		//fmt.Println("Me - ", message)
		if message == "disconnect"{
			msg = createMessage(DISCONNECT, myName, getLocalIP(),"Disconnected")
			msg.sendMessage()
			break
		} else if len(message) > 1 {
			msg = createMessage(PUBLIC, myName, getLocalIP(), message)
			msg.sendMessage()
		}
	}
	os.Exit(1)
}

func main() {
	introduceMyself()
	go listenUDP()
	go server()
	userInput()
}