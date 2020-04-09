package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
)

const (
	Port 			= "8080"
	BroadcastAdr	= "192.168.0.255:8080"
	CONNECT			= "CONNECT"
	RESPONSE		= "RESPONSE"
	HISTORY			= "HISTORY"
	PUBLIC			= "PUBLIC"
	DISCONNECT		= "DISCONNECT"
)

type Message struct {
	Kind      	string //
	Username	string //my username
	IP        	string //Ip address of my computer
	MSG       	string //message
}

var (
	messages                            =[]Message{}
	mutex                               = new(sync.Mutex)
	myName          string              = ""
	listConnections map[string]net.Conn = make(map[string]net.Conn)
	listIPs         map[string]string   = make(map[string]string)
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
			fmt.Println(msg.MSG + " - " + msg.Username + "[" + msg.IP + "]")

		case PUBLIC:
			fmt.Println(msg.MSG + " - " + msg.Username + "[" + msg.IP + "]")
			messages = append(messages, *msg)

		case HISTORY:
			sendHistoryOfCurrentSession(*msg)

		case DISCONNECT:
			disconnect(*msg)
			return
		}
	}
}

func disconnect(msg Message) {
	mutex.Lock()
	delete(listIPs, msg.Username)
	delete(listConnections, msg.Username)
	mutex.Unlock()
	fmt.Println(msg.Username + " left the chat :(")
}

func handleConnection(msg Message, conn net.Conn) bool {
	mutex.Lock()
	listConnections[msg.Username] = conn
	listIPs[msg.Username] = msg.IP
	mutex.Unlock()
	return true
}

func (msg *Message) sendMessage() {
	for _, peerConnection := range listConnections {
		enc := json.NewEncoder(peerConnection)
		enc.Encode(msg)
	}
}

func (msg *Message) sendPrivateMessage(receiver string) {
	enc := json.NewEncoder(listConnections[receiver])
	enc.Encode(msg)
}

func sendHistoryOfCurrentSession(msg Message) {
	for _, msgToSend := range messages {
		msgToSend.sendPrivateMessage(msg.Username)
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
	fmt.Println("Welcome to the chat " + name + " :)" + " - Server")
	msg := createMessage("CONNECT", name, getLocalIP(), "Hello, my friend\n")
	myName = name
	msg.sendUDP()
}

func server() {
	go listenTCPConnection(getLocalIP())
}

func printHelp() {
	fmt.Println("	'.disconnect' - to disconnect from the chat")
	fmt.Println("	'.hist [name]' - to ask for history of messages")
}

func userExists(name string) bool {
	for n, _ := range listIPs {
		if name == n {
			return true
		}
	}
	return false
}

func userInput() {
	msg := new(Message)
	for {
		var message string
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			fmt.Println(scanner.Text() + " - " + myName + "(Me)")
			message = scanner.Text()
			switch message {
			case ".disconnect":
				disconnectMsg := createMessage(DISCONNECT, myName, getLocalIP(), "Disconnected")
				disconnectMsg.sendMessage()
				fmt.Println("You have left the chat :(")
				os.Exit(0)
			case ".help":
				printHelp()
			default:
				if message[0:5] == ".hist" {
					username := message[6:len(message)]
					if userExists(username) {
						createMessage(HISTORY, myName, getLocalIP(), username).sendMessage()
					}
				} else if len(message) > 0 {
					msg = createMessage(PUBLIC, myName, getLocalIP(), message)
					messages = append(messages, *msg)
					msg.sendMessage()
				}
			}
			//log.Println(messages)
		}
		if err := scanner.Err(); err != nil {
			log.Println(err)
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