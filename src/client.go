package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"
)

const (
	Port 			= "8080"
	BroadcastAdr	= "192.168.0.255:8080"
	DNSGoogle		= "8.8.8.8:80"
	CONNECT			= "CONNECT"
	MSGRESPONSE		= "MSGRESPONSE"
	HISTORY			= "HISTORY"
	PUBLIC			= "PUBLIC"
	DISCONNECT		= "DISCONNECT"
)

type Message struct {
	Kind      	string		//	Type of message
	Time 		time.Time	// 	Time of message
	Username	string		//	Username of the message
	IP        	string		//	Ip address of the computer
	MSG       	string		//	message
}

var (
	messages                            =[]Message{}
	mutex                               = new(sync.Mutex)
	myName          string              = ""
	listConnections map[string]net.Conn = make(map[string]net.Conn)
	listIPs         map[string]string   = make(map[string]string)
)

func createMessage(Kind string, Time time.Time, Username string, IP string, Msg string) (msg *Message) {
	msg = new(Message)
	msg.Kind = Kind
	msg.Time = Time
	msg.Username = Username
	msg.IP = IP
	msg.MSG = Msg
	return
}

func getLocalIP() string {
	conn, err := net.Dial("udp", DNSGoogle)
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

		go receiveMessage(conn)
	}
}

func getNameByIP(IP string) string {
	for n, adr := range listIPs {
		if adr == IP {
			return n
		}
	}
	return ""
}

func receiveMessage(conn net.Conn) {
	defer func() {
		conn.Close()
	}()

	dec := json.NewDecoder(conn)
	msg := new(Message)
	for {
		if err := dec.Decode(msg); err != nil {
			msg := createMessage(DISCONNECT, time.Now(), getNameByIP(conn.RemoteAddr().String()), "", "")
			disconnect(*msg)
			return
		}

		msg.Time = time.Now()
		switch msg.Kind {
		case CONNECT:
			if !handleConnection(*msg, conn) {
				return
			}
		case MSGRESPONSE:
			if msg.IP == getLocalIP() {
				fmt.Println(msg.MSG + " - " + msg.Username + "(Me)" + msg.Time.Format("01-02-2006 15:04:05"))
			} else {
				fmt.Println(msg.MSG + " - " + msg.Username + "[" + msg.IP + "] " + msg.Time.Format("01-02-2006 15:04:05"))
			}

		case PUBLIC:
			fmt.Println(msg.MSG + " - " + msg.Username + "[" + msg.IP + "] " + msg.Time.Format("01-02-2006 15:04:05"))
			messages = append(messages, *msg)

		case HISTORY:
			sendHistoryOfCurrentSession(*msg)

		case DISCONNECT:
			disconnect(*msg)
			return
		}
	}
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
	msg.Kind = MSGRESPONSE
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

	receivedMsg := createMessage(CONNECT, time.Now(), string(buf[:n]), addr.String(), "123")
	conn := createTCPConnection(addr.String())
	handleConnection(*receivedMsg, conn)
	enc:= json.NewEncoder(conn)
	introMessage := createMessage(CONNECT, time.Now(), myName, getLocalIP(), "Response for UDP packet\n")
	enc.Encode(introMessage)
	go listenUDP()
	go receiveMessage(conn)
}

func (MSG *Message) sendUDPBroadcast() {
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
	fmt.Println("Welcome to the chat " + name + " :)" + " - Server " + time.Now().Format("01-02-2006 15:04:05"))
	msg := createMessage("CONNECT", time.Now(), name, getLocalIP(), "Hello, my friend\n")
	myName = name
	msg.sendUDPBroadcast()
}

func printHelp() {
	fmt.Println("	'.disconnect' - to disconnect from the chat")
	fmt.Println("	'.hist [name]' - to ask for history of messages")
}

func disconnect(msg Message) {
	mutex.Lock()
	delete(listIPs, msg.Username)
	delete(listConnections, msg.Username)
	mutex.Unlock()
	fmt.Println(msg.Username + " left the chat :(")
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
			fmt.Println(scanner.Text() + " - " + myName + "(Me) " + time.Now().Format("01-02-2006 15:04:05"))
			message = scanner.Text()
			switch message {
			case ".disconnect":
				disconnectMsg := createMessage(DISCONNECT,  time.Now(), myName, getLocalIP(), "Disconnected")
				disconnectMsg.sendMessage()
				fmt.Println("You have left the chat :( " + time.Now().Format("01-02-2006 15:04:05"))
				os.Exit(0)
			case ".help":
				printHelp()
			default:
				if len(message) > 6 && message[0:5] == ".hist" {
					username := message[6:len(message)]
					if userExists(username) {
						createMessage(HISTORY, time.Now(), myName, getLocalIP(), username).sendMessage()
					} else if username == myName {
						fmt.Println("You can't ask yourself to send history :D")
					} else {
						fmt.Println(username + " isn't online.")
					}
				} else if len(message) > 0 {
					msg = createMessage(PUBLIC, time.Now(), myName, getLocalIP(), message)
					messages = append(messages, *msg)
					msg.sendMessage()
				}
			}
		}
		if err := scanner.Err(); err != nil {
			log.Println(err)
		}
	}
	os.Exit(1)
}

func startServer() {
	go listenTCPConnection(getLocalIP())
}

func main() {
	introduceMyself()
	go listenUDP()
	go startServer()
	userInput()
}