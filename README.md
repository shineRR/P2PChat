# P2PChat-Go
Develop a program for the exchange of text messages, working in a local network in a peer-to-peer mode.
Each participant in the messaging exchange (node) is identified by an IP address and an arbitrary name that is specified by the user (via a command line parameter, configuration file, or in any other way). The uniqueness of the names is not required.
Each node uses UDP to form a list of active nodes (IP addresses and names):
* after starting the node sends a broadcast packet containing its name to notify other nodes on the network about its connection to the network;
* other nodes that have received such a packet establish a TCP connection with the sender for exchanging messages and transmit their name through it for identification in the chat.<br/>
<b>A new client can join the chat at any time.</b><br/>
Messages are exchanged using TCP in a logically shared space: each node maintains one TCP connection with every other node and sends its messages to all nodes on the network. A node disconnection must be handled correctly by other nodes.
The user interface of the program should be able to enter from the keyboard and send messages, as well as view the history of events since the last launch of the program.
The story should include the following events in chronological order with timestamps:
* incoming messages from other nodes (indicating the name and IP-address of the sender);
* own sent messages;
* detection of a new node;
* shutdown of a running node.<br/>
For messaging, it is recommended that you develop your own message format that allows you to transfer messages of different types and simplifies the transmission of messages in the streaming mode used in TCP.
* Implement the transfer of the existing history of events to the node upon connection.
Once nodes are discovered, the new node queries any existing event history. The complete history of events known to the node is transmitted over the TCP connection established between these nodes. Once received, the story should be displayed appropriately in the user interface.
