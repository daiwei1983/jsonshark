Abstract: In this project, we developed a web application based on tshark commands, so that users can remotely capture packets or open raw packet data files through browsers. Users may also dissect and parse the captured packets. Relevant detailed information of the packets will thus be shown in the browser. This application is composed of three parts, the front end, the Node.js back end and the wrapper based on tshark commands. The front end (index.ejs) is responsible for sending user requests, displaying the captured and parsed packets. The node.js back end (app.js and echld.js) is responsible for handling user requests by calling the wrapper and communicating with the front end in real time through socket.io module. The wrapper (echldwrapper.h .cc, jsonparser.h .cc) is implemented as a c/c++ addon module for the node.js server, so that the back end can call tshark commands as sub-processes, and output the captured packets and parsed packet information as json messages. Functions in the wrapper are general enough to be extended for the echld module in wireshark, instead of only tshark commands.

1. Install

In echldwrapper.cc, write the right info based on your system configuration:
//the password required to run tshark in sudo mode under Linux
const char *ROOT_PASSWORD = "123456";
//the directory of the wireshark software, where we can run tshark commands
const char *WIRESHARK_DIRECTORY = "/etc/opt/wireshark/";
//the directory of the saved raw packet data files
const char *FILE_DIRECTORY = "/etc/opt/jsonshark/public/data/";

Recompile the c/c++ addon codes of the wrapper:
run "sudo node-gyp rebuild" under the wrapper folder, e.g. "/jsonshark/wrapper/"
For more detailed info about c/c++ module addon, see:
http://nodejs.org/api/addons.html

2. Source codes

Node.js web app:
view module
/jsonshark/views/shark/index.ejs
the control module for displaying the web pages
/jsonshark/app.js 
the control module for the echld subprocess, which will call the echld wrapper 
/jsonshark/echld.js

Echld wrapper:
The main wrapper interfaces used to open file, capture, dissect packets and so on
/jsonshark/wrapper/echldwrapper.h
/jsonshark/wrapper/echldwrapper.cc
The json parser interfaces used to convert the tshark output to json messages
/jsonshark/wrapper/jsonparser.h
/jsonshark/wrapper/jsonparser.cc
files used for compiling c/c++ addon modules in Node.js
/jsonshark/wrapper/addon.cc
/jsonshark/wrapper/binding.gyp

Directory of the tmp files that contains json messages of the parsed packet information (both detailed and summarized packet information) 
/jsonshark/public/tmp/
There are three types of tmp files, "simple.[userId]" contains a summarized list of the captured packets in json strings for the user with [userId]; "detail.[userId]" contains a detailed list of the captured packets in json strings for the user with [userId]; "index.[userId]" contains the starting and ending postions of each packet in the "detail.[userId]" file, so as to speed up searching, when users want to dissect captured packets and get the according detailed packet information.

Directory of the saved raw packet data files to be opened remotely. Currently, there are two files "test" and "test2" in this folder for the purpose of testing and showing the demo.
/jsonshark/public/data/

3. How to use Jsonshark

Run "node app.js" under the jsonshark folder

Type "http://localhost:8080" in the browser. Then you may play with jsonshark, for example:

To capture packets remotely, 1) click "Show Interfaces" button, all the available interfaces on the server will thus be shown; 2) check the interfaces to be monitoered, where the packets will be captured; 3) you may control when to stop capturing and the capture filter if necessary; 4) click "Capture" button; 5) a list of the captured packets will be shown in the "Packet results" section; 5) to see the detailed information of a packet, click the line of that packet. Relevant information will thus be expanded and shown.
 
To open raw packet data files remotely, 1) click "Show Files" button, all the available raw packet data files on the server will thus be shown; 2) check the file to be opened; 3) click "Open File" button; 4) a list of the packets saved in the file will be shown in the "Packet results" section; 5) to see the detailed information of a packet, click the line of that packet. Relevant information will thus be expanded and shown.
