#define BUILDING_NODE_EXTENSION
#include <node.h>
#include "echldwrapper.h"
#include "jsonparser.h"

extern "C" {
	//#include "config.h"
	
	//#ifdef HAVE_FCNTL_H
	#include <fcntl.h>
	//#endif

	//#ifdef HAVE_SYS_TYPES_H
	# include <sys/types.h>
	//#endif

	#include <sys/time.h>
	#include <sys/uio.h>
	#include <sys/wait.h>

	//#ifdef HAVE_UNISTD_H
	#include <unistd.h>
	//#endif

	#include <signal.h>
	#include <stdio.h>
	#include <stdlib.h>
	#include <string.h>
	#include <signal.h>
	#include <math.h>
	#include <malloc.h>

/*	#include "echld/echld.h"
	#include "echld/echld-util.h"

	#include "epan/epan.h"
	#include "wsutil/str_util.h"
	#include "capture-pcap-util.h"*/
}

using namespace v8;
//using namespace std;

#define MAX_PARAMSETS 16
#define READ 0
#define WRITE 1
#define FALSE 0
#define TRUE 1
#define bool int

//The root password, which will be used to run commands in sudo mode
const char *ROOT_PASSWORD = "123456";
//The directory where wireshark is installed, which will be used to run tshark commands
const char *WIRESHARK_DIRECTORY = "/etc/opt/wireshark/";
//The directory where raw packet data files are saved, which will be opened remotely from the client side
const char *FILE_DIRECTORY = "/etc/opt/jsonshark/public/data/";

EchldWrapper::EchldWrapper() {};
EchldWrapper::~EchldWrapper() {};

//Clean up zombie child processes, if necessary.
void cleanupChildProcess(int signalNumber) {
	int status;
	printf("I am waiting, and my pid is %d.\n", getpid());
	wait(&status);
	printf("I am done waiting.\n");
}

//Initialize the EchldWrapper
void EchldWrapper::Init(Handle<Object> exports) {
	// Prepare constructor template
	Local<FunctionTemplate> tpl = FunctionTemplate::New(New);
	tpl->SetClassName(String::NewSymbol("EchldWrapper"));
	tpl->InstanceTemplate()->SetInternalFieldCount(1);
	// Prototype
	tpl->PrototypeTemplate()->Set(String::NewSymbol("ping"), FunctionTemplate::New(Ping)->GetFunction());
	tpl->PrototypeTemplate()->Set(String::NewSymbol("interfaceList"), FunctionTemplate::New(InterfaceList)->GetFunction());
	tpl->PrototypeTemplate()->Set(String::NewSymbol("fileList"), FunctionTemplate::New(FileList)->GetFunction());
	tpl->PrototypeTemplate()->Set(String::NewSymbol("newChild"), FunctionTemplate::New(NewChild)->GetFunction());
	tpl->PrototypeTemplate()->Set(String::NewSymbol("closeChild"), FunctionTemplate::New(CloseChild)->GetFunction());
	tpl->PrototypeTemplate()->Set(String::NewSymbol("capture"), FunctionTemplate::New(Capture)->GetFunction());
	tpl->PrototypeTemplate()->Set(String::NewSymbol("openFile"), FunctionTemplate::New(OpenFile)->GetFunction());
	tpl->PrototypeTemplate()->Set(String::NewSymbol("set"), FunctionTemplate::New(Set)->GetFunction());
	tpl->PrototypeTemplate()->Set(String::NewSymbol("get"), FunctionTemplate::New(Get)->GetFunction());
	tpl->PrototypeTemplate()->Set(String::NewSymbol("stop"), FunctionTemplate::New(Stop)->GetFunction());
	tpl->PrototypeTemplate()->Set(String::NewSymbol("save"), FunctionTemplate::New(Save)->GetFunction());
	tpl->PrototypeTemplate()->Set(String::NewSymbol("dissect"), FunctionTemplate::New(Dissect)->GetFunction());

	Persistent<Function> constructor = Persistent<Function>::New(tpl->GetFunction());
	exports->Set(String::NewSymbol("EchldWrapper"), constructor);

	// Handle SIGCHLD by calling cleanupChildProcess
	struct sigaction sigchldAction;
	memset(&sigchldAction, 0, sizeof(sigchldAction));
	sigchldAction.sa_handler = &cleanupChildProcess;
	sigaction(SIGCHLD, &sigchldAction, NULL);

}

//New a EchldWrapper
Handle<Value> EchldWrapper::New(const Arguments& args) {
	HandleScope scope;

	EchldWrapper* obj = new EchldWrapper();
	obj->childNumber = args[0]->IsUndefined() ? 0 : args[0]->IntegerValue();
	obj->Wrap(args.This());
	
	return args.This();
}

//Create commands that run in sudo mode given the root password. 
void createCmd(char cmd[], char* rawCmd) {
	strcpy(cmd, "echo ");
	strcat(cmd, ROOT_PASSWORD);
	strcat(cmd, " | sudo -S ");
	strcat(cmd, WIRESHARK_DIRECTORY);
	strcat(cmd, rawCmd);
}

//Function used to return a list of available interfaces on the server, where the packets will be captured and parsed. 
Handle<Value> EchldWrapper::InterfaceList(const Arguments& args) {
	HandleScope scope;
	Local<Object> obj = Object::New();
	FILE *fp;
	int status;
	char path[100];
	char cmd[200];
	createCmd(cmd, "tshark -D 2>&1");

	/* Open the command for reading. */
	fp = popen(cmd, "r");
	if (fp == NULL) {
    		printf("Failed to run command \"tshark -D\"\n" );
		exit;
	}

	char output[1000];
	memset(output, NULL, sizeof(output));
	strcpy(output, "{\"interfaces\":[");
	int i = 0, j = strlen(output);
	/* Read the output a line at a time - output it. */
	while (fgets(path, sizeof(path)-1, fp) != NULL) {
		strcat(output, "{\"name\":\"");
		j += 9;
		i = 0;
		char interface[100];
		while (path[i] != '.' || path[i+1] != ' ') {
			i++;		
		}
		i = i + 2;
		while (path[i] != '\n' && i < sizeof(path)) {
			output[j] = path[i];
			printf("%c", path[i]);
			i++;
			j++;
		}
		strcat(output, "\"},");
		j += 3;
	}
	output[strlen(output)-1] = NULL;
	strcat(output,"]}");

	/* close */
	pclose(fp);
  	obj->Set(String::NewSymbol("msg"), String::NewSymbol(output));

  	return scope.Close(obj);
}

//Function used to return a list of available raw packet data files, which will be opened remoted from the client side
Handle<Value> EchldWrapper::FileList(const Arguments& args) {
	HandleScope scope;

	printf("Running FileList in C++\n");
	Local<Object> obj = Object::New();
	FILE *fp;
	int status;
	char path[100];
	char cmd[200];
	strcpy(cmd, "ls ");
	strcat(cmd, FILE_DIRECTORY);
	strcat(cmd, " -1");

	/* Open the command for reading. */
	fp = popen(cmd, "r");
	if (fp == NULL) {
    		printf("Failed to run command \"ls -1\"\n" );
		exit;
	}

	char output[1000];
	memset(output, NULL, sizeof(output));
	strcpy(output, "{\"files\":[");
	int i = 0, j = strlen(output);
	/* Read the output a line at a time - output it. */
	while (fgets(path, sizeof(path)-1, fp) != NULL) {
		strcat(output, "{\"name\":\"");
		j += 9;
		i = 0;
		while (path[i] != '\n' && i < sizeof(path)) {
			output[j] = path[i];
			printf("%c", path[i]);
			i++;
			j++;
		}
		strcat(output, "\"},");
		j += 3;
	}
	output[strlen(output)-1] = NULL;
	strcat(output,"]}");

	/* close */
	pclose(fp);

  	obj->Set(String::NewSymbol("msg"), String::NewSymbol(output));

  	return scope.Close(obj);
}

//Function reserved for echld module, to new an echld sub-process
Handle<Value> EchldWrapper::NewChild(const Arguments& args) {
	HandleScope scope;
	EchldWrapper* obj = ObjectWrap::Unwrap<EchldWrapper>(args.This());
	//int child = echld_new(paramsets[obj->childNumber],NULL);
	int child = 1;	
	if (child > 0)
		obj->childNumber += 1;

	return scope.Close(Number::New(child));
}

//Function reserved for echld module, to close an echld sub-process
Handle<Value> EchldWrapper::CloseChild(const Arguments& args) {
	HandleScope scope;
	EchldWrapper* obj = ObjectWrap::Unwrap<EchldWrapper>(args.This());

	if (args.Length() < 1) {
    		ThrowException(Exception::TypeError(String::New("Wrong number of arguments")));
    		return scope.Close(Undefined());
  	}

  	if (!args[0]->IsNumber()) {
    		ThrowException(Exception::TypeError(String::New("Wrong arguments")));
    		return scope.Close(Undefined());
  	}

	int child = args[0]->NumberValue();
	int* cmdp = new int[1];
	*cmdp = child;
	return scope.Close(Number::New(0));
}

//Function used to run tshark or other commands as sub-processes, then return the pid so that jsonshark may kill it if necessary
pid_t popen2(const char *command, int *infp, int *outfp) {
	int p_stdin[2], p_stdout[2];
	pid_t pid;

	if (pipe(p_stdin) != 0 || pipe(p_stdout) != 0)
		return -1;
 
	pid = fork();
 
	if (pid < 0)
		return pid;
	else if (pid == 0)
	{
		setpgrp();
		close(p_stdin[WRITE]);
		dup2(p_stdin[READ], READ);
		close(p_stdout[READ]);
		dup2(p_stdout[WRITE], WRITE);
 
		execl("/bin/sh", "sh", "-c", command, NULL);
		perror("execl");
		exit(1);
	}
 
	if (infp == NULL)
		close(p_stdin[WRITE]);
	else
		*infp = p_stdin[WRITE];
 
	if (outfp == NULL)
		close(p_stdout[READ]);
	else
		*outfp = p_stdout[READ];
 
	printf("Pid for tshark is %d.\n", pid);
	return pid;
}

//Utility function to remove leading/ending space and '\n' from a string
char *trim(char *s) {
	int i = strlen(s) - 1;
	while (s[i] == '\n' || s[i] == ' ') {
		s[i] = '\0';
		i--;
	}
	i = 0;
	char *point = s;
	while(s[i] == '\n' || s[i] == ' ') {
		i++;
		point++;
	}
	return point;
}

//Utility function to add indents to the json string
void addSpace(FILE *detailTmp, int indent) {
	for(int i=0; i<=indent; i++) {
		fprintf(detailTmp, "%s", " ");
	}
}

// Extracts a C string from a V8 Utf8Value.
const char* ToCString(const v8::String::Utf8Value& value) {
  return *value ? *value : "<string conversion failed>";
}

//Function used to extract simple packet information from the detailed parsed packet information, so as to give a list of the summarized packets
void parseSimpleOutput(char *simpleOutput, char *path) {
	if(strlen(simpleOutput) == 0) {
		strcpy(simpleOutput, "{");
	}
	static bool v = FALSE;
	if (strncmp(trim(path), "Frame Number", 12) == 0) {
		strcat(simpleOutput, "\"No\": \"");
		strcat(simpleOutput, trim(path)+14);
		strcat(simpleOutput, "\",");
	}
	if (strncmp(trim(path), "[Time since reference or first frame", 36) == 0) {
		strcat(simpleOutput, "\"Time\": \"");
		strcat(simpleOutput, trim(path)+38);
		simpleOutput[strlen(simpleOutput)-1] = NULL;
		strcat(simpleOutput, "\",");
	}
	if (v == TRUE && strncmp(trim(path), "Source", 6) == 0) {
		strcat(simpleOutput, "\"Source\": \"");
		strcat(simpleOutput, trim(path)+8);
		strcat(simpleOutput, "\",");
	}
	if (v == TRUE && strncmp(trim(path), "Destination", 11) == 0) {
		strcat(simpleOutput, "\"Destination\": \"");
		strcat(simpleOutput, trim(path)+13);
		strcat(simpleOutput, "\",");
	}
	if (v == TRUE && strncmp(trim(path), "Protocol", 8) == 0) {
		strcat(simpleOutput, "\"Protocol\": \"");
		strcat(simpleOutput, trim(path)+10);
		strcat(simpleOutput, "\",");
	}
	if (v == TRUE && strncmp(trim(path), "Total Length", 12) == 0) {
		strcat(simpleOutput, "\"Length\": \"");
		strcat(simpleOutput, trim(path)+14);
		strcat(simpleOutput, "\",");
	}
	if (v == TRUE && strncmp(path, " ", 1) != 0) {
		strcat(simpleOutput, "\"Info\": \"");
		strcat(simpleOutput, trim(path));
		strcat(simpleOutput, "\"");
		v = FALSE;
	}
	if (strncmp(path, "Internet Protocol", 17) == 0) {
		v = TRUE;
	}
	else if (strncmp(trim(path), "Spanning Tree Protocol", 22) == 0 || strncmp(trim(path), "Address Resolution Protocol", 27) == 0) {
		strcat(simpleOutput, "\"Protocol\": \"");
		strcat(simpleOutput, trim(path));
		strcat(simpleOutput, "\"");
	}	
}

//Function used to parse the output from the tshark commands, which contains the detail packet information
void parseOutput(FILE *fp, FILE *simpleTmp, FILE *detailTmp, FILE *indexTmp) {
	item *root = NULL, *curItem = NULL;	
	bool v = FALSE;
	char path[1000], simpleOutput[1000];
	memset(path, NULL, sizeof(simpleOutput));
	memset(simpleOutput, NULL, sizeof(simpleOutput));
	int i, indent = 0;
	while(fgets(path, sizeof(path)-1, fp) != NULL) {
		i = 0;	
		while (path[i] != NULL && path[i] == ' ') {
			i += 4;
		}
		if (strlen(trim(path)) == 0) {
			continue;
		}
		if (i==0 && strncmp(trim(path), "[sudo]", 6) == 0 ) {
			continue;
		}
		if (i==0 && strncmp(trim(path), "Capturing", 9) == 0) {
			continue;
		}
		parseSimpleOutput(simpleOutput, path);
		
		if (i == 0 && strncmp(trim(path), "Frame X", 5) == 0) { //beginning of the next packet
			saveAsJsonString(root, detailTmp, indexTmp);
			freeItems(root);
			root = addNextItem(NULL, trim(path));
			curItem = root;
			indent = 0;

			if(strlen(simpleOutput) > 1) {
				if(simpleOutput[strlen(simpleOutput)-1] == ',')
					simpleOutput[strlen(simpleOutput)-1] = NULL;
				strcat(simpleOutput,"},\n");
				fprintf(simpleTmp, "%s", simpleOutput);
				fflush(simpleTmp);
				memset(simpleOutput, NULL, sizeof(simpleOutput));
			}
		}
		else if (i/4 == indent + 1) { //if contains the lower level info
			curItem = addChldItem(curItem, trim(path));
			indent++;
		}
		else if (i/4 < indent) { //if the info is within the upper level
			curItem = addParentItem(root, i/4, trim(path));
			indent = i/4;
		}
		else if (i/4 == indent) { //if the info is within the same level			
			curItem = addNextItem(curItem, trim(path));
		}
		memset(path, NULL, sizeof(path));
	}
	return;
}

//This is the old parse function to convert the tshark packet capture output to json messages, it works but the codes are not well organized.
void parseOutputBackup(FILE *fp, FILE *simpleTmp, FILE *detailTmp) {
	char path[1000];
	char simpleOutput[1000];
	bool v = FALSE;
	int indent = 0;
	int packetNo = 0;
	int i, j;
	memset(path, NULL, sizeof(path));
	memset(simpleOutput, NULL, sizeof(simpleOutput));
	fprintf(detailTmp, "%s", "{\n \"protocols\": [\n");
	strcpy(simpleOutput,"{"); 

	while (fgets(path, sizeof(path)-1, fp) != NULL) {
		i = 0;	
		while (path[i] != NULL && path[i] == ' ') {
			i += 4;
		}
		if (strlen(trim(path)) == 0) {
			continue;
		}
		if (i==0 && strncmp(trim(path), "[sudo]", 6) == 0 ) {
			continue;
		}
		if (i==0 && strncmp(trim(path), "Capturing", 9) == 0) {
			continue;
		}
		if (strncmp(trim(path), "Frame Number", 12) == 0) {
			strcat(simpleOutput, "\"No\": \"");
			strcat(simpleOutput, trim(path)+14);
			strcat(simpleOutput, "\",");
		}
		if (strncmp(trim(path), "[Time since reference or first frame", 36) == 0) {
			strcat(simpleOutput, "\"Time\": \"");
			strcat(simpleOutput, trim(path)+38);
			simpleOutput[strlen(simpleOutput)-1] = NULL;
			strcat(simpleOutput, "\",");
		}
		if (v == TRUE && strncmp(trim(path), "Source", 6) == 0) {
			strcat(simpleOutput, "\"Source\": \"");
			strcat(simpleOutput, trim(path)+8);
			strcat(simpleOutput, "\",");
		}
		if (v == TRUE && strncmp(trim(path), "Destination", 11) == 0) {
			strcat(simpleOutput, "\"Destination\": \"");
			strcat(simpleOutput, trim(path)+13);
			strcat(simpleOutput, "\",");
		}
		if (v == TRUE && strncmp(trim(path), "Protocol", 8) == 0) {
			strcat(simpleOutput, "\"Protocol\": \"");
			strcat(simpleOutput, trim(path)+10);
			strcat(simpleOutput, "\",");
		}
		if (v == TRUE && strncmp(trim(path), "Total Length", 12) == 0) {
			strcat(simpleOutput, "\"Length\": \"");
			strcat(simpleOutput, trim(path)+14);
			strcat(simpleOutput, "\",");
		}
		if (v == TRUE && i == 0) {
			strcat(simpleOutput, "\"Info\": \"");
			strcat(simpleOutput, trim(path));
			strcat(simpleOutput, "\"");
			v = FALSE;
		}

		if (i==0 && strncmp(trim(path), "Frame X", 5) == 0 && indent == 0) { //beginning of the packet dissected info
			fprintf(detailTmp, "%s", "  {\n");
		}		
		else if (i/4 == indent + 1 && i != 0) { //if contains the next level of info
			indent++;
			fprintf(detailTmp, "%s", ",\n");
			addSpace(detailTmp, indent);
			fprintf(detailTmp, "%s", "\"fields\": [\n");
			addSpace(detailTmp, indent+1);
			fprintf(detailTmp, "%s", "{\n");			
		}
		else if (i/4 == indent && i != 0) {  //if the info is within the same level
			fprintf(detailTmp, "%s", "\n");
			addSpace(detailTmp, indent+1);
			fprintf(detailTmp, "%s", "},\n");
			addSpace(detailTmp, indent+1);
			fprintf(detailTmp, "%s", "{\n");
		}
		else if (i/4 == indent - 1 && i != 0) { //if goes back to the previous level		
			fprintf(detailTmp, "%s", "\n");
			addSpace(detailTmp, indent+1);
			fprintf(detailTmp, "%s", "}\n");
			addSpace(detailTmp, indent);
			fprintf(detailTmp, "%s", "]\n");
			indent--;
			addSpace(detailTmp, indent);
			fprintf(detailTmp, "%s", "},\n");
			addSpace(detailTmp, indent);
			fprintf(detailTmp, "%s", "{\n");
			
		}
		else if (i==0 && strncmp(trim(path), "Frame X", 5) == 0) { //beginning of the next packet			
			addSpace(detailTmp, indent+1);
			fprintf(detailTmp, "%s", "}\n");
			for(j = 0; j < indent+1; j++) {
				addSpace(detailTmp, indent+1);
				fprintf(detailTmp, "%s", "]\n");
				addSpace(detailTmp, indent);
				fprintf(detailTmp, "%s", "}\n");
			}
			if(simpleOutput[strlen(simpleOutput)-1] == ',')
				simpleOutput[strlen(simpleOutput)-1] = NULL;
			strcat(simpleOutput,"},\n");
			fprintf(simpleTmp, "%s", simpleOutput);
			fflush(simpleTmp);
			memset(simpleOutput, NULL, sizeof(simpleOutput));
			strcpy(simpleOutput,"{");
			fprintf(detailTmp, "%s", "{\n \"protocols\":[\n");
			indent = 0;
		}
		else if (i==0 && strncmp(trim(path), "Frame X", 5) != 0) { // beginning of next protocol
			addSpace(detailTmp, indent+1);
			fprintf(detailTmp, "%s", "}\n");
			for(j = 0; j < indent; j++) {
				addSpace(detailTmp, indent+1);
				fprintf(detailTmp, "%s", "]\n");
				addSpace(detailTmp, indent);
				fprintf(detailTmp, "%s", "}\n");
			}
			fprintf(detailTmp, "%s", ",\n  {");
			if (strncmp(trim(path), "Internet Protocol", 17) == 0) {
				v = TRUE;
			}
			else if (strncmp(trim(path), "Spanning Tree Protocol", 22) == 0 || strncmp(trim(path), "Address Resolution Protocol", 27) == 0) {
				strcat(simpleOutput, "\"Protocol\": \"");
				strcat(simpleOutput, trim(path));
				strcat(simpleOutput, "\"");
			}
			indent = 0;
		}
		addSpace(detailTmp, indent+1);
		fprintf(detailTmp, "%s", "\"showname\":\"");
		fprintf(detailTmp, "i is %d, ", i);
		fprintf(detailTmp, "%s", path);
		fprintf(detailTmp, "%s", "\"");
		memset(path, NULL, sizeof(path));
	}
	pclose(fp);	
	fclose(simpleTmp); 
	fclose(detailTmp);
}

//Function used to return a summarized list of the captured packets, which are organized as json strings
Handle<Value> EchldWrapper::Capture(const Arguments& args) {
	HandleScope scope;
	if (args.Length() < 4) {
		ThrowException(Exception::TypeError(String::New("Wrong number of arguments!!")));
  		return scope.Close(Undefined());
	}

	if (!args[0]->IsString() || !args[1]->IsString()) {
   		ThrowException(Exception::TypeError(String::New("Wrong arguments!!")));
		return scope.Close(Undefined());
 	}

	String::Utf8Value idStr(args[0]);
	String::Utf8Value interfaceStr(args[1]);
	String::Utf8Value optionsStr(args[2]);
	String::Utf8Value filterStr(args[3]);
	const char* filter = ToCString(filterStr);
	const char* options = ToCString(optionsStr);
  	const char* id = ToCString(idStr);
	const char* interfaces = ToCString(interfaceStr);
	printf("%s\n", id);
	printf("%s\n", interfaces);

	char rawCmd[108];
	memset(rawCmd, NULL, sizeof(rawCmd));
	strcpy(rawCmd, "tshark -i ");
	int i, j=strlen(rawCmd);
	printf("original j = %d\n", j);
	for(i=0; i<strlen(interfaces) && j<100; i++) {
		if(interfaces[i] == ',') {
			strcat(rawCmd, " -i ");
			j += 4;
		}
		else {
			rawCmd[j] = interfaces[i];
			j++;
		}
	}
	
	if (strlen(options) > 0) {
		strcat(rawCmd, " -a duration:");
		strcat(rawCmd, options);
	}
	if (strlen(filter) != NULL) {
		strcat(rawCmd, " -f ");
		strcat(rawCmd, filter);
	}

	if (j == 100) {
		printf("too many interfaces: %s\n", rawCmd);
		return scope.Close(Undefined());
	}
	strcat(rawCmd, " -V 2>&1");

	char cmd[200];
	createCmd(cmd, rawCmd);
	int infp, outfp;
	pid_t tsharkPid;
	//char buf[128];
	printf("%s\n", cmd);
	tsharkPid = popen2(cmd, &infp, &outfp);
 
	if (tsharkPid <= 0) {
		printf("Unable to exec tshark -i\n");
		exit(1);
	}
 
	close(infp);
	FILE *fp, *simpleTmp, *detailTmp, *indexTmp;
	fp = fdopen(outfp, "r");
	printf("opening fp: %d\n", outfp);
	char simpleTmpName[25];
	char detailTmpName[25];
	char indexTmpName[25];
	strcpy(simpleTmpName, "./public/tmp/simple.");
	strcpy(detailTmpName, "./public/tmp/detail.");
	strcpy(indexTmpName, "./public/tmp/index.");
	strcat(simpleTmpName, id);
	strcat(detailTmpName, id);
	strcat(indexTmpName, id);
	simpleTmp = fopen(simpleTmpName, "w+");
	detailTmp = fopen(detailTmpName, "w+");
	indexTmp = fopen(indexTmpName, "w+");
	
	pid_t jsonPid;
	//printf("begin to fork.\n");
	jsonPid = fork();
	//printf("Just forked and pid id is %d.\n", jsonPid);
	if (jsonPid < 0) {
		printf("Unable to parse output\n");
		exit(1);
	}
	else if (jsonPid > 0) {
		//parent process
		return scope.Close(Number::New(tsharkPid));
	}
	else {
		//child process
		printf("Begin to prase the output!");
		parseOutput(fp, simpleTmp, detailTmp, indexTmp);
		fprintf(simpleTmp, "{\"No\": \"-1\"},\n");
		fflush(simpleTmp);
		printf("End of parsing the output!");	
		pclose(fp);	
		fclose(simpleTmp); 
		fclose(detailTmp);
		fclose(indexTmp);
	}
}

//Function used to stop the tshark commands that are capturing packets
Handle<Value> EchldWrapper::Stop(const Arguments& args) {
	HandleScope scope;
	if (args.Length() < 1) {
    		ThrowException(Exception::TypeError(String::New("Wrong number of arguments")));
    		return scope.Close(Undefined());
  	}

  	if (!args[0]->IsNumber()) {
   		ThrowException(Exception::TypeError(String::New("Wrong arguments")));
    		return scope.Close(Undefined());
  	}
	pid_t pid = args[0]->NumberValue();
	//int state = kill(pid, SIGKILL);
	//kill(pid, SIGTERM);
	int status = kill(-1*pid, SIGTERM);
	printf("We already killed tshark by calling kill(%d, SIGTERM) and status is %d.\n", pid, status);

	return scope.Close(Number::New(0));
}

//Function used to dissect the already captured packets, detailed packet information will be returned as json strings.
Handle<Value> EchldWrapper::Dissect(const Arguments& args) {
	HandleScope scope;
	if (args.Length() < 2) {
    		ThrowException(Exception::TypeError(String::New("Wrong number of arguments!!")));
    		return scope.Close(Undefined());
  	}

  	if (!args[0]->IsString() || !args[1]->IsNumber()) {
   		ThrowException(Exception::TypeError(String::New("Wrong arguments!!")));
    		return scope.Close(Undefined());
  	}

	String::Utf8Value userId(args[0]);
	String::Utf8Value pktId(args[1]);
  	const char* user = ToCString(userId);
	int pkt = args[1]->NumberValue();
	
	char index[100];
	char detailTmpName[25];
	char indexTmpName[25];
	strcpy(detailTmpName, "./public/tmp/detail.");
	strcpy(indexTmpName, "./public/tmp/index.");
	strcat(detailTmpName, user);
	strcat(indexTmpName, user);
	
	FILE *detailTmp, *indexTmp;
	detailTmp = fopen(detailTmpName, "r+");
	indexTmp = fopen(indexTmpName, "r+");

	for(int i = 0; i < pkt; i++) {
		fgets(index, sizeof(index)-1, indexTmp);
	}
	int size = 0, start = 0, end = 0;
	printf("index is %s.\n", index);
	while(index[size] != ',')
		size++;
	for(int j = 0; j < size; j++) {
		printf("%d ", index[j] - '0');
		start += (index[j] - '0')*pow(10, size - j - 1);
	}
	printf("%c", ',');
	for(int j = size+1; j < strlen(index) - 1; j++) {
		printf("%d ", index[j] - '0');
		end += (index[j] - '0')*pow(10, strlen(index) - 2 - j);
	}

	printf("\n");
	printf("%d\n", start);
	printf("%d\n", end);

	char *output;
	output = (char *)malloc((end - start) * sizeof(char)+1);
	fseek(detailTmp, start, SEEK_SET);
	fread(output, end - start, 1, detailTmp); 
	for(int i = 0; i < end - start; i++) {
		if (output[i] < 32) {
			output[i] = ' ';
		}
	}
	output[end - start] = '\0';
	//printf("Dissect output is %s\n", output);
	Local<Object> obj = Object::New();
	obj->Set(String::NewSymbol("msg"), String::NewSymbol(output));

	free(output);

  	return scope.Close(obj);
}

//Function used to open raw packet data files on the server remotely from the client side
Handle<Value> EchldWrapper::OpenFile(const Arguments& args) {
	HandleScope scope;
	
	if (args.Length() < 2) {
		ThrowException(Exception::TypeError(String::New("Wrong number of arguments!!")));
  		return scope.Close(Undefined());
	}

	if (!args[0]->IsString() || !args[1]->IsString()) {
   		ThrowException(Exception::TypeError(String::New("Wrong arguments!!")));
		return scope.Close(Undefined());
 	}

	String::Utf8Value idStr(args[0]);
	String::Utf8Value fileStr(args[1]);
  	const char* id = ToCString(idStr);
	const char* files = ToCString(fileStr);

	char rawCmd[108];
	memset(rawCmd, NULL, sizeof(rawCmd));
	strcpy(rawCmd, "tshark -r ");
	strcat(rawCmd, FILE_DIRECTORY);
	strcat(rawCmd, files);
	strcat(rawCmd, " -V 2>&1");

	char cmd[200];
	createCmd(cmd, rawCmd);
	int infp, outfp;
	pid_t tsharkPid;
	tsharkPid = popen2(cmd, &infp, &outfp);
 
	if (tsharkPid <= 0) {
		printf("Unable to exec tshark -i\n");
		exit(1);
	}
 
	close(infp);
	FILE *fp, *simpleTmp, *detailTmp, *indexTmp;
	fp = fdopen(outfp, "r");
	char simpleTmpName[25];
	char detailTmpName[25];
	char indexTmpName[25];
	strcpy(simpleTmpName, "./public/tmp/simple.");
	strcpy(detailTmpName, "./public/tmp/detail.");
	strcpy(indexTmpName, "./public/tmp/index.");
	strcat(simpleTmpName, id);
	strcat(detailTmpName, id);
	strcat(indexTmpName, id);
	simpleTmp = fopen(simpleTmpName, "w+");
	detailTmp = fopen(detailTmpName, "w+");
	indexTmp = fopen(indexTmpName, "w+");
	
	pid_t jsonPid;
	jsonPid = fork();
	if (jsonPid < 0) {
		printf("Unable to parse output\n");
		exit(1);
	}
	else if (jsonPid > 0) {
		//parent process
		return scope.Close(Number::New(tsharkPid));
	}
	else {
		//child process
		parseOutput(fp, simpleTmp, detailTmp, indexTmp);		
		pclose(fp);	
		fclose(simpleTmp); 
		fclose(detailTmp);
		fclose(indexTmp);
	}
	return scope.Close(String::New("Begin to open file!"));
}

//Function reserved for echld module, to set the echld parameters
Handle<Value> EchldWrapper::Set(const Arguments& args) {
	HandleScope scope;

	return scope.Close(String::New("Begin to set echld!"));
}

//Function reserved for echld module, to get the echld parameters
Handle<Value> EchldWrapper::Get(const Arguments& args) {
	HandleScope scope;

	return scope.Close(String::New("Begin to get echld!"));
}

//Function reserved for echld module, to save the raw packet data files
Handle<Value> EchldWrapper::Save(const Arguments& args) {
	HandleScope scope;

	return scope.Close(String::New("Begin to save file!"));
}

//Function reserved for echld module, to ping a echld sub-process
Handle<Value> EchldWrapper::Ping(const Arguments& args) {
	HandleScope scope;

	if (args.Length() < 1) {
		ThrowException(Exception::TypeError(String::New("Wrong number of arguments")));
		return scope.Close(Undefined());
	}

	if (!args[0]->IsNumber()) {
		ThrowException(Exception::TypeError(String::New("Wrong arguments")));
		return scope.Close(Undefined());
	}

	return scope.Close(String::New("Begin to ping echld!"));
}
