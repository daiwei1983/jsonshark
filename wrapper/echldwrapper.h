#ifndef ECHLDWRAPPER_H
#define ECHLDWRAPPER_H

#include <node.h>

class EchldWrapper : public node::ObjectWrap {
	public:
		//Initialize the EchldWrapper
		static void Init(v8::Handle<v8::Object> exports);

	private:
		EchldWrapper();
		~EchldWrapper();

		//New a EchldWrapper
		static v8::Handle<v8::Value> New(const v8::Arguments& args);

		//Function reserved for echld module, to new an echld sub-process
		static v8::Handle<v8::Value> NewChild(const v8::Arguments& args);
		
		//Function used to return a list of available interfaces on the server, where the packets will be captured and parsed. 
		static v8::Handle<v8::Value> InterfaceList(const v8::Arguments& args);

		//Function used to return a list of available raw packet data files, which will be opened remoted from the client side
		static v8::Handle<v8::Value> FileList(const v8::Arguments& args);
		
		//Function reserved for echld module, to close an echld sub-process
		static v8::Handle<v8::Value> CloseChild(const v8::Arguments& args);

		//Function used to return a summarized list of the captured packets, which are organized as json strings
		static v8::Handle<v8::Value> Capture(const v8::Arguments& args);

		//Function used to open raw packet data files on the server remotely from the client side
		static v8::Handle<v8::Value> OpenFile(const v8::Arguments& args);

		//Function reserved for echld module, to ping a echld sub-process
		static v8::Handle<v8::Value> Ping(const v8::Arguments& args);

		//Function reserved for echld module, to set the echld parameters
		static v8::Handle<v8::Value> Set(const v8::Arguments& args);

		//Function reserved for echld module, to get the echld parameters
		static v8::Handle<v8::Value> Get(const v8::Arguments& args);

		//Function used to stop the tshark commands that are capturing packets
		static v8::Handle<v8::Value> Stop(const v8::Arguments& args);

		//Function reserved for echld module, to save the raw packet data files
		static v8::Handle<v8::Value> Save(const v8::Arguments& args);

		//Function used to dissect the already captured packets, detailed packet information will be returned as json strings.
		static v8::Handle<v8::Value> Dissect(const v8::Arguments& args);		
		
		//Field reserverd for echld module, to indicate the number of the active echld sub-processes
		int childNumber;
};

#endif
