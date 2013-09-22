#define BUILDING_NODE_EXTENSION
#include <node.h>
#include "echldwrapper.h"

using namespace v8;

void InitAll(Handle<Object> exports) {
	EchldWrapper::Init(exports);
}

NODE_MODULE(addon, InitAll)