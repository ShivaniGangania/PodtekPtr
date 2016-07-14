#pragma once

#include <iostream>
#include <string>
#include "json\json.h"
#include <time.h>

using namespace std;
using namespace Json;

class PtrMessage
{

public:

	PtrMessage(Json::Value jsonMsg)
	{
		jsonMessage = jsonMsg;
	}

	PtrMessage(string message, int GID, int clientID)
	{

		jsonMessage["time"] = currentDateTime();
		jsonMessage["id"] = GID;
		jsonMessage["cid"] = clientID;
		jsonMessage["message"] = message;
		jsonMessage["TimeToLive"] = 1;
	}

	Json::Value getJsonMessage()
	{
		output(jsonMessage);
		return jsonMessage;
	}


private:

	Json::Value jsonMessage;

	const string currentDateTime() {
		time_t     now = time(0);
		struct tm  tstruct;
		char       buf[80];
		tstruct = *localtime(&now);
		strftime(buf, sizeof(buf), "%Y-%m-%d.%X", &tstruct);

		return buf;
	}

	void output(const Json::Value & value)
	{
		// querying the json object is very simple
		std::cout << value["time"];
		std::cout << value["id"];
		std::cout << value["cid"];
		std::cout << value["message"];
	}

};





































/*#include <iostream>
#include <string>
#include "json\json.h"

using namespace std;
using namespace Json;

class PtrMessage
{

public:

	PtrMessage(Json::Value jsonMessage) 
	{
		jsonMessage = jsonMessage;
	} 
	

	Value getJsonMessage() 
	{
		return jsonMessage;
	}

	PtrMessage(string message, int Time, int GID, int clientID, float TTL)
	{
		jsonMessage["time"] = Time;
		jsonMessage["id"] = GID;
		jsonMessage["cid"] = clientID;
		jsonMessage["message"] = message;
		jsonMessage["TimeToLive"] = TTL;

	}

private:

	Json::Value jsonMessage;

	
}; */

