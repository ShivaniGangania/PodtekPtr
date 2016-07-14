#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <string>
#include <chrono>          //to print current time
#include "json\json.h"
#include "PtrMessage.h"

using namespace std;
using namespace Json;

/*void output(const Json::Value & value)
{
	// querying the json object is very simple
	cout << value["time"];
	cout << value["id"];
	cout << value["cid"];
	cout << value["message"];
}*/

const string currentDateTime() {
	time_t     now = time(0);
	struct tm  tstruct;
	char       buf[80];
	tstruct = *localtime(&now);
	strftime(buf, sizeof(buf), "%Y-%m-%d.%X", &tstruct);

	return buf;
}

int main(int argc, char* argv[])

{
	string source = "Input.txt";
	string dest = "Output.json";
	int GID = 0;
	int clientId = 1;
	string message = "";
	time_t curtime;
	time(&curtime);
	ofstream outFile;
	ifstream inputFile(source);  //Text File
	if (inputFile.is_open())
	{
		string line;
		cout << "Opening file" << endl;
		while (getline(inputFile, line))  //reading file line by line
		{
			//cout << message << '\n';
			message += line;
		}
		inputFile.close();
	}
	else cout << "Unable to open file" << endl;

	Value jsonMessage;
	jsonMessage["time"] = ctime(&curtime);
	jsonMessage["id"] = GID;
	jsonMessage["cid"] = clientId;
	jsonMessage["TimeToLive"] = 1;
	jsonMessage["message"] = message;

	//PtrMessage json = new PtrMessage(message, GID, clientId); Get function was returning TRUE, instead of the entire JSON bject

	FastWriter jsonWriter;

	//output(jsonMessage);
	string file = jsonWriter.write(jsonMessage);
	outFile.open(dest, ofstream::out | ofstream::app);
	if (outFile.is_open()) {
		outFile << file;
	}
	else
	{
		cout << "Error opening file" << endl;
	}
	outFile.close();
	system("pause");

	return 0;
}











/*#include <stdio.h>
#include <iostream>
#include <fstream>
#include <string>
#include "json\json.h"
#include "Header.h"

using namespace std;
using namespace Json;

void output(const Json::Value & value);

int main() 

{
	Value jsonMessage;
	jsonMessage["time"] = 2;
	jsonMessage["id"] = 123;
	jsonMessage["cid"] = 000000;
	jsonMessage["message"] = 123;
	jsonMessage["TimeToLive"] = 0.7; 
	
	//output(fromScratch);

	// write in a nice readible way
	StyledWriter styledWriter;
	cout << styledWriter.write(jsonMessage);

	FastWriter fastWriter;
	cout << fastWriter.write(jsonMessage);

	//char FileData[1024];
	string text;

	ofstream outFile;
	ifstream InputFile("SampleData.txt");  //Text File
	if (InputFile.is_open())
	{
		while (getline(InputFile, text))  //reading file line by line
		{
			cout << text << '\n';
			outFile.open("test.txt", ofstream::out | ofstream::app);
			if (outFile.is_open()) {
				outFile << text << "\n";
			}
			else
			{
				cout << "Error opening file" << endl;
			}
			
			outFile.close();
		}


		InputFile.close();
	}

	else cout << "Unable to open file" << endl;

	system("pause");

	return 0;
}

void output(const Json::Value & value)
{
	// querying the json object 
	std::cout << value["time"];
	std::cout << value["id"];
	std::cout << value["cid"];
	std::cout << value["message"];
	std::cout << value["TimeToLive"];
}
/*FILE *fpINPUT = fopen("SampleData.txt", "r+");
FILE *fp = fopen("C:\\Users\\Admin\\Desktop\\myfile.txt", "w+");

while (fgets(FileData, 1024, fpINPUT) != NULL)
{
fputs(FileData, fp);
}

fclose(fpINPUT);
fclose(fp);*/