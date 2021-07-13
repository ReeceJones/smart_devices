import std.stdio;
import std.file;
import std.json;
import std.algorithm;
import std.conv;
import core.stdc.time;
import core.stdc.string;
import std.string;
import std.array;
import std.digest.sha;
import std.bitmanip : bitfields;

/*
Input:

struct header {
    uint32_t sig;        // Magic Signature of 32 bits to identify the binary ("0xcafef00d")
    uint8_t numDevices;  // Number of smart devices on the network
    uint8_t hash[32];    // A SHA256 Hash of all binary entries
    uin64_t timestamp;   // Timestamp of when binary was generated
}

struct entry {
    char name[256];     // The name of the device
    uint64_t mac:48;    // The mac address of the device
    uint64_t majVer:8;  // The major version of the firmware the X in X.Y
    uint64_t minVer:8;  // The minor version of the firmware the Y in X.Y
}
*/

struct Header
{
	uint sig = 0xcafef00d;
	ubyte numDevices;
	ubyte[32] hash;
	ulong timestamp;
}

struct Entry
{
	ubyte[256] name;
	mixin(bitfields!(
		ulong, "mac", 48,
		ulong, "majVer", 8,
		ulong, "minVer", 8
	));
}

void convertInput(string inFileName, string outFileName)
{
	auto inputJson = parseJSON(readText(inFileName));
	auto devices = inputJson["devices"];
	Entry[] entries;
	foreach (JSONValue ent; devices.array())
	{
		auto name = ent["name"].toString().strip("\"").toStringz();
		auto vers = ent["fw_version"].toString().strip("\"").split(".");
		string smac = ent["mac_address"].toString().strip("\"");
		ulong mac = 0;
		int i = 0;
		foreach (string tok; smac.split(":"))
		{
			writeln(tok);
			mac = mac | (tok.to!ulong(16) << (i++ * 8));
		}
		Entry e;
		e.mac = mac;
		e.majVer = cast(ulong)*(vers[0].ptr);
		e.minVer = cast(ulong)*(vers[1].ptr);
		memcpy(&e.name, name, name.strlen);
		entries ~= e;
	}
	Header h = {
		numDevices : cast(ubyte)entries.length,
		hash : cast(ubyte[32])sha256Of(cast(void[])entries),
		timestamp : cast(ulong)time(null)
	};
	auto f = File(outFileName, "w");
	f.rawWrite([h]);
	f.rawWrite(entries);
}


void main()
{
	writeln(Header.sizeof);
	writeln(Entry.sizeof);
	convertInput("input.json", "out.bin");
}