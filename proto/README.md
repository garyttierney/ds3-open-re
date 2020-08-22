# Protocol Buffer Definitions

This tree contains various protobuf definitions that have been reverse engineered from the game.
They will be eventually be compiled to another language to support a private server, but for now they serve mostly as a means to examine raw protobuf data.

## Usage

All examples here assume that the user has `protoc` installed.

### Deserialize a raw message to a human readable representation

Once a dump of protobuf messages has been obtained using the `protobuf-logger` CE table, they can be decoded manually on the command line.

```pwsh
> protoc --decode_raw < proto\dumps\000000_Frpg2RequestMessage__RequestQueryLoginServerInfo.dat
1: "01100001424d254a"
3: 114
```

If a `.proto` file exists with a definition for the message, it can be applied to the binary data:

```pwsh
> protoc -Iproto/ --decode=RequestQueryLoginServerInfo proto/auth.proto < proto\stream\000000_Frpg2RequestMessage__RequestQueryLoginServerInfo.dat
steam_id: "01100001424d254a"
f3: 114
```