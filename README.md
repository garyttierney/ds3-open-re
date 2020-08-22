# Dark Souls 3 - Reverse Engineering

This repository serves as a set of tools, resources and collected data related to reverse engineering the Dark Souls 3 game engine and netcode.
The focus is on the matchmaking implementation, with the hopes of eventually creating a private matchmaking server.

# What can I find in here?

The layout of the directory structure in this repository should be mostly self-explanatory for now.
Each sub-directory has its own README which you can visit from the links below.

├───[proto](/tree/master/proto) - Collection of [protobuf](https://github.com/protocolbuffers/protobuf/) definitions
│   └───[dumps](/tree/master/proto/dumps) - An empty directory for dumping out protobuf messages to.
└───[tools](/tree/master/tools) - Collection of various tools for working with the runtime game or game data.
    └───[tables](/tree/master/tools/tables) - CheatEngine tables used for debugging.

# How can I help?

The work being done here is by members of the ?ServerName? souls modding discord.
Check [their website](http://soulsmodding.wikidot.com/) for an invite to the Discord server where any discussion around this happens.
 
I run a Ghidra server containing runtime images of the Dark Souls 3 executable.
You can access it by connecting to the Ghidra repository at soulsmodding-ghidra-hosting.uksouth.cloudapp.azure.com.

If you would like write access, please ping `sfix#5190` on Discord, either via DM or a ping in ?ServerName?.

You can check the [issues](https://github.com/garyttierney/ds3-open-re/issues) page for a list of things that are being worked on. 