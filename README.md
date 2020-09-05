# Dark Souls 3 - Reverse Engineering

This repository serves as a set of tools, resources and collected data related to reverse engineering the Dark Souls 3 game engine and netcode.
The focus is on the matchmaking implementation, with the hopes of eventually creating a private matchmaking server.

# What can I find in here?

The layout of the directory structure in this repository should be mostly self-explanatory for now.
Each sub-directory has its own README which you can visit from the links below.

- [proto](/proto) - Collection of [protobuf](https://github.com/protocolbuffers/protobuf/) definitions
    - [dumps](/proto/dumps) - An empty directory for dumping out protobuf messages to.
- [tools](/tools) - Collection of various tools for working with the runtime game or game data.
    - [tables](/tools/tables) - CheatEngine tables used for debugging.
- [packages](/packages) - Rust packages for server emulation.
    - [cwc](/packages/cwc) - A port of the CWC authenticated cipher mode.

# How can I help?

The work being done here is by members of the ?ServerName? souls modding discord.
Check [their website](http://soulsmodding.wikidot.com/) for an invite to the Discord server where any discussion around this happens.
 
I run a Ghidra server containing runtime images of the Dark Souls 3 executable.
You can access it by connecting to the Ghidra repository at soulsmodding-ghidra-hosting.uksouth.cloudapp.azure.com.

If you would like write access, please ping `sfix#5190` on Discord, either via DM or a ping in ?ServerName?.
This server is running Ghidra 9.2, so you will need to build your own distribution or get one from [Ghidra, batteries included](https://github.com/garyttierney/ghidra-batteries-included) before you can access the repository.

You can check the [issues](https://github.com/garyttierney/ds3-open-re/issues) page for a list of things that are being worked on. 