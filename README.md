# RDPHoneyPot
Simple RDP honeypot for attracting, analyzing, and inspecting RDP-based attacks written in C#

# Features
1. Performs basic protol mocking, allowing to destinguish RDP clients/RDP exploits from port scanners.
2. Auto-Applying ban for IP addresses already logged in the database (RDP exploiters only, port scanners are still allowed)
3. Built with .NET 8 and C#
4. Stores IP addresses, timestamps, and connection types in a SQLite database for analysis.

# Getting Started
Prerequisites:
1.NET 8.0 SDK
Clone: Get the code from this repository.
Customize.
Build in Visual Studio.

# Use Responsibly
This honeypot is a tool for security research. Deploy it in controlled environments with appropriate security measures.

# License
MIT License
