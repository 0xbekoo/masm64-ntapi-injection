## `⚠️` NTAPI Injection with MASM64 Assembly

This project demonstrates the technique of NTAPI Injection using MASM64 Assembly. The goal of this project is to inject a shellcode into a target process using low-level Windows NT Native API (NTAPI) functions. 

## `🔧` Prerequisites

Before you begin, ensure you have the following tools installed:

- MASM64 (Microsoft Macro Assembler for 64-bit Windows)
- Microsoft Visual Studio (or any IDE supporting MASM64)
- x64dbg or a similar debugger (optional but recommended for debugging purposes)
- Windows 10/11 x64 (The code is tailored for modern Windows OS, and might not work on older versions)

Since the project does not use any function to print the program's status to the screen, you will need to track the results using a debugger tool.

## `⚙️` Required Modifications Before Running the Project
Before running the project, some changes need to be made. Follow the steps below to update the necessary configurations:

- **PID Value:** The PID value is set to 0 by default in the main.asm file. Change this to your target PID value:

```asm
.const 
    ; Make sure you enter the PID
    PID DW 0
```
<br>

- **Shellcode**: The project contains a default shellcode. When executed, this shellcode runs the command **cmd /K "echo NTAPI Injection with masm64"**. If you'd like to change this shellcode, update the following:

```asm
.code
     ; /*
     ;  cmd /K "echo NTAPI Injection with masm64"
     ; */
     Shellcode BYTE 0fch, 048h, 083h, 0e4h, 0f0h, 0e8h, 0c0h, 000h, 000h, 000h, 041h, 051h, 041h, 050h, 052h
               BYTE 051h, 056h, 048h, 031h, 0d2h, 065h, 048h, 08bh, 052h, 060h, 048h, 08bh, 052h, 018h, 048h
               ...
```

When changing the shellcode, make sure it has the same format. Values must have **'0'** at the beginning and **'h'** at the end. For example, you should write 0x41 as **041h**.

## 🚨 Disclaimer
This project has been developed solely for educational purposes. It is intended to demonstrate concepts related to NTAPI Injection using MASM64 Assembly and is not intended for use in any real-world malicious activities.

Usage in real-world scenarios is at your own risk. The author is not responsible for any damage, misuse, or legal consequences that may arise from using or distributing this project. 
