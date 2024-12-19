# Rhadamanthys Stealer  

# Rhadamanthys in a Nutshell

Rhadamanthys is an advanced infostealer that emerged around 2022 as a Malware-as-a-Service (MaaS) threat. Malware’s author advertised it on underground forums as first-class multi-functional stealer with tons of features, written in c++. Rhadamanthys gained significant popularity due to its sophisticated, multi-staged architecture. The malware employs a multi-stage delivery mechanism, with each stage deploying heavily obfuscated shellcode and incorporating robust anti-analysis techniques to evade detection and hinder reverse engineering. One of Rhadamanthys' features is its frequent updates and rapid release cycle, with up to 10 different versions identified so far.

This report consists of two main parts, This part is analysis of the Rhadamanthys loader ,and second part will dissect the infostealer.

# Technical Summary

1. Obfuscation Mechanism : The initial stage of the Rhadamanthys loader utilize a virtual machine (VM) called Quake3 VM (Q3VM) open-source project based on the Quake III engine to obfuscate code, This implementation makes reverse engineering more challenging.  

2. Unpacking Stages : The initial stage contains a large Base32-encoded blob of shellcode stored in the .rdata section. Rhadamanthys uses the Q3VM interpreter to decode this embedded shellcode. It drops a small piece of shellcode at first, which resolves essential imports and decompress LZSS algorithm of the actual loader.

3. Anti-Analysis Techniques : The Rhadamanthys loader employs multiple anti-analysis techniques to evade detection, The loader uses API hashing to hide it's suspeciouse imports, It's using **ROR-13** hashing algorithm, With another layer of complication is done with custom Exception Handling manipulation and redirect API calls to ensures that the loader operates stealthily. The malware performs a bunch of common techniques borrowed from the open-source Al-Khaser project. 

4. Configuration Extraction : Rhadamanthys loader stores its network configuration in the .data section during the initial stage. This configuration is passed through multiple stages and decrypted during the loader stage using the RC4 encryption algorithm. Decrypted configuration of the analyzed version of Rhadamanthys includes magic bytes "RHY", flags for command-line parsing, Encryption keys for decrypting the downloaded payload ,and one embedded Command and Control (C2) IP address.

5. Malicious Code Execution : Rhadamanthys performing multiple complex operation to execute its payload, after downloading file from it's C2 ,Rhadamanthys write payload on disk then use Rundll32 to execute one of dll exports with faked legitimate name.

# Technical Analysis

# Initial Stage 

To begin our analysis, we executed the Rhadamanthys sample in the Triage Sandbox to observe its behavior.

The sandbox analysis revealed memory dumps, identifying the execution as the second stage of shellcode ,and rhadamanthys attempts to determine the geographical location of the host by inspecting the system language settings.

<p style="text-align: center;">
  <img src="Images/00_triage_sandbox.png" alt="Sample Image" style="max-width: 100%;"/>
  <br/>
  <ins>Triage Sandbox</ins>
</p>

Additionally, the sandbox extracted a Command and Control (C2) address: `http://116.202.18.132/blob/q3k6tk.xi8o`

As many loaders, Rhadamanthys exhibits high entropy in its initial stage **6.38520**. This high entropy is expected due to the presence of encoded blob of shellcode.

Interestingly, the Rhadamanthys initial stage does not include anti-emulation checks. The lack of anti-emulation checks allows analysts to emulate  analysis to easily execute and analyze the malware's behavior.

## VM Obfuscator

The first stage of Rhadamanthys appears to be a heavly obfuscated unpacker. Its primary function is to decompress and load other stages of the malware in a stealthy manner.

The **Q3VM** packer was identified as the obfuscation mechanism used in this stage, based on its distinct characteristics. By analyzing the decoder function responsible for unpacking the next stages, we found it to be identical to the <ins>VM_Call</ins> and its callee <ins>VM_CallInterpreted</ins> functions from the Q3VM project.

This observation confirms the use of Q3VM as the packing mechanism for Rhadamanthys.


<p style="text-align: center;">
  <img src="Images/22_decoder.png" alt="Sample Image" style="max-width: 100%;"/>
  <br/>
  <ins>Identical Q3VM Protector</ins>
</p>

During the analysis, a significant blob of encoded data was located within the <ins>.rdata</ins> section starting at offset 0x1246, with a size of `107,030` bytes. This strongly confirms shellcode location.


<p style="text-align: center;">
  <img src="Images/01_encoded_shellcode.png" alt="Sample Image" style="max-width: 100%;"/>
  <br/>
  <ins>Blob(1) : Encoded Shellcode located in rdata section</ins>
</p>


It is also noteworthy that this stage does not implement any anti-debugging techniques, which simplifies the analysis process. Using an x64 debugger, we observed a straightforward unpacking process. Initially, the unpacker allocates memory for the encoded shellcode, decodes it, and then transfers execution to the decoded shellcode.

<p style="text-align: center;">
  <img src="Images/01_tailjmp_1.png" alt="Sample Image" style="max-width: 100%;"/>
  <br/>
  <ins>Shellcode After Decoded in Memory</ins>
</p>

Through this quick analysis, the functionality of the initial stage was clearly identified, and the encoded shellcode was successfully extracted. Identifying the unpacker allowed us to focus on next stages without requiring a deep investigation into the unpacking process.

# Middle Stage

The first dropped shellcode is a tiny piece of code with size of `212 KiB` ,and with entropy of `5.65524`

At the entry point, the handcrafted nature of the shellcode becomes evident. It begins with a sequence of three `NOP` instructions followed by three `INC EAX` instructions —a non-standard pattern not typically generated by compilers.

Additionally, the initial stage passes seven parameters to this shellcode. Using HashDB, we identified that four of these parameters are hashes for resolving Virtual API calls at runtime:

- **VirtualAlloc()** & **VirtualFree()** & **LocalAlloc()** & **LocalFree()**

<p style="text-align: center;">
  <img src="Images/02_entrypoint.png" alt="Sample Image" style="max-width: 100%;"/>
  <br/>
  <ins>Shellcode Entry Point</ins>
</p>

#### Overview of Middle Stage Functionality

- Retrieves the Kernel32.dll image base. 
- Resolves the passed API hashes.
- Decompress third stage of compressed LZSS algorithm. 
- Transfers execution to the third stage, passing along two arguments.

<p style="text-align: center;">
  <img src="Images/23_middle.png" alt="Sample Image" style="max-width: 100%;"/>
  <br/>
  <ins>Second Stage Functionality</ins>
</p>

<p style="text-align: center;">
  <img src="Images/23_midle_2.png" alt="Sample Image" style="max-width: 100%;"/>
  <br/>
  <ins>Jump to next stage</ins>
</p>

# Loader

The final stage of the Rhadamanthys loader is reached, containing the core and most complex functionalities of the malware. This stage begins execution with two parameters passed from the previous stage, the purpose of which will be analyzed in detail.

## Defeating Anti-Analysis

### API Hashing

Rhadamanthys use the same API hashing  methodology across all its dropped shellcodes. This is a most known anti-analysis techniques, involves hashing API names using any hashing algorithm. By doing so, the malware avoids directly referencing suspicious API calls in the Import Address Table (IAT), thereby evading detection through static analysis and hindering the work of malware analysts.

Additionally, this technique is very famous in shellcode as it is Position-Independent Code (PIC). Unlike Portable Executable (PE) files, shellcode cannot rely on the Windows loader and must independently resolve API addresses during runtime.

Rhadamanthys dynamically resolves API addresses during execution through the following steps :
- Obtain `kernel32.dll` imagebase 
- Resolve loader APIs `LoadLibraryA` and `GetProcAddress`.
- Fix IAT 

At first malware must obtain `kernel32.dll` that includes a collection of essential functions and procedures for any executable as LoadLibraryA & GetProcAddress    

Rhadamanthys implements a PEB Walk to locate kernel32.dll. This involves traversing the PEB_LDR_DATA structure to access _LDR_DATA_TABLE_ENTRY, which provides a list of loaded modules. 

<p style="text-align: center;">
  <img src="Images/31_pebwalkview.jpg" alt="Sample Image" style="max-width: 100%;"/>
  <br/>
  <ins>PEB Walk</ins>
</p>

However, the implementation disrupts standard disassembly views in tools like IDA Pro due to unconventional trick: 
- The decompiler misinterprets the InMemoryOrderModuleList offsets because the malware uses the CONTAINING_RECORD macro to directly access structure members.
- As a result, IDA incorrectly resolves offsets, requiring a manual fix through shifted pointers.

<p style="text-align: center;">
  <img src="Images/32_ida_before.png" alt="Sample Image" style="max-width: 100%;"/>
  <br/>
  <ins>PEB Walk Corruption in IDA Pro</ins>
</p>

By adjusting pointer offsets, it is possible to correct these issues and accurately identify the kernel32.dll base address.

The problem **-in a nutshell-** I think that author used the macro **CONTAINING_RECORD** to be able to directly access the list_entry members to avoid calculation of each member address from the address of list_entry so it's Distracted IDA decompiler so when it access **_LDR_DATA_TABLE_ENTRY** find **LIST_ENTRY InMemoryOrderLinks** so it uses same method that points to it with Flink to nothing rather then pointing to **DllBase** 


<p style="text-align: center;">
  <img src="Images/31_peb_corrupt.jpg" alt="Sample Image" style="max-width: 100%;"/>
  <br/>
  <ins>How Hex-Rays decompiler has beed distracted</ins>
</p>

We can use IDA Shifted Pointers to fix this ,and we need to shift by 8 bytes to point to DllBase

<p style="text-align: center;">
  <img src="Images/33_obtainkernel32(1).png" alt="Sample Image" style="max-width: 100%;"/>
  <br/>
  <ins>PEB walk to obtain kernel32.dll image-base</ins>
</p>

You can use [Hex-RaysPyTools](https://github.com/igogo-x86/HexRaysPyTools) IDA plugin to make it exactly as source code. 


After locating kernel32.dll, the malware parses its PE structure to access the Export Table. 

Rhadamanthys ensuring the base address contains a valid PE header by referencing the e_lfanew pointer and verifying the magic bytes, Then retrieves Virtual Address stored in the IMAGE_DATA_DIRECTORY to locate the Export Table at offset zero.

<p style="text-align: center;">
  <img src="Images/33_exports.png" alt="Sample Image" style="max-width: 100%;"/>
  <br/>
  <ins>Obtain kernel32.dll Export Table</ins>
</p>

The Export Table includes three arrays:    
- AddressOfNames: Contains the names of all exported functions.    
- AddressOfFunctions: Contains the addresses of all exported functions.             
- AddressOfNameOrdinals: Used for alignment of function names with their addresses.       

<p style="text-align: center;">
  <img src="Images/33_exports_structs.png" alt="Sample Image" style="max-width: 100%;"/>
  <br/>
  <ins>Export Table Structure</ins>
</p>

Rhadamanthys iterates over the AddressOfNames array, applying the **ror13_add** hashing algorithm to each export name. It then compares the resulting hash to precomputed values for LoadLibraryA and GetProcAddress.

<p style="text-align: center;">
  <img src="Images/33_pharse_exports_names.png" alt="Sample Image" style="max-width: 100%;"/>
  <br/>
  <ins>Grap & hash Names of Dll Exports</ins>
</p>

The last thing do comparizon of each hash to check LoadLibraryA and GetProcAddress hashes.

<p style="text-align: center;">
  <img src="Images/33_pharse_loaders.png" alt="Sample Image" style="max-width: 100%;"/>
  <br/>
  <ins>Check LoadLibraryA and GetProcAddress</ins>
</p>

In all this process i used [HashDB](https://hashdb.openanalysis.net/) to identify the APIs, Fix IAT ,and cleaning up IDA's pseudocode for better readability.

## Anti-Checks

Rhadamanthys implements multiple anti-analysis checks derived from the Al-Khaser project. These checks target various virtualized and debugging environments to hinder analysis. 

<table>
  <tr>
    <td><img src="Images/444444.png" alt="Image 1" width="250"><br></td>
    <td><img src="Images/22222.png" alt="Image 2" width="200"><br></td>
  </tr>
  <br>Here are just two examples of Al-Khaser implementation in Rhadamanthys loader</td>
</table>


## Exception Handling Manipulation  

Rhadamanthys employs an advanced exception-handling evasion technique as part of its anti-analysis strategy. This mechanism is commonly used in sophisticated malware to evade detection, hinder reverse engineering efforts, and disrupt dynamic analysis. The implementation of this technique highlights the high skill level of its authors.

By manipulating the exception-handling process, Rhadamanthys achieves the following objectives:
- Redirecting `ZwQueryInformationProcess` API to custom functions.
- Suppressing error notifications and alerts to avoid raising suspicion.

Initially, Rhadamanthys resolves the address of `ZwQueryInformationProcess` to hook into the process later, enabling the malware to manipulate process information queries. The loader stores the address of this function to ensure that legitimate system calls can still proceed. Additionally, Rhadamanthys obtains the address of `KiUserExceptionDispatcher`, a key component of the Windows exception-handling mechanism, which is invoked whenever an exception occurs. This gives the malware an opportunity to manipulate exception processing.

Rhadamanthys ensures that only specific calls to `ZwQueryInformationProcess` (made via exception handling) are intercepted. The malware achieves this by iterating over the KiUserExceptionDispatcher code to locate the exact point where the call to ZwQueryInformationProcess occurs.

<p style="text-align: center;">
  <img src="Images/55_ex_hndl.png" alt="Sample Image" style="max-width: 100%;"/>
  <br/>
  <ins>Search for the Call to "ZwQueryInformationProcess"</ins>
</p>

Once the call to `ZwQueryInformationProcess` is located, Rhadamanthys sets a hook by overwriting the function call with a jump to its custom function. This allows the malware to control how the process information is handled.

<p style="text-align: center;">
  <img src="Images/55_patchfunc.png" alt="Sample Image" style="max-width: 100%;"/>
  <br/>
  <ins>Patch KiUserExceptionDispatcher to Redirect the Call</ins>
</p>

Rhadamanthys redirects the call to its custom function, where it modifies the ProcessInformation flag to <ins>0x6D</ins> which corresponds to `MEM_EXECUTE_OPTION_IMAGE_DISPATCH_ENABLE`. This flag enables exception handling to be performed on the shellcode, allowing it to execute without detection.

<p style="text-align: center;">
  <img src="Images/55_ex_dis.png" alt="Sample Image" style="max-width: 100%;"/>
  <br/>
  <ins>Patched KiUserExceptionDispatcher</ins>
</p>

After successfully managing exceptions triggered by the malware and inserting a custom exception handler, Rhadamanthys gains full control over the exception-handling process. The malware then suppresses error messages by using the SetErrorMode API with the value 0x8003. This value is a combination of the following flags:

- SEM_NOOPENFILEERRORBOX: Prevents the system from displaying the critical-error handler message box.
- SEM_NOGPFAULTERRORBOX: Disables the Windows Error Reporting dialog.
- SEM_FAILCRITICALERRORS: Ensures that critical errors do not display message boxes.

These settings allow the malware to handle errors silently and avoid raising suspicion.

<p style="text-align: center;">
  <img src="Images/55_fuin.png" alt="Sample Image" style="max-width: 100%;"/>
  <br/>
  <ins>Suppressing Error Messages to Avoid Detection</ins>
</p>

## Configs

Rhadamanthys stores its encrypted configuration in the <ins>.data</ins> section, starting at offset `0x6340`. During runtime and the unpacking of multiple stages, this configuration is passed through various layers until the loader stage.

By analyzing the malware’s execution, it was determined that the configuration pointer is passed as an argument from the first shellcode to the second-stage shellcode. Further investigation revealed that the configuration is stored in an initial structure, which is allocated in the heap during the malware's initialization phase.

<p style="text-align: center;">
  <img src="Images/34_initalstruct.png3.png" alt="Sample Image" style="max-width: 100%;"/>
  <br/>
  <ins>Initial Struct Containing Configuration</ins>
</p>

Rhadamanthys’ decryption key is stored in the third stage. Unlike the encrypted configuration, which resides in the .data section, the key is dynamically allocated and utilized only during the decryption phase.

<p style="text-align: center;">
  <img src="Images/34_configs.jpg" alt="Sample Image" style="max-width: 100%;"/>
  <br/>
  <ins>Config and Key Locations Overview</ins>
</p>

Rhadamanthys uses RC4 encryption for its configuration data .The decryption is implemented over two functions in a straightforward manner as documented in [RC4](https://en.wikipedia.org/wiki/RC4) , `mb_rc4_KSA` responsible for initializing the RC4 key scheduling algorithm (KSA) with the key and key length. Second one `rc4_crypto` implements the main RC4 decryption algorithm, which performs an XOR operation between the encrypted configuration and the keystream. After decryption, Rhadamanthys check magic bytes of decrypted configs `!RHY` and set secceed status.  

<p style="text-align: center;">
  <img src="Images/34_configs_overview.png" alt="Sample Image" style="max-width: 100%;"/>
  <br/>
  <ins>Decryption Process of Rhadamanthys Configuration</ins>
</p>

We can bypass this process and retrieve decrypted configs directly using an x64 debugger.

<p style="text-align: center;">
  <img src="Images/55_configs.png" alt="Sample Image" style="max-width: 100%;"/>
  <br/>
  <ins>Decrypted Conigs</ins>
</p>

The decrypted configuration includes magic bytes, flags for command-line parsing, a key for AES decryption of the main module, and the C2 URL.


## Config Extractor 

I developed a python code you will find [Here](https://github.com/Yahyaalsayed/Malware/tree/main/Rhadamanthys), This Extractor:
- Extract embedded shellcode 
- Decode Shellcode
- Extract Configs from Initial Stage 
- Extract Key from Third Stage 'Loader'
- Decrypt Configs
- Produce Clean C2 Address 
 

<p style="text-align: center;">
  <img src="Images/66.png" alt="Sample Image" style="max-width: 100%;"/>
  <br/>
  <ins>Output of the code after extracting the Configs</ins>
</p>

You can disassemble extracted shellcode using Capstone Framework in CS_ARCH_X86 arhcitecture and CS_MODE_32 but it doesn't included in this version of extractor. 

## C2 Communication

Rhadamanthys loader establishes communication with C2 server to download and execute final stage **The Stealer**.

Rhadamanthys resolves domain name into IP address by `getaddrinfo` to be `116.202.18.132`

<p style="text-align: center;">
  <img src="Images/44_c_addrinfo.png" alt="Sample Image" style="max-width: 100%;"/>
  <br/>
  <ins>Rhadamanthys resolves domain name</ins>
</p>

Rhadamanthys loader communicates using `WSASend` & `WSARecv`.

<p style="text-align: center;">
  <img src="Images/44_c_wssend.png" alt="Sample Image" style="max-width: 100%;"/>
  <br/>
  <ins>Communicate using WSASend</ins>
</p>

Once the loader has sent the HTTP request to download the main module, the command-and-control server replies with the stealer.

<p style="text-align: center;">
  <img src="Images/44_c_wsrcv.png" alt="Sample Image" style="max-width: 100%;"/>
  <br/>
  <ins>Communicate using WSARecv</ins>
</p>

Rhadamanthys loader controls socket mode using `WSAIoctl` using Obscure IOCTL code `0xC8000006` which is defined as **<ins>SIO_GET_EXTENSION_FUNCTION_POINTER</ins>** as used in same purpose in **<ins>Royal ransomware</ins>** 

<p style="text-align: center;">
  <img src="Images/44_c_wsrcv.png" alt="Sample Image" style="max-width: 100%;"/>
  <br/>
  <ins>WSAIoctl</ins>
</p>

### How Loader Execute Final Stage 

Rhadamanthys Loader receive data from C2 and create file with name `nsis_[uns%04x].dll` then write PE format, and set `rundll32.exe` and dll export `PrintUIEntry` to execute is using `CreateProcessW()`
 <p style="text-align: center;">
  <img src="Images/44_c_dowload.png" alt="Sample Image" style="max-width: 100%;"/>
  <br/>
  <ins>Download & Execute Rhadamanthys Stealer</ins>
</p>



# Conclusion

Rhadamanthys Infostealer, a Malware-as-a-Service (MaaS), represents a significant threat due to its unique multi-layered design, advanced capabilities, and evasion techniques.

The initial stage of Rhadamanthys is obfuscated by the Q3VM open-source packer, securing its encoded payload, which is encoded with a Base32 algorithm using a custom character set.

The middle stage resolves some virtual APIs and decompresses the loader stage, which is compressed using the LZSS algorithm. While this was defeated using a debugger, an automated extractor can now be used.

The loader stage employs various anti-analysis techniques, including API hashing, custom exception handling with API redirection, and other anti-analysis tricks. The loader decrypts RC4-encrypted configs, connects to the C2 server, and downloads and executes the actual stealer.

# IoCs
|No.|Description|Value|    
|----|-----|-------|     
|1|Initial file|dca16a0e7bdc4968f1988c2d38db133a0e742edf702c923b4f4a3c2f3bdaacf5| 
|2|1st Shellcode|5d539f24585cf85db7beabce4c0a94d9f780c8d8de72bb7872b4da071d1e656e| 
|3|2nd Shellcode|ee3fe7d514c1c8612015a0a9b6a4b504c2bedbd7050b401636f8c0eaef4ac0b3| 
|4|Rhadamanthys C&C Server|http://116.202.18.132/blob/q3k6tk.xi8o| 

# YARA Rule
```yara
rule rhadamanthys
{
    meta:
		  author = "Yahya Alsify"
      		  description = "Detects Rhadamanthya loader"
		  hash = "dca16a0e7bdc4968f1988c2d38db133a0e742edf702c923b4f4a3c2f3bdaacf5"
		  hash = "9917b5f66784e134129291999ae0d33dcd80930a0a70a4fbada1a3b70a53ba91"
		  hash = "3300206b9867c6d9515ad09191e7bf793ad1b42d688b2dbd73ce8d900477392e"
    strings:
		  $mz = {4D 5A} //PE File
	          $shellcode = "7ARQAAAAS"
		  $s1 = "GetQueuedCompletionStatus"
		  $s2 = "CreateCompatibleBitmap"
		  $s3 = "DispatchMessage"
		  $s4 = "IsBadCodePtr"
		  $s5 = "BitBlt"
		  $s6 = "CreateBitmap"
		  $s7 = "AlphaBlend"

    condition:
		  ($mz at 0) and $shellcode and 4 of ($s*)
}
```

# References

https://www.recordedfuture.com/research/rhadamanthys-stealer-adds-innovative-ai-feature-version           
https://www.zscaler.com/blogs/security-research/technical-analysis-rhadamanthys-obfuscation-techniques           
http://undocumented.ntinternals.net/index.html?page=UserMode%2FStructures%2FPEB_LDR_DATA.html        
https://gurucul.com/blog/royal-ransomware/       
https://github.com/corngood/mono/blob/master/mono/io-layer/sockets.h       
https://outpost24.com/blog/rhadamanthys-malware-analysis/#disassembling-standard-and-rhadamanthys-quake-vm-binaries       
https://github.com/ayoubfaouzi/al-khaser       
https://github.com/jnz/q3vm
