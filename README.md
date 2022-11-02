# Nutex

----

**NutEx** (nut extractor) is an unpacker for out-of-the-box usage of popular tools like:

* TheWover's [Donut](https://github.com/TheWover/donut)
* Hashezerade's [pe_to_shellcode](https://github.com/hasherezade/pe_to_shellcode)
* The original [sRDI implementation](https://github.com/monoxgas/sRDI) by Monoxgas

All of the tools listed above wrap PE or other files with a layer of shellcode that performs all
the loading necessary in order to run the code. Put simply, this allows executable files and scripts
to be utilized as simply as writing it to process memory (local or remote) and then triggering execution
via a thread (existing or otherwise). As a result, functionality like Metasploit's _migrate_ becomes
trivial to implement for other malware like [Sliver](https://github.com/BishopFox/sliver).

NutEx attempts to identify and extract the original payload.

## Building

```bash
go build -o build/nutextractor.exe .
```

---

## Usage

**Packer Identification**

Example:
```bash
nutex.exe tastetest C:\Users\user\Desktop\Tools\donut_v0.9.3\loaderARGSWENTRY.bin

[*] Input file: C:\Users\kozak\Desktop\Tools\donut_v0.9.3\loaderARGSWENTRY.bin
[*] Shellcode-Compiler Identified: Donut Loader
Donut Instance
[ Entropy Level : Random Names + Symmetric Encryption
[ Instance Type: Embedded
[ Module Type: Native DLL
[ Runs EP as Thread: true
[ Invoked Method: MAPIFreeBuffer
[ EP Parameters: wtfargs
[ Compression: LZNT1
```

**Payload Recovery**

```bash
nutex.exe extract --input C:\Users\user\Desktop\Tools\donut_v0.9.3\loaderARGSWENTRY.bin --output unpacked.bin

[*] Input File: C:\Users\user\Desktop\Tools\donut_v0.9.3\loaderARGSWENTRY.bin
[*] Shellcode-Compiler Identified: Donut Loader
[+] Extraction Successful! Output written to: unpacked.bin

```

---

## Learn More

To learn more about the internals of the various packers targeted, read the blog post [here](https://malware.tech)
