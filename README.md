# WHPEmulationKiller
Built for LLVM 19.1 - Windows x64 <br> <br>

We use 3 different methods to break EPT hooks placed in our code. The issue with most EPT hook detections is they need JIT code of sorts, which makes them useless.<br>
This is one of the VERY VERY few ways you can actually use usermode EPT hook detections properly, as your natural physical page is what gets hooked. This code will all be next to your actual code, so it gets violated with your code. <br> 
This pass effectively detect [HyperDBG](https://github.com/HyperDbg/HyperDbg) and [DBVM](https://github.com/cheat-engine/cheat-engine/tree/master/dbvm) EPT hooks. I haven't tested with any others. <br>

## Method 1
[ERMSB](https://github.com/everdox/ermsb-meme) We use a custom version of Everdox's REP MOVSB/STOSB detection, with a twist, we detect the shadow DR miss. The original method has been known and used in the wild by certain anti cheats for a while. <br>
Instead of just checking DR misalignment; which doesn't happen in HyperDBG as it uses shadow DRs. Therefore the DR never gets set at all. 
"MOV DR. The MOV DR instruction causes a VM exit if the “MOV-DR exiting” VM-execution control is 1. Such
VM exits represent an exception to the principles identified in Section 28.1.1 in that they take priority over the
following: general-protection exceptions based on privilege level; and invalid-opcode exceptions that occur
because CR4.DE=1 and the instruction specified access to DR4 or DR5." - [Vol. 3C 28-3](https://www.intel.com/content/www/us/en/content-details/922489/intel-64-and-ia-32-architectures-software-developer-s-manual-volume-3c-system-programming-guide-part-3.html)

## Method 2
Now this one more recently became public. Its LODSD RET, A method I have had sitting around from Theia for a while now. Since we are at LLVM time, we emit the LODSD gadget in the actual page. <br>
So this will not work if you are in RWX. <br>
The same attack can also be performed with STOSB RET. <br>
This is basically nearly impossible to hit, even from LLVM where we can force load the gadget onto our page, its such a primitive and poor technique that it is much less effective than ERMSB, I only got it to hit once on HyperDBG.<br>
You can read about it here: <br>
[K0mkc's blog](https://k0mkc.hatenablog.com/entry/2026/08/25/062815)
Its quite a poor technique though. In its entire 4 years of deployment in one of the biggest anti tamper tools, I am yet to find anyone moderately inconvenienced by it.<br>

## Method 3
[HyperDOS](https://github.com/IntelSDM/HyperDBGDOS) Simply inlines an _mm_pause loop at the start of your function. It pauses a legit machine for a milisecond, but pauses a HyperDBG EPT hooked page for hours. <br>
It will not hit the detection system, it just causes insanely slow EPT execution.


## Annotations
```c
__attribute__((annotate("EPTDetect")))
``` 
* Applies the 2 detection methods to your function
```c
__attribute__((annotate("EPTDetectionResponse")))
``` 
* Tells the LLVM pass which function you want to handle the detection, this will get called on EPT hook detection
```c
__attribute__((annotate("EPTDetectionResponse")))
__declspec(noinline)
void EPTDetection(void) {
    MessageBoxA(0, "Detected", "Detected", 0);
}
```
```c
__attribute__((annotate("HyperDOS-n")))
```
* n Here is the amount of millions of _mm_pause executions you want. This will hault execution, the higher n the longer your user might have to wait, but the longer the DOS on HyperDBG goes on for.
```c
__attribute__((annotate("HyperDOS-10")))
```
* HyperDOS-10 is 500 miliseconds on a legitimate machine, 20 hours on a HyperDBG EPT hook. 



## How To Build
* Download [LLVM 19.1](https://github.com/llvm/llvm-project/releases/tag/llvmorg-19.1.0)
* Download [VCPKG](https://github.com/microsoft/vcpkg)
* VCPKG install asmjit
* Open build.bat in a text editor.
* Find the LLVM 19.1 references in the command line, Change them to your file path.
* Find the VCPKG references in the command line, Change them to your file path.
* Run the build script
* Build your application with the ``` -load-pass-plugin ``` Param to the FunctionPass.dll
