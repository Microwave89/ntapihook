# ntapihook
Attempt to Create a Simple and Light-weight Hook Engine Without Use of an LDE

STATUS/TODO: Finds a 3 KB code cave (RT, PAGE) and in the target process copies the dispatch code there. No hooking implemented yet.
How to properly get dispatch code size with the smallest code? And code cave scanning needs to be simplified to only search ntdll.dll.

When attempting to detour a function one normally overwrites part of its first instructions with an unconditional jump to a new function. As the overwritten bytes constitute part of the function the hook engine will them save beforehand. When the target process calls into the hooked function later on, it will eventually execute the saved bytes and then return control to the original function.
Since one must only save complete instructions, to not provoke crashing of the target process, usually a length disassembler engine (LDE) is used to exactly know the complete instruction length the jump is going to overwrite. Such an LDE might not only fail to disassemble the function's beginning in rare cases but it will also add a size overhead in the compiled code of the hook engine.
Retrieving the instruction length and thus dissassembling becomes even more difficult if there are relative instructions in the code the jump is going to overwrite. This holds particularly true when talking about 64-bits code, due to the minimum instruction length of 12 bytes of a generic x64 displacement (jump must be absolute for generic hooking).

If we could somehow make sure each interesting function starts with the same instruction length we would no longer need an LDE for saving the instruction bytes but simply hardcode the instruction length. This is in fact, what the Hot Patch mechanism of 32-bits Windows was about.
Luckily, we are able to emulate this mechanism when solely hooking NtXxx functions since we not only know the instruction length we are going to overwrite, but we can even perform all necessary operations of such an NtXxx call ourselves!
Moreover, it can be easily understood that almost each interesting function (except ones that access global data directly, --> "KUSER_SHARED_DATA"), be it either graphical or non-graphical, at some point ends up performing an NtXxx call.
