![IMAGE](genshin.png)

# Genshin-Bypass
An Anti-Cheat Bypass for Genshin Impact that allows you to inject ANY dlls into the protected game.

# Overview

The Genshin installs KernelMode Driver named `"mhyprot2"` to protect its process under a privileage of Windows Kernel.  
So there is nothing we can do from the user-mode usually, except abusing exploits.

In this project, I choose [libelevate](https://github.com/notscimmy/libelevate) which provides handle elavation for ANY processes, using [libcapcom](https://github.com/notscimmy/libcapcom).  
Also the libcapcom provides code execution on kernel which makes us advantage in this fight, against kernel mode drivers.

Because mhyprot2 just hides its process handle by `ObRegisterCallbacks`.  
After the work finishes, driver will be unloaded, therefore there are no real-time protections as of now.

# Analysis

### The `"mhyprot2"` registers:

- **`PsSetCreateProcessNotifyRoutineEx`**
- **`PsSetLoadImageNotifyRoutine`**
- **`PsSetCreateThreadNotifyRoutine`**

### The `"mhyprot2"` does:

- Observing for `csrss.exe` injection.
- Remove process/thread object from all handle tables.
- Write logs into `c:\windows\kmlog.log`

We can confirm that the driver hides handle by `ObRegisterCallbacks` below:

![IMAGE](analysis01.png)
