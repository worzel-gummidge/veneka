import immlib

DESC = "hooks LoadLibrary and GetProcAddress to reveal dynamically loaded dlls and apis"

imm = immlib.Debugger()
addresses = []
return_addresses = []

def main(args):
    global addresses
    global return_addresses
    global imm
    api_dictionary = {}
    # set breakpoints and add breakpoint addresses and names to a dictionary for easy retrieval
    api_addr = (imm.setBreakpointOnName('LoadLibraryA'))
    addresses.append(api_addr)
    api_dictionary[api_addr] = 'LoadLibraryA'
    imm.log("breakpoint for LoadLibraryA set at %08x" % api_addr)
    api_addr = (imm.setBreakpointOnName('GetProcAddress'))
    addresses.append(api_addr)
    api_dictionary[api_addr] = 'GetProcAddress'
    imm.log("breakpoint for GetProcAddress set at %08x" % api_addr)

    imm.run()

    while True:
        top = False
        if imm.isStopped():
            c_addr = imm.getCurrentAddress() 
            imm.log("%s" % handler(c_addr, api_dictionary), gray=True)
            for addr in addresses:
                # have we stopped at a breakpoint or a return address? there are three(3) possibilities to why we have stopped: breakpoint, return address or the process has been terminated
                if addr == c_addr:
                    imm.run()
                    top = True
            if top == False:
                for addr in return_addresses:
                    if addr == c_addr:
                        imm.run()
        else:
            return "done"

def handler(current_address, dictionary):
    # if we are at a breakpoint select appropriate analysis function
    if current_address in dictionary:
        api_name = dictionary[current_address]
        registers = imm.getRegs()
        esp = registers['ESP']
        if 'LoadLibrary' in api_name:
            analysis = analyze_LoadLibrary(esp)
        elif 'GetProcAddress' in api_name:
            analysis = analyze_GetProcAddress(esp)
        else:
            return "api not supported"
        return analysis
    else:
        return "not a monitored address"

def analyze_GetProcAddress(stack_pointer):
    global return_addresses
    return_addr = imm.readLong(stack_pointer)
    hModule = imm.readLong(stack_pointer + 4)
    lpProcName = imm.readLong(stack_pointer + 8)
    return_addresses.append(return_addr)
    # set bp at return address so that we can look at the return address
    imm.setTemporaryBreakpoint(return_addr)
    imm.run()
    while True:
        if imm.isStopped():
            if return_addr == imm.getCurrentAddress():
                return_value = imm.getRegs()['EAX']
                lpProcName = imm.readString(lpProcName)
                if return_value == 0:
                    return "GetProcAddress: FAILED to retrieve the address of process %s" % lpProcName
                else:
                    return "GetProcAddress: SUCCESSFULLY retrieved the address of process %s" % lpProcName

def analyze_LoadLibrary(stack_pointer):
    global return_addresses
    return_addr = imm.readLong(stack_pointer)
    lpFileName = imm.readLong(stack_pointer + 4)
    return_addresses.append(return_addr)
    imm.setTemporaryBreakpoint(return_addr)
    imm.run()
    while True:
        if imm.isStopped():
            if return_addr == imm.getCurrentAddress():
                return_value = imm.getRegs()['EAX']
                if return_value == 0:
                    return "LoadLibrary: FAILED to load %s" % imm.readString(lpFileName)
                else:
                    return "LoadLibrary: SUCCESSFULLY loaded %s" % imm.readString(lpFileName)
