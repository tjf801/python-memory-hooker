"""
TODO: add docstring
"""

from ctypes import windll, cast, sizeof, byref, POINTER, c_void_p, c_char_p, c_char, c_size_t, c_ulong
import struct
from typing import Union, List, Tuple
import win32process
import psutil #TODO: dont use psutil, how to get PID from name?


def get_pid_from_name(process_name:str) -> int:
	"""
	returns the process ID of a given running process.
	"""
	for process in psutil.process_iter():
		if process_name in process.name():
			return process.pid
	raise ProcessLookupError("process '" + process_name + "' not found.")

class MemoryHooker:
	"""
	A hooker to a given process. Allows for the reading and writing of the process's memory, either for custom cheats, or an AI in python.
	
	'process' can either be the process ID or the process name, e.g: 0x2078, 17056, or "GeometryDash.exe"
	"""
	
	def __init__(self, process: Union[int,str]):
		if isinstance(process, int):
			process_id = process
		elif isinstance(process, str):
			process_id = get_pid_from_name(process)
		else:
			raise TypeError('process ID was type ' + type(process))
		
		self.process_id = process_id
		self.OpenProcess = windll.kernel32.OpenProcess
		self.ReadProcessMemory = windll.kernel32.ReadProcessMemory
		self.WriteProcessMemory = windll.kernel32.WriteProcessMemory
		self.CloseHandle = windll.kernel32.CloseHandle
		
		PROCESS_ALL_ACCESS = 0x1F0FFF
		self.buffer = cast(c_char_p(b'.'*16), POINTER(c_char))
		self.process_handle = self.OpenProcess(PROCESS_ALL_ACCESS, False, self.process_id)
		self.base_address = self.__get_base_address()
		
		self.pointer_cache = {}
	
	def __del__(self):
		self.close()
	
	def __get_base_address(self)->int:
		modules = win32process.EnumProcessModules(self.process_handle)
		return modules[0]
	
	def get_pointer_address(self, pointer:Union[List[int], Tuple[int]], update_cache=False)->int:
		"""
		gets the address of a list of offsets, (in cheat engine notation)
		
		NOTE: this uses a cache to speed up the address time,  
		so until it is run with update_cache=True, it will continue pointing to the same address,  
		regardless weather or not the value is there.
		
		e.g:  
		GD = MemoryHooker("GeometryDash.exe")  
		pxpos = GD.get_pointer_address([GD.base_address, 0x3222D0, 0x164, 0x124, 0xEC, 0x108, 0x67C], update_cache=True)  
		"""
		
		if not update_cache and tuple(pointer) in self.pointer_cache: return self.pointer_cache[tuple(pointer)]
		
		address:int = pointer[0]
		if len(pointer) > 1: 
			address += pointer[1]
			for i in range(2, len(pointer)):
				ReadAddr = c_size_t(address)
				if not self.ReadProcessMemory(self.process_handle, cast(address, c_void_p), byref(ReadAddr), sizeof(c_size_t)//2, 0): raise MemoryError("error calculating pointer refrence")
				address = ReadAddr.value
				address += pointer[i]
		
		self.pointer_cache[tuple(pointer)] = address
		
		return address
	
	def get_error_message(self)->str:
		error_num = windll.kernel32.GetLastError()
		return "Error {num}".format(num=error_num)
	
	def close(self):
		self.CloseHandle(self.process_handle)
	
	
	def readFloat(self, address:Union[int,list,tuple], update_cache=False)->float:
		if isinstance(address, (list, tuple)): address = self.get_pointer_address(address, update_cache=update_cache)
		buffer_size = 4
		bytes_read = c_ulong(0)
		
		if self.ReadProcessMemory(self.process_handle, address, self.buffer, buffer_size, byref(bytes_read)):
			v = self.buffer[:buffer_size]
			return struct.unpack('f', v)[0]
		
		raise MemoryError('unable to read memory: ' + self.get_error_message())
	
	def readDouble(self, address:Union[int,list,tuple], update_cache=False)->float:
		if isinstance(address, list): address = self.get_pointer_address(address, update_cache=update_cache)
		buffer_size = 8
		bytes_read = c_ulong(0)
		
		if self.ReadProcessMemory(self.process_handle, address, self.buffer, buffer_size, byref(bytes_read)):
			v = self.buffer[:buffer_size]
			return struct.unpack('d', v)[0]
		
		raise MemoryError('unable to read memory: ' + self.get_error_message())
	
	def readInt(self, address:Union[int,list,tuple], update_cache=False)->int:
		if isinstance(address, list): address = self.get_pointer_address(address, update_cache=update_cache)
		buffer_size = 4
		bytes_read = c_ulong(0)
		
		if self.ReadProcessMemory(self.process_handle, address, self.buffer, buffer_size, byref(bytes_read)):
			v = self.buffer[:buffer_size]
			return struct.unpack('i', v)[0]
		
		raise MemoryError('unable to read memory: ' + self.get_error_message())
	
	def readLong(self, address:Union[int,list,tuple], update_cache=False)->int:
		if isinstance(address, list): address = self.get_pointer_address(address, update_cache=update_cache)
		buffer_size = 8
		bytes_read = c_ulong(0)
		
		if self.ReadProcessMemory(self.process_handle, address, self.buffer, buffer_size, byref(bytes_read)):
			v = self.buffer[:buffer_size]
			return struct.unpack('q', v)[0]
		
		raise MemoryError('unable to read memory: ' + self.get_error_message())
	
	def readChar(self, address:Union[int,list,tuple], update_cache=False)->bytes:
		if isinstance(address, list): address = self.get_pointer_address(address, update_cache=update_cache)
		buffer_size = 1
		bytes_read = c_ulong(0)
		
		if self.ReadProcessMemory(self.process_handle, address, self.buffer, buffer_size, byref(bytes_read)):
			v = self.buffer[:buffer_size]
			return struct.unpack('c', v)[0]
		
		raise MemoryError('unable to read memory: ' + self.get_error_message())
	
	def readBool(self, address:Union[int,list,tuple], update_cache=False)->bool:
		if isinstance(address, list): address = self.get_pointer_address(address, update_cache=update_cache)
		buffer_size = 1
		bytes_read = c_ulong(0)
		
		if self.ReadProcessMemory(self.process_handle, address, self.buffer, buffer_size, byref(bytes_read)):
			v = self.buffer[:buffer_size]
			return struct.unpack('?', v)[0]
		
		raise MemoryError('unable to read memory: ' + self.get_error_message())
	
	
	def writeFloat(self, address:Union[int,list,tuple], value:float, update_cache=False):
		if isinstance(address, list): address = self.get_pointer_address(address, update_cache=update_cache)
		buffer_size = 4
		bytes_written = c_ulong(0)
		data = c_char_p(struct.pack('f', value))
		
		if not self.WriteProcessMemory(self.process_handle, address, data, buffer_size, byref(bytes_written)):
			raise MemoryError("unable to write memory " + self.get_error_message())
	
	def writeDouble(self, address:Union[int,list,tuple], value:float, update_cache=False):
		if isinstance(address, list): address = self.get_pointer_address(address, update_cache=update_cache)
		buffer_size = 8
		bytes_written = c_ulong(0)
		data = c_char_p(struct.pack('d', value))
		
		if not self.WriteProcessMemory(self.process_handle, address, data, buffer_size, byref(bytes_written)):
			raise MemoryError("unable to write memory " + self.get_error_message())
	
	def writeInt(self, address:Union[int,list,tuple], value:int, update_cache=False):
		if isinstance(address, list): address = self.get_pointer_address(address, update_cache=update_cache)
		buffer_size = 4
		bytes_written = c_ulong(0)
		data = c_char_p(struct.pack('i', value))
		
		if not self.WriteProcessMemory(self.process_handle, address, data, buffer_size, byref(bytes_written)):
			raise MemoryError("unable to write memory " + self.get_error_message())
	
	def writeChar(self, address:Union[int,list,tuple], value:bytes, update_cache=False):
		if isinstance(address, list): address = self.get_pointer_address(address, update_cache=update_cache)
		buffer_size = 1
		bytes_written = c_ulong(0)
		data = c_char_p(struct.pack('c', value))
		
		if not self.WriteProcessMemory(self.process_handle, address, data, buffer_size, byref(bytes_written)):
			raise MemoryError("unable to write memory " + self.get_error_message())
	
	def writeBool(self, address:Union[int,list,tuple], value:bool, update_cache=False):
		if isinstance(address, list): address = self.get_pointer_address(address, update_cache=update_cache)
		buffer_size = 1
		bytes_written = c_ulong(0)
		data = c_char_p(struct.pack('?', value))
		
		if not self.WriteProcessMemory(self.process_handle, address, data, buffer_size, byref(bytes_written)):
			raise MemoryError("unable to write memory " + self.get_error_message())


if __name__ == '__main__':
	GD = MemoryHooker("GeometryDash.exe")
	
	xpos = (GD.base_address, 0x3222D0, 0x164, 0x124, 0xEC, 0x108, 0x67C)
	
	import time
	
	start = time.time()
	for _ in range(10000): GD.readFloat(xpos)
	end = time.time()
	print(end-start)
	
	start = time.time()
	for _ in range(10000): GD.readFloat(xpos, update_cache=True)
	end = time.time()
	print(end-start)