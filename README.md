# python-memory-hooker
A memory hooker written in python. Able to read process's memory, usually to use as inputs to some sort of AI.
You can either supply a direct address to read/write from, or use a cheat engine style pointer.

example code:
```
GD = MemoryHooker("GeometryDash.exe")

p_xpos = [GD.base_address, 0x3222D0, 0x164, 0x124, 0xEC, 0x108, 0x67C] #cheat engine pointer
xpos = GD.readFloat(p_xpos)
print(xpos) #the player's current x position
```
