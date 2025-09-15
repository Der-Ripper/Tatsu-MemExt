
with open('C:\\memory.dmp.', 'rb') as f:
    data = f.read(1000)
    print('Linux signatures found:', b'Linux version' in data)
    print('ELF signatures found:', b'ELF' in data)
