# Magic numbers de archivos comunes
file_magic_number_dict = {
    '.jpg': b'\xFF\xD8\xFF',                           # JPEG graphic file
    '.jpeg': b'\xFF\xD8\xFF',                          # JPEG graphic file
    '.png': b'\x89PNG',                                # PNG graphic file
    '.gif': b'GIF8',                                   # GIF graphic file
    '.pdf': b'%PDF',                                   # PDF Document
    '.zip': b'PK\x03\x04',                             # PKZip
    '.bmp': b'BM',                                     # Bitmap graphic
    '.tiff': [b'II*\x00', b'MM\x00\x2A'],             # TIF graphic file
    '.doc': b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1',       # Word Document
    '.docx': b'PK\x03\x04',                            # DOCX (Office 2010)
    '.xls': b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1',       # Excel Document
    '.xlsx': b'PK\x03\x04',                            # XLSX (Office 2010)
    '.ppt': b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1',       # PowerPoint Document
    '.pptx': b'PK\x03\x04',                            # PPTX (Office 2010)
    '.tar': b'ustar',                                  # Tar file
    '.gz': b'\x1F\x8B',                                # GZip
    '.rar': b'\x52\x61\x72\x21\x1A\x07\x00',           # RAR file
    '.ai': b'%PDF',                                    # Adobe Illustrator
    '.psd': b'8BPS',                                   # Photoshop Graphics
    '.wmf': b'\xD7\xCD\xC6\x9A',                       # Windows Meta File
    '.mid': b'MThd',                                   # MIDI file
    '.ico': b'\x00\x00\x01\x00',                       # Icon file
    '.mp3': b'ID3',                                    # MP3 file with ID3 identity tag
    '.avi': b'RIFF',                                   # AVI video file
    '.swf': b'FWS',                                    # Flash Shockwave
    '.flv': b'FLV',                                    # Flash Video
    '.mp4': b'\x00\x00\x00\x18\x66\x74\x79\x70\x6D\x70\x34\x32',  # Mpeg 4 video file
    '.mov': b'moov',                                   # MOV video file
    '.wmv': b'\x30\x26\xB2\x75\x8E\x66\xCF',           # Windows Video file
    '.wma': b'\x30\x26\xB2\x75\x8E\x66\xCF',           # Windows Audio file
}

# Magic numbers de ejecutables
executable_magic_number_dict = {
    '.exe': b'MZ',                                     # Executable file
    '.dll': b'MZ',                                     # Dynamic Library
    '.class': b'\xCA\xFE\xBA\xBE',                     # Class File
    '.jar': b'PK\x03\x04',                             # Jar File
    '.msi': b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1',       # Microsoft Installer
    '.sys': b'MZ',                                     # SYS file
    '.com': b'MZ',                                     # COM file
    '.scr': b'MZ',                                     # SCR file
    '.bat': b'#!',                                     # BAT file (no magic number, but can use shebang)
    '.cmd': b'#!',                                     # CMD file (no magic number, but can use shebang)
    '.pif': b'MZ',                                     # PIF file
    '.hta': b'MZ',                                     # HTA file
    '.cpl': b'MZ',                                     # CPL file
    '.msc': b'MZ',                                     # MSC file
}

