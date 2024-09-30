import hashlib
import os
from virus_total_apis import PublicApi
import magic


API_KEY = "98ba7f64af11754831b5dfaac4481a8c6e61f9d00098781537d19501bff521a6"
sus_extensions = ['.EXE', '.PIF', '.APPLICATION', '.GADGET', '.MSI', '.MSP', '.COM', '.SCR', '.HTA', '.CPL', '.MSC', '.JAR', '.BAT', '.CMD', '.VB', '.VBS', '.VBE', '.JS', '.JSE', '.WS', '.WSF', '.WSC', '.WSH', '.PS1', '.PS1XML', '.PS2', '.PS2XML', '.PSC1', '.PSC2', '.MSH', '.MSH1', '.MSH2', '.MSHXML', '.MSH1XML', '.MSH2XML', '.SCF', '.LNK', '.INF', '.REG','.DOC', '.XLS', '.PPT', '.DOCM', '.DOTM', '.XLSM', '.XLTM', '.XLAM', '.PPTM', '.POTM', '.PPAM', '.PPSM', '.SLDM']
magic_number_dict = {
    '.jpg': b'\xFF\xD8\xFF',
    '.jpeg': b'\xFF\xD8\xFF',
    '.png': b'\x89PNG',
    '.gif': b'GIF8',
    '.pdf': b'%PDF',
    '.zip': b'PK\x03\x04',
    '.exe': b'MZ',
    '.dll': b'MZ',
    '.class': b'\xCA\xFE\xBA\xBE',
    '.jar': b'PK\x03\x04',
    '.bmp': b'BM',
    '.tiff': [b'II*\x00', b'MM\x00\x2A'],
    '.doc': b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1',
    '.docx': b'PK\x03\x04',
    '.xls': b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1',
    '.xlsx': b'PK\x03\x04',
    '.ppt': b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1',
    '.pptx': b'PK\x03\x04',
    '.tar': b'\x75\x73\x74\x61\x72',
    '.gz': b'\x1F\x8B',
    '.rar': b'\x52\x61\x72\x21\x1A\x07\x00'
}
magic_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.pdf', '.zip', '.exe', '.dll', '.class', '.jar', '.bmp', '.tiff', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.tar', '.gz', '.rar',]


def get_head():
	cwd_path = os.getcwd()
	return cwd_path.split('/')[1]


def compute_file_hash(file_path, algorithm):
	hash_func = hashlib.new(algorithm)
	with open(file_path, 'rb') as file:
		while chunk := file.read(8192):
			hash_func.update(chunk)
	return hash_func.hexdigest()


def compare_hash(hash_value):
	api = PublicApi(API_KEY)
	response = api.get_file_report(hash_value)
	if response["response_code"] == 200:
		results = response.get("results", {})
		if "positives" in results:
			if results["positives"] > 0:
				return 1
			else:
				return 0
		else:
			return 0
	else:
		return 0


def verify_hash(file_path):
	hash_value = compute_file_hash(file_path, "md5")
	return compare_hash(hash_value)


def remove_file(file_path):
	print(f"{file_path} may be malicious, do you want to delete it?(yes/no) ")
	user_option = input()
	if user_option == "yes":
		os.remove(file_path)


def print_file(file):
	print(f"\t|_{file}")


def get_magic_number(file_path):
	with open(file_path, 'rb') as f:
		return f.read(8)


def check_magic_number(file_path):
	ext = os.path.splitext(file_path)[1].lower()
	if ext in magic_extensions:
		magic_number = get_magic_number(file_path)
		expected_magic = magic_number_dict.get(ext)
		if magic_number.startswith(expected_magic):
			return 0
		else:
			return 1


def verify_extension(file_path)
	ext = os.path.splitext(file_path)[1]
	if ext in sus_extensions: 
		return verify_hash(file_path)
	return 0


def file_scanner(files, current_head_dir):
	for file in files:
		file_path = os.path.join(current_head_dir, file)
		print_file(file)
		if verify_extension(file_path) > 0:
			remove_file(file_path)
		else:
			check_magic_number(file_path)


def list_dirs(current_head_dir):
	os.chdir(current_head_dir)
	print(os.getcwd())
	directories = [d for d in os.listdir() if os.path.isdir(os.path.join(current_head_dir, d))]
	files = [f for f in os.listdir() if os.path.isfile(os.path.join(current_head_dir, f))]
	if len(files) > 0:
		file_scanner(files, current_head_dir)
	if len(directories) == 0:
		return
	else:
		for i in range(len(directories)):
			next_dir = os.path.join(current_head_dir, directories[i])
			list_dirs(next_dir)


def main():
	head_dir = "/" + get_head()
	list_dirs(head_dir)


if __name__ == '__main__':
	main()
