import hashlib
import os
from virus_total_apis import PublicApi
import magic
from magic_numbers import file_magic_number_dict, executable_magic_number_dict


API_KEY = "98ba7f64af11754831b5dfaac4481a8c6e61f9d00098781537d19501bff521a6"
sus_extensions = ['.EXE', '.PIF', '.APPLICATION', '.GADGET', '.MSI', '.MSP', '.COM', '.SCR', '.HTA', '.CPL', '.MSC', '.JAR', '.BAT', '.CMD', '.VB', '.VBS', '.VBE', '.JS', '.JSE', '.WS', '.WSF', '.WSC', '.WSH', '.PS1', '.PS1XML', '.PS2', '.PS2XML', '.PSC1', '.PSC2', '.MSH', '.MSH1', '.MSH2', '.MSHXML', '.MSH1XML', '.MSH2XML', '.SCF', '.LNK', '.INF', '.REG','.DOC', '.XLS', '.PPT', '.DOCM', '.DOTM', '.XLSM', '.XLTM', '.XLAM', '.PPTM', '.POTM', '.PPAM', '.PPSM', '.SLDM']
magic_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.pdf', '.zip', '.exe', '.dll', '.class', '.jar', '.bmp', '.tiff', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.tar', '.gz', '.rar',]


###############---------- FUNS ----------###############
def get_head():
	cwd_path = os.getcwd()
	return cwd_path.split('/')[1]


def remove_file(file_path, user_option):
	if user_option == "yes":
		os.remove(file_path)


def print_file(file):
	print(f"\t|_{file}")


###############---------- FILE HASH ----------###############
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


def verify_extension(file_path):
	ext = os.path.splitext(file_path)[1]
	if ext in sus_extensions:
		return verify_hash(file_path)
	 return 0


###############---------- MAGIC NUMBER ----------###############
def get_magic_number(file_path):
	with open(file_path, 'rb') as f:
		return f.read(8)


def ask_for_further_check():
	print(f"{file_path} seems suspicious. Do you want a further analysis")
	user_input = input()
	return user_input


def check_coincidence(magic_number, expected_magic):
	if isinstance(expexted_magic, list):
		if any(magic_number.startswith(magic) for magic in expected_magic):
			return 0
		else:
			return 1
	else:
		if magic_number.startswith(expected_magic):
			return 0
		else:
			return 1


def static_analysis(file_path):
	print("Static analysis")


def dinamic_analysis(file_path):
	print("Dinamic analysis")


def check_code():
	print("Checking file")


def check_magic_number(file_path):
	ext = os.path.splitext(file_path)[1].lower()
	if ext in magic_extensions:
		magic_number = get_magic_number(file_path)
		if ext in executable_magic_number_dict:
			expected_magic = executable_magic_number_dict.get(ext)
			if check_coincidence() == 0:
				return 0
			else:
				if ask_for_further_check() == "yes":
					if static_analysis(file_path) == 1:
						return 1
					else:
						return dinamic_analysis(file_path):
				return 0
		elif ext in file_magic_number_dict:
			expected_magic = file_magic_number_dict.get(ext)
			if check_coincidence() == 0:
				return 0
			else:
				return check_code()
	return 0


###############---------- MAIN ----------###############
def file_scanner(files, current_head_dir):
	for file in files:
		file_path = os.path.join(current_head_dir, file)
		print_file(file)
		if verify_extension(file_path) > 0:
			print(f"{file_path} found in virus db and may be malicious, do you want to delete it?(yes/no)")
			user_input = input()
			remove_file(file_path, user_input)
		else:
		if check_magic_number(file_path) > 0:
			remove_file(file_path, user_input)


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
