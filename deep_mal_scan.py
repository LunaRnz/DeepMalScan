import hashlib
import os
from virus_total_apis import PublicApi


API_KEY = "98ba7f64af11754831b5dfaac4481a8c6e61f9d00098781537d19501bff521a6"


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


def file_scanner(files, current_head_dir):
	for file in files:
		file_path = os.path.join(current_head_dir, file)
		if verify_hash(file_path) > 0:
			remove_file(file_path)


def print_files(files):
	print("\t|")
	for file in files:
		print("\t|_ "+file)


def list_dirs(current_head_dir):
	os.chdir(current_head_dir)
	print(os.getcwd())
	directories = [d for d in os.listdir() if os.path.isdir(os.path.join(current_head_dir, d))]
	files = [f for f in os.listdir() if os.path.isfile(os.path.join(current_head_dir, f))]
	print_files(files)
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
