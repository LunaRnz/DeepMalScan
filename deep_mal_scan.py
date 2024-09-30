import hashlib
import os


def get_head():
	cwd_path = os.getcwd()
	return cwd_path.split('/')[1]


def search_malicious_file(files, path):
	for file in files:
		file_path = path + "/" + file
		file_extension = os.path.splitext(file_path)[1]
		if file_extension == ".exe":
			file_path = path + "/" + file
			print(file_path + " may contain malicious code, do you want to delete it?(yes/no) ")
			user_option = input()
			if user_option == "yes":
				 os.remove(file_path)


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
		search_malicious_file(files, current_head_dir)
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
