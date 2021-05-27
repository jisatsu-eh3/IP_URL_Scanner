#!/usr/bin/python3

from json import dump
from base64 import b64encode
from hashlib import md5, sha1, sha256

hashes = [md5, sha1, sha256]

def write_log(data, file_name):
	f = open(file_name, "w")

	dump(
		data, f,
		indent = 8
	)

	f.close()
	return file_name

def get_hash_file(file_name, hashs):
	s_hash = None

	for a in hashes:
		if f"openssl_{hashs}" == a.__name__:
			s_hash = a
			break

	if not s_hash:
		return "Invalid hash"

	f = open(file_name, "rb")

	hashed = s_hash(
		f.read()
	).hexdigest()

	f.close()
	return hashed

def get_hash_url(url, hashs):
	url = url.encode()

	if hashs == "base64":
		hashed = b64encode(url).decode().strip("=")
	else:
		return "Invalid hash"

	return hashed

def check_url(ids):
	if ids[:2] == "u-":
		ids = ids.split("-")[1]

	return ids