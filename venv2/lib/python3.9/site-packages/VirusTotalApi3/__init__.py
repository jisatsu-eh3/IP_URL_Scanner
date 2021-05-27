#!/usr/bin/python3

from requests import Session
from VirusTotalApi3.utils import write_log, check_url

api_url = "https://www.virustotal.com/api/v3/"

class VirusTotal:
	def __init__(self, api_key):
		self.api_key = api_key

		self.datas = {
			"x-apikey": self.api_key
		}

		self.req = Session()
		self.req.headers = self.datas

	def files(self, file_name, url = None):
		if not url:
			url = f"{api_url}files"

		form = {
			"file": open(file_name, "rb")
		}

		json = self.req.post(url, files = form).json()
		return json

	def upload_url(self):
		url = f"{api_url}files/upload_url"
		json = self.req.get(url).json()
		return json

	def file_infos(self, hashs, log = None):
		url = f"{api_url}files/{hashs}"
		json = self.req.get(url).json()

		if not log:
			return json

		file_name = "%s.json" % hashs
		f_log = write_log(json, file_name)
		return f_log

	def re_analyse_file(self, hashs):
		url = f"{api_url}files/{hashs}/analyse"
		json = self.req.post(url).json()
		return json

	def download(self, ids):
		url = f"{api_url}files/{ids}/download"
		json = self.req.get(url).json()
		return json

	def urls(self, url_to_scan, log = None):
		url = f"{api_url}urls"

		form = {
			"url": url_to_scan
		}

		json = self.req.post(
			url, data = form
		).json()

		if not log:
			return json

		file_name = "%s.json" % url_to_scan
		f_log = write_log(json, file_name)
		return f_log

	def url_infos(self, ids, log = None):
		ids = check_url(ids)
		url = f"{api_url}urls/{ids}"
		json = self.req.get(url).json()

		if not log:
			return json

		file_name = "%s.json" % ids
		f_log = write_log(json, file_name)
		return f_log

	def url_analyse(self, ids):
		ids = check_url(ids)
		url = f"{api_url}urls/{ids}/analyse"
		json = self.req.post(url).json()
		return json

	def url_location(self, ids, log = None):
		ids = check_url(ids)
		url = f"{api_url}urls/{ids}/network_location"
		json = self.req.get(url).json()

		if not log:
			return json

		file_name = "%s.json" % ids
		f_log = write_log(json, file_name)
		return f_log

	def domain(self, domain, log = None):
		url = f"{api_url}domains/{domain}"
		json = self.req.get(url).json()

		if not log:
			return json

		file_name = "%s.json" % domain
		f_log = write_log(json, file_name)
		return f_log

	def ip_addresses(self, ip, log = None):
		url = f"{api_url}ip_addresses/{ip}"
		json = self.req.get(url).json()

		if not log:
			return json

		file_name = "%s.json" % ip
		f_log = write_log(json, file_name)
		return f_log

	def analyse(self, ids, log = None):
		url = f"{api_url}analyses/{ids}"
		json = self.req.get(url).json()

		if not log:
			return json

		file_name = "%s.json" % ids
		f_log = write_log(json, file_name)
		return f_log