#coding:utf-8
import os
import subprocess
import sys
import re
import time
import json


def multi_run(dirpath, prev_unsolved_result, result):
	result_dict = [] # 存储本次结果; 本脚本静态求解，可以一次性写入，无需考虑中途崩溃
	unsolve_old_dict = {} # 之前未求解的脚本
	# 读取字典文件
	if os.path.exists(prev_unsolved_result):
		fp_unsolve_json = open(prev_unsolved_result, "r", encoding="utf-8")
		file2 = fp_unsolve_json.read()
		if len(file2) > 0:
			unsolve_old_dict = json.loads(file2)

	# 遍历文件判断是否为没有求解的
	ps_list = os.listdir(dirpath)
	for i in range(len(ps_list)):
		psname = ps_list[i]

		# 判断是否在字典中 level1(in) level2(not in)
		if psname not in unsolve_old_dict:
			print("solving %s" % psname)
			filepath = dirpath + "/" + psname
			try:
				info = subprocess.run("python pslv2.py -f " + filepath + " -d", stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
				pattern = re.compile(
					r"ip:((2((5[0-5])|([0-4]\d)))|([0-1]?\d{1,2}))(\.((2((5[0-5])|([0-4]\d)))|([0-1]?\d{1,2}))){3}")
				re_result = re.search(pattern, str(info))
				if re_result is not None:
					tmp_ip = re_result[0]
					print(tmp_ip)
					result_dict.append(psname + ", " + tmp_ip)
			# 参数：stdout = subprocess.PIPE, stderr = subprocess.STDOUT
			except subprocess.TimeoutExpired:
				print("meet TimeoutExpired problem")
		else:
			print("0")

	f = open(result, "a+")
	for i in range(len(result_dict)):
		f.write(result_dict[i] + "\n")
	print("solve %d ip in %d powershell scripts" %(len(result_dict),len(ps_list)))


if __name__ == "__main__":
	# 输入数据路径:
	data = "./Second-Stage"  # .\\powershell_level01\\First-Stage\\   .\\First-Stage\\   ./Second-Stage
	# 之前未求解脚本
	prev_unsolved_result = "./level2_prev.json"
	# result路径
	result = "./result.txt"
	start = time.time()
	print("--------------------------------------------python start!-----------------------------------------")
	multi_run(data, prev_unsolved_result, result)
	end = time.time()
	print("------------------------------------Python end!---Running time:%d  s-------------------" % (end - start))
	

'''
level1，10stimeout:
solve 126 ip in 800 powershell scripts
------------------------------------Python end!---Running time:445  s-------------------

level2，30stimeout:
solve 60 ip in 200 powershell scripts
------------------------------------Python end!---Running time:155  s-------------------
'''