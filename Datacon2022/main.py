import os
import subprocess
import re
import time
import json
import chardet


"""
编码相关：
- check_charset(file_path)：识别文件编码，用于读取文件进行编码转换
- try_decode(ori_bytes)：用多种编码解码    
"""


# 识别文件编码，用于读取文件进行编码转换
def check_charset(file_path):
    with open(file_path, "rb") as f:
        data = f.read(4)
        charset = chardet.detect(data)['encoding']
    return charset


# 对bytes decode时，采用utf-8、gbk等多种方式try_decode，实在无法decode时，赋值为无用的"wrong_ans"
def try_decode(ori_bytes):
    try:
        ret = ori_bytes.decode('GB2312')
        return ret
    except UnicodeDecodeError as err:
        print(err)
    try:
        ret = ori_bytes.decode('utf-8')
        return ret
    except UnicodeDecodeError as err:
        print(err)
    try:
        ret = ori_bytes.decode('ascii')
        return ret
    except UnicodeDecodeError as err:
        print(err)
    try:
        ret = ori_bytes.decode('GBK')
        return ret
    except UnicodeDecodeError as err:
        print(err)
    try:
        ret = ori_bytes.decode('Big5')
        return ret
    except UnicodeDecodeError as err:
        print(err)
    return "wrong_ans"


"""
解混淆主函数：
- solve(ps_path, result_path, script_path, data_path, prev_result_path, test_num, newly_solved_script_path,
          unsolved_script_path)
  相关参数声明见main
"""


def solve(ps_path, result_path, script_path, data_path, prev_result_path, test_num, prev_unsolved_result, time_path):
    # 打开相关文件
    file_output = open(result_path, 'a+')   # 保存result
    # 调用invoke-deobfuscation的相关命令
    cmd1 = "Import-Module .\\Invoke-DeObfuscation.psd1"
    cmd2 = "DeObfuscatedMain -ScriptPath0 "
    # 用于正则匹配提取ip
    pattern = re.compile(
        r"ip:((2((5[0-5])|([0-4]\d)))|([0-1]?\d{1,2}))(\.((2((5[0-5])|([0-4]\d)))|([0-1]?\d{1,2}))){3}")
    # 变量初始化
    cnt_script = 0          # 计数：目前进行到第几个脚本的解混淆
    cnt_ip = 0              # 计数：发现的真实ip数量
    cnt_newly_solved = 0    # 计数：新解决脚本数量
    cnt_unsolved = 0        # 计数：未解决脚本数量;
    cnt_old_solved = 0      # 计数：当前遇到了多少之前解过的ip;
    cnt_powerdecode = 0     # 计数：powerdecode求解的ip数量;
    cnt_PDandID = 0         # 计数：先powerdecode，再invoke-deobfuscation，得到的ip数量
    flag_line1 = True       # 便于写入文件，判断是否是第一行，不是需要添加'\n'

    """
    增量运行调用json字典文件存储之前运行的结果
    """
    # 创建字典文件,以保存已处理的结果
    if not os.path.exists(prev_result_path):
        print("No previous json file. creating %s " % prev_result_path)
        fp_json = open(prev_result_path, "w+", encoding="utf-8")
        fp_json.close()
    # 读取字典文件
    fp_json = open(prev_result_path, "r", encoding="utf-8")
    file = fp_json.read()
    if len(file) > 0:
        old_dict = json.loads(file)  # read后文件指针偏移到最后了，加载file中的信息到old_dict
        print("Previously solved result:")
        print(old_dict)
        print("--------")
    else:
        print("No previous results. creating dict in  %s " % (prev_result_path))
        old_dict = {}  # 创建字典 old_dict
    fp_json.close()
    # 打印之前的结果
    prev_len_dict = len(old_dict)
    print("previous solved ip nums :%d" % prev_len_dict)

    # 创建字典文件,以保存未成功求解的结果
    if not os.path.exists(prev_unsolved_result):
        print("No previous unsolved json file. creating %s " % prev_unsolved_result)
        fp_unsolve_json = open(prev_unsolved_result, "w+", encoding="utf-8")
        fp_unsolve_json.close()
    # 读取字典文件
    fp_unsolve_json = open(prev_unsolved_result, "r", encoding="utf-8")
    file2 = fp_unsolve_json.read()
    if len(file2) > 0:
        unsolve_old_dict = json.loads(file2)
        print("Previously unsolved result:")
        print(unsolve_old_dict)
        print("--------")
    else:
        print("No previous unsolved results. creating dict in  %s " % (prev_unsolved_result))
        unsolve_old_dict = {}  # 创建字典 unsolve_old_dict
    fp_unsolve_json.close()
    # 打印之前的结果
    prev_unsolve_len_dict = len(unsolve_old_dict)
    print("previous unsolved nums :%d" % prev_unsolve_len_dict)

    """
    遍历测试数据集文件目录，进行解混淆并提取flag，具体步骤为：
    1. Stage1: 调用powershellprofiler解混淆，正则匹配提取ip
    2. Stage2: 调用Invoke-Deobfuscation解混淆，正则匹配提取ip
    3. Stage3: Invoke-Deobfuscation没有提取成功的：调用PowerDecode解混淆，正则匹配提取ip
    4. Stage4: PowerDecode没有提取成功的：基于PowerDecode的解混淆结果再次调用Invoke-Deobfuscation解混淆，正则匹配提取ip
    5. 输出所有的flag提取结果
    """
    for root, ds, files in os.walk(data_path):
        for name in files:
            cnt_script = cnt_script + 1
            if cnt_script > test_num:
                break
            print("solving number:%d ,script name:%s \n" % (cnt_script, name))

            fp_time = open(time_path, 'a', encoding="utf-8")
            fp_time.write(name + " start " + time.strftime("%Y%m%d-%H%M%S") + '\n')
            fp_time.close()

            # 已经测试的直接读取json文件结果
            if name in old_dict:
                cnt_old_solved = cnt_old_solved + 1
                print("The %d previously solved, name:%s ans: %s" % (cnt_old_solved, name, old_dict[name]))
                cnt_ip = cnt_ip + 1
                print("currently solved ip nums:%d" % cnt_ip)
                print("----skip----")
                # if flag_line1:
                #     flag_line1 = False
                # else:
                #     file_output.write('\n')
                # file_output.write(name + ", " + old_dict[name])  # result是w+模式打开的，需要写一遍
                continue
            # 若之前标记为无法求解，跳过
            if name in unsolve_old_dict:
                cnt_unsolved = cnt_unsolved + 1
                print("previously unsolved: %s" % name)
                print("currently unsolved ip nums:%d" % cnt_unsolved)
                print("currently can't solve")
                print("----skip----")
                continue

            # 在脚本求解前，将脚本预先标记为无法求解;
            # 这样可以使得，当解某个脚本过程中导致崩溃、重启等结果时，下次可以跳过该脚本;
            # 在求解完成后，若可以求解，再删除该unsolved标记
            unsolve_old_dict.update({name: "unsolved"})
            fp_unsolve_json = open(prev_unsolved_result, "w+", encoding="utf-8")
            json.dump(unsolve_old_dict, fp_unsolve_json)  # 目前采取更新一次写一次的策略；文件io比较多，但是可以及时记录，防止崩溃时丢失数据
            fp_unsolve_json.close()

            # Stage1: powershellprofiler
            print("---stage 1: powershellprofiler---")
            try:
                info = subprocess.run("python pslv2.py -f " + data_path + name + " -d", stdout=subprocess.PIPE,
                                      stderr=subprocess.STDOUT, timeout=5)
            except subprocess.TimeoutExpired:
                print("Stage1: meet TimeoutExpired problem")

            re_result = re.search(pattern, str(info))
            tmp_ip = "-"
            if re_result is not None:
                cnt_ip = cnt_ip + 1
                tmp_ip = re_result[0]
                print("Stage1: currently solved ip nums:%d" % cnt_ip)
                print(tmp_ip)
            # 输出正确求解的ip
            if tmp_ip != "-":
                if flag_line1:
                    flag_line1 = False
                else:
                    file_output.write('\n')
                file_output.write(name + ", " + tmp_ip)

                # 统计这次解混淆新求解出ip的脚本
                cnt_newly_solved = cnt_newly_solved + 1
                print("Stage1: currently newly solved ip nums:%d" % cnt_newly_solved)
                # 更新预存结果字典
                old_dict.update({name: tmp_ip})
                fp_json = open(prev_result_path, "w+", encoding="utf-8")
                json.dump(old_dict, fp_json)
                fp_json.close()

            # Stage2:Invoke-Deobfuscation
            else:
                print("---stage 2: invoke-deobfuscation---")
                # 写入要执行的命令到 solve.ps1
                fp_script = open(script_path, 'w+')
                cmd = cmd2 + data_path + name
                fp_script.write(cmd1 + '\n')
                fp_script.write(cmd + '\n')
                fp_script.close()
                # 添加参数设置powershell执行策略
                args = [ps_path, "-ExecutionPolicy", "Bypass", script_path]
                ret = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

                # 设置timeout防止卡死
                try:
                    ret.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    print("Stage2: meet TimeoutExpired problem")
                    ret.kill()  # 此处kill了之后，ret.stdout还是有结果的；有可能ip在已经stdout输出的部分，即已解部分，而不在未解部分
                # 读取分析 Stage2 解混淆结果
                deob_result = ret.stdout.readlines()
                tmp_ip = "-"  # 设置初始ip（默认值）
                tmp_cnt = 0  # 行号
                for line in deob_result:
                    tmp_cnt = tmp_cnt + 1
                    str_line = try_decode(line)
                    # print("line %d:%s" % (tmp_cnt, str_line)) # 按行输出已解混淆部分
                    # 搜索ip字段
                    re_result = re.search(pattern, str_line)
                    if re_result is not None:
                        cnt_ip = cnt_ip + 1
                        tmp_ip = re_result[0]
                        print("Stage2: currently solved ip nums:%d" % cnt_ip)
                        print(tmp_ip)
                        # print(str_line)       # 原字符串
                        break
                # 输出正确求解的ip
                if tmp_ip != "-":
                    if flag_line1:
                        flag_line1 = False
                    else:
                        file_output.write('\n')
                    file_output.write(name + ", " + tmp_ip)

                    # 统计这次解混淆新求解出ip的脚本
                    cnt_newly_solved = cnt_newly_solved + 1
                    print("Stage2: currently newly solved ip nums:%d" % cnt_newly_solved)
                    # 更新预存结果字典
                    old_dict.update({name: tmp_ip})
                    fp_json = open(prev_result_path, "w+", encoding="utf-8")
                    json.dump(old_dict, fp_json)
                    fp_json.close()

                # Stage3: 调用PowerDecode
                else:
                    print("---stage 3: powerdecode---\n")
                    powerdecode_result = call_powerdecode(data_path + name, name)    # 返回powerdecode解混淆得到的txt
                    pd_file_result = open(powerdecode_result, 'r', encoding=check_charset(powerdecode_result),
                                          errors='ignore')
                    pd_lines = pd_file_result.readlines()

                    # 逆序遍历结果文件提取ip，考虑结果可能更靠近文件尾部
                    tmp_ip = "-"
                    for item in reversed(pd_lines):
                        re_result = re.search(pattern, item)
                        if re_result is not None:
                            cnt_ip = cnt_ip + 1
                            print("Stage3: currently solved ip nums:%d" % cnt_ip)
                            tmp_ip = re_result[0]
                            print(tmp_ip)
                            # print(item)  # 原字符串
                            break
                    if tmp_ip != "-":  # 只输出正确求解的ip
                        if flag_line1:
                            flag_line1 = False
                        else:
                            file_output.write('\n')
                        file_output.write(name + ", " + tmp_ip)

                        # 统计powerdecode求解出ip的脚本
                        cnt_newly_solved = cnt_newly_solved + 1
                        cnt_powerdecode = cnt_powerdecode + 1
                        print("Stage3: currently powerdecode solved ip nums:%d" % cnt_powerdecode)
                        print("currently newly solved ip nums:%d" % cnt_newly_solved)  # 新找到的ip数量
                        # 更新字典
                        old_dict.update({name: tmp_ip})
                        fp_json = open(prev_result_path, "w+", encoding="utf-8")
                        json.dump(old_dict, fp_json)
                        fp_json.close()

                    # Stage4: invoke deobfuscation on powerdecode
                    else:
                        print("---stage 4: invoke deobfuscation on powerdecode---\n")
                        # 写入要执行的命令到 solve.ps1
                        fp_script = open(script_path, 'w+')
                        cmd = cmd2 + powerdecode_result
                        fp_script.write(cmd1 + '\n')
                        fp_script.write(cmd + '\n')
                        fp_script.close()

                        # 添加参数设置powershell执行策略
                        args = [ps_path, "-ExecutionPolicy", "Bypass", script_path]
                        ret = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

                        # 设置timeout防止卡死
                        try:
                            ret.wait(timeout=15)
                        except subprocess.TimeoutExpired:
                            print("Stage4: meet TimeoutExpired problem")
                            ret.kill()  # 此处kill了之后，ret.stdout还是有结果的；有可能ip在已经stdout输出的部分，即已解部分，而不在未解部分

                        deob_result = ret.stdout.readlines()
                        tmp_ip = "-"  # 设置初始ip（默认值）
                        tmp_cnt = 0  # 行号
                        for line in deob_result:
                            tmp_cnt = tmp_cnt + 1
                            str_line = try_decode(line)
                            # print("line %d:%s" % (tmp_cnt, str_line)) # 按行输出已解混淆部分
                            # 搜索ip字段
                            re_result = re.search(pattern, str_line)
                            if re_result is not None:  # invoke-deobfuscation应该是把ip整到一行里了，暂不考虑ip断开在两行的情况
                                cnt_ip = cnt_ip + 1
                                tmp_ip = re_result[0]
                                print("Stage4: currently solved ip nums:%d" % cnt_ip)
                                print(tmp_ip)
                                # print(str_line)  # 原字符串
                                break
                        if tmp_ip != "-":  # 只输出正确求解的ip
                            if flag_line1:
                                flag_line1 = False
                            else:
                                file_output.write('\n')
                            file_output.write(name + ", " + tmp_ip)

                            # 统计这次解混淆新求解出ip的脚本
                            cnt_newly_solved = cnt_newly_solved + 1
                            cnt_PDandID = cnt_PDandID + 1
                            print("Stage4: currently PDandID solved ip nums:%d" % cnt_PDandID)
                            print("currently newly solved ip nums:%d" % cnt_newly_solved)  # 新找到的ip数量
                            # 更新字典
                            old_dict.update({name: tmp_ip})  # 更新字典
                            fp_json = open(prev_result_path, "w+", encoding="utf-8")
                            json.dump(old_dict, fp_json)  # 目前采取更新一次写一次的策略；文件io比较多，但是可以及时记录
                            fp_json.close()

            # 未在dict，说明未成功求解;
            if name not in old_dict:
                cnt_unsolved = cnt_unsolved + 1
                print("currently unsolved ip nums:%d" % cnt_unsolved)
            # 成功求解，将预先设置的unsolve标记去除
            else:
                unsolve_old_dict.pop(name, None)
                fp_unsolve_json = open(prev_unsolved_result, "w+", encoding="utf-8")
                json.dump(unsolve_old_dict, fp_unsolve_json)  # 目前采取更新一次写一次的策略；文件io比较多，但是可以及时记录，防止崩溃时丢失数据
                fp_unsolve_json.close()

            fp_time = open(time_path, 'a', encoding="utf-8")
            fp_time.write(name + " end " + time.strftime("%Y%m%d-%H%M%S") + '\n')
            fp_time.close()

    print("======== Summary ========")
    print("本次样本数量 %d" % (cnt_unsolved + cnt_ip))
    print("存储在json字典中，之前求解的ip数量:%d" % prev_len_dict)
    print("本次结果中，有 %d 个ip是从之前的数据集中直接读取的" % cnt_old_solved)
    print("本次结果中，新求解的ip数量:%d" % cnt_newly_solved)
    print("本次结果中，通过powerdecode求解的ip数量:%d" % cnt_powerdecode)
    print("本次结果中，通过powerdecode+invokedeob求解的ip数量:%d" % cnt_PDandID)
    print("本次结果中，仍未求解的ip数量:%d" % cnt_unsolved)

    file_output.close()


# 直接读取现有的结果，创建result.txt。提高效率。
def read_pre_result(prev_result_path, result_path):
    if not os.path.exists(prev_result_path):
        print("No previous json file. creating %s " % prev_result_path)
        fp_json = open(prev_result_path, "w+", encoding="utf-8")
        fp_json.close()
    # 读取字典文件
    fp_json = open(prev_result_path, "r", encoding="utf-8")
    file = fp_json.read()
    if len(file) <= 0:
        fp_json.close()
        print("No previous results. creating dict in  %s " % (prev_result_path))
        fp_json = open(prev_result_path, "w+", encoding="utf-8")
        old_dict = {}  # 创建字典 old_dict
        json.dump(old_dict, fp_json)
        fp_json.close()
    else:
        fp_json.close()

    fp_json = open(prev_result_path, "r", encoding="utf-8")
    old_dict = json.load(fp_json)
    print("prev solved ip nums: %d" % len(old_dict))
    file_output = open(result_path, 'w+')

    flag_line1 = True
    for name in old_dict:
        if flag_line1:
            flag_line1 = False
        else:
            file_output.write('\n')
        file_output.write(name + ", " + old_dict[name])  # result是w+模式打开的，需要写一遍


def call_powerdecode(target_path, name):
    ps_path = "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
    script_path = "./callpowerdecode.ps1"   # 调用powerdecode的脚本
    fp_script = open(script_path, 'w+')
    # 创建/pdoutput文件夹来保存powerdecode的输出
    pd_output_path = "./pdoutput/" + name + "-" + time.strftime("%Y%m%d-%H%M%S") + "-result.txt"

    cmd1 = "Import-Module ./package/PowerDecode.psd1"
    cmd4 = "PowerDecode " + target_path + " " + pd_output_path + " " + "'Disabled' 'Not set' '2'"
    print(cmd4)
    fp_script.write(cmd1 + '\n')
    fp_script.write(cmd4)
    fp_script.close()

    # 添加参数设置powershell执行策略 #Set-ExecutionPolicy Bypass;Set-ExecutionPolicy -ExecutionPolicy UNRESTRICTED;
    # Set-ExecutionPolicy RemoteSigned -Scope Process; 需要管理员权限运行pycharm
    args = [ps_path, "Set-ExecutionPolicy Bypass;Set-ExecutionPolicy -ExecutionPolicy UNRESTRICTED "
                     ";Set-ExecutionPolicy RemoteSigned -Scope Process;" + script_path ]  # Set-ExecutionPolicy bypass
    try:
        ret = subprocess.run(args, timeout=5)
        # run会等待powerdecode执行完；Popen不会，导致使用popen时，txt或者cmdline都么输出完;
        # 参数：stdout = subprocess.PIPE, stderr = subprocess.STDOUT
    except subprocess.TimeoutExpired:
        print("Stage2: meet TimeoutExpired problem")
        fp_pd_output = open(pd_output_path, 'w+', encoding="utf-8") # 创建一个空文件，为了逻辑的完整性;
        fp_pd_output.close()

    # 返回解混淆结果txt
    return pd_output_path


if __name__ == '__main__':
    start = time.time()
    print("--------------------------------------------python start!-----------------------------------------")

    """
    参数设置：
    - PowerShell路径；ps = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    - 输入数据路径：data = ".\\powershell_level01\\First-Stage\\"
    - flag提取结果路径：result = "./result/" + time.strftime("%Y%m%d-%H%M%S") + "-result.txt"
    """
    # PowerShell路径

    # 时间记录
    time_path = "./time.txt"
    fp_time = open(time_path, 'a+', encoding="utf-8") # 为了计算运行时间
    fp_time.write("solving start " + time.strftime("%Y%m%d-%H%M%S") + '\n')
    fp_time.write("========================")
    fp_time.close()

    ps = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    # 命令写入脚本路径
    script = "./solve.ps1"
    # 输入数据路径:
    data = ".\\First-Stage\\"   # .\\powershell_level01\\First-Stage\\
    # 利用json+dict，保存之前的数据结果
    prev_result = "./level1_prev.json"                      # "./221209-1800-prev.json"
    prev_unsolved_result = "./level1_unsolve_prev.json"     # "./221209-1800-unsolve_prev.json"
    # 测试运行的数量,便于调试
    test_num_total = 800
    # 数据结果路径
    # result = "./result/" + time.strftime("%Y%m%d-%H%M%S") + "-result.txt"  # 结果路径。添加了时间，便于对比
    result = "./result1.txt"
    read_pre_result(prev_result, result)

    # 主函数处理
    solve(ps, result, script, data, prev_result, test_num_total, prev_unsolved_result, time_path)

    # 运行结束
    read_pre_result(prev_result, result)
    end = time.time()
    print("------------------------------------Python end!---Running time:%d  s-------------------" % (end - start))
    fp_time = open(time_path, 'a', encoding="utf-8")
    fp_time.write("end " + time.strftime("%Y%m%d-%H%M%S") + '\n')
    fp_time.write("========================")
    fp_time.close()

