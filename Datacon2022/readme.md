#### 环境配置：

windows 10：需要先手动关闭病毒与威胁防护中的实时保护

python3：需要额外安装三个库

- pip install chardet  （chardet不是charset！！！）
- pip install pycryptodome
- pip install crypto

#### 运行说明：

- ##### Powershell反混淆-Level1：

  一键运行脚本：`./level01_run.bat`

  测试数据集目录：`data = "./First-Stage"`

  结果输出路径：`result = "./result1.txt"`

  提示：如果进程崩溃直接再次运行即可，会保存已执行结果继续运行

- ##### Powershell反混淆-Level2

  一键运行脚本：`./level02_run.bat`

  测试数据集目录：`data = "./Second-Stage"`

  结果输出路径：`esult = "./result2.txt"`

------

#### 文件说明：

- ##### 自动化批处理相关文件：

  - `main.py`                                                    自动化对level1的脚本进行批量解混淆
  - `pslv2.py`                                                  自动化对level2的脚本进行批量解混淆
  - `./First-Stage`                                        level1数据集样本目录
  - `./Second-Stage`                                      level2数据集样本目录
  - `./pdoutput`                                              用于临时存放powerdecode的解混淆结果
  - `Final-level01-result.txt`                 level1最终解混淆结果
  - `Final-level02-result.txt`                 level2最终解混淆结果

- ##### 辅助文件：

  - `level1_prev.json`                                  防止崩溃，利用json+dict保存之前运行的结果
  -  `solve.ps1`                                               调用invoke-deob中间命令写入文件
  - `callpowerdecode.ps1`                           调用powerdecode中间命令写入我呢见

- ##### 调用 Invoke-Deobfuscation：

  - `Utils.ps1`                                                获取脚本文件等一系列简单函数集合
  - `ResolveTokens.ps1 `                               解析脚本，完成token级别的反混淆
  - `RenameVariables.ps1`                           将随机化的变量名称规范化
  - `InvokeDeob.ps1`                                     对pipelineAst等节点进行invoke，获取执行结果。
  - `Beautifier.ps1`                                     去除白空格，规范代码缩进
  - `Invoke-DeObfuscation.psd1`               生成powershell反混淆模块，可以用import-module的方式安装
  - `validValuesCache.txt`                         本地保存的一些正则规则变量对应项

- ##### 调用 PowerDecode:

  - `./package`                                                调用powerdecode解混淆

- ##### 调用PowerShellProfiler:

  - `pslv2.py`                                                  调用PowerShellProfiler解混淆





