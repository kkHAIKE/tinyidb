# tinyidb
Some python scripts are used to export userdata from huge idb

## 前提
ida 自带一个功能 `File -> Produce file -> Dump database to IDC file`，可以把 idc 中除了 hexrays 的大部分数据导出成一个 idc 脚本，只要在新分析的工程中执行这个脚本就能导入之前的用户数据，但是这个文件还是非常大（1.3G 的 idb，生成 580M 的 idc，压缩后 40 M），当然，你也可以直接保存这个压缩后的 idc，以获得最大兼容

## dmpidc_diff.py
使用**前提**的方法，生成当前进度的 cur.idc，新分析一个文件，生成初始进度 ori.idc，使用 `python dmpidc_diff.py ori.idc cur.idc > dif.idc`，可生成最小的差异 idc

## hexrays_dmp.py
使用 `File -> Script file` 执行该脚本，可在 idb 同目录生成 _.dmp 文件用以导出 hexrays 用户数据。该文件内容可使用 pickle 查看

## hexrays_load.py
使用 `File -> Script file` 执行该脚本，可从 idb 同目录的 _.dmp 文件中导入 hexrays 用户数据

## link
hexrays 代码参考了 [IDArling](https://github.com/IDArlingTeam/IDArling)

## 支付宝捐助
![支付宝捐助](https://github.com/kkHAIKE/fake115/blob/master/qrcode.png)
