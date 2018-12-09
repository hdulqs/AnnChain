### Delos 部署手册

#### 1 环境变量

> TM_ROOT

	作用：配置以及数据的存放位置
	默认值：$HOME/ann_runtime


#### 2 初始化

	命令： ./ann init
	作用： 在 TM_ROOT 目录中生成配置3个配置文件 config.toml、genesis.json、priv_validator.json

#### 3 配置节点

##### 3.1 参考信息

参数名称|参数位置|参数取值|备注
-------|------|-------|---
节点公钥|priv_validator.json|pub_key字段|初始化时自动生成，不需要修改
节点私钥| priv_validator.json|priv_key字段|初始化时自动生成，不需要修改

##### 3.2 配置参数

配置文件|参数|参数含义|如何修改|备注
-------|---|-------|------|---
config.toml|node_laddr|节点互联端口|IP可默认，端口所有节点保持一致|确认端口未占用，若多网卡需指定IP
config.toml|rpc_laddr|节点RPC端口|IP可默认，端口所有节点保持一致|确认端口未占用，若多网卡需指定IP
config.toml|seeds|种子节点|节点1IP:互联端口,节点2IP:互联端口,...|把所有节点拼接起来，配置到各节点上
config.toml|signbyCA|节点签名|填写对当前节点的签名|签名方法见下方签名指南
genesis.json|chain_id|链名称|预先设定|所有节点保持一致
genesis.json|init_accounts|初始发行账户列表|按需求填写数组|所有节点保持一致
genesis.json|validators|授权节点列表|数组填写所有节点，每个成员仅需修改pub_key一项|所有节点保持一致

	签名指南 假设现在要计算D节点的签名，也称为对D节点进行签名
	1、取任意一个节点的 “节点私钥”，作为 secKey
	2、取D节点的 “节点公钥”，作为 pubKey
	3、执行命令 ./ann sign --sec secKey --pub pubKey, 输出结果中冒号后边的字符串就是D节点的签名

#### 4 启动节点
	
	命令：./ann node
	作用：启动当前节点
	
	若启动成功，会输入类似以下内容：
	node (annchain-xxx) is running on 192.168.24.39:46656 ......
	
	区块链运行正常时，运行日志(见5.1)会有持续的信息输出。
	
#### 5 维护

##### 5.1 节点日志

	启动节点时所在的目录中，会生成 angine-[chainid] 的目录，目录中存放了日志以及错误信息：
	运行日志：output.log
	错误信息：err.output.log

##### 5.2 配置文件备份
	
	建议配置好节点之后，在启动节点之前，将三个配置文件备份一下，以便后期清理数据重启节点后，
	可以直接使用，不再需要进行 步骤2初始化 以及 步骤3配置节点。

#### 6 关闭与重启

	依次关闭所有节点，即可停止区块链网络
	重启与启动步骤一致
<br>

----

### Delos API 部署手册

### 配置

	在执行 ann-api 的目录下，创建config.json配置文件，内容如下：
	
	{
	  "ListenAddress": ":8889",
	  "BackendCallAddress": "tcp://0.0.0.0:46657",
	  "Public":false,
	  "GasLimit": 10000000,
	  "Debug":true,
	  "TiConnEndpoint":"http://11382-zis-other-ti-capsule-anlinkapiserver.test.za-tech.net",
	  "TiConnKey":"ZWViMTYyNWJlMTNmNDg5NDg2MTA1Mzhl",
	  "TiConnSecret":"MjJkZWMzMDUyMjM5NDc3YTkxYzZlNjkxMjA5NGQ2YTQ4Mzc3YzlmMmQ1ZDc0MDdj"
	}
	
	配置项：
	ListenAddress ：服务端口
	BackendCallAddress：任一节点的RPC地址
	TiConnEndpoint、TiConnKey、TiConnSecret：太空舱的配置信息
	
#### 启动
	在执行 ann-api 的目录下，创建 logs目录
	执行 ./ann-api
	
