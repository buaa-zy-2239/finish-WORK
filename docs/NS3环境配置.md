## NS3环境配置

系统：Ubuntu 22.04

+ 首先下载依赖组件

  ```
  sudo apt install -y g++ python3 cmake ninja-build git python3-dev pkg-config castxml
  ```

+ 下载cppyy库

  ```
  pip3 install --user cppyy
  ```

+ 源码下载与编译

  ```
  wget https://www.nsnam.org/release/ns-allinone-3.43.tar.bz2
  tar xjf ns-allinone-3.43.tar.bz2
  cd ns-allinone-3.43/ns-3.43
  ./ns3 configure --build-profile=debug --enable-examples --enable-tests --enable-python
  #观察是否输出有Python Bindings ON
  
  ./ns3 build #执行编译
  ./ns3 run first.py #python运行测试
  #输出如下
  At time +2s client sent 1024 bytes to 10.1.1.2 port 9
  At time +2.00369s server received 1024 bytes from 10.1.1.1 port 49153
  At time +2.00369s server sent 1024 bytes to 10.1.1.1 port 49153
  At time +2.00737s client received 1024 bytes from 10.1.1.2 port 9
  ```

  