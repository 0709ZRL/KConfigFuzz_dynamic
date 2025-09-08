#!/bin/bash

cp target/release/healer ~/workdir
cp target/release/syz-bin/syz-* ~/workdir/bin
cp -r target/release/linux_amd64 ~/workdir/bin/
cp *.json ~/workdir
# 默认所有最新的HEALER版本都放在workdir里
# 调用命令：
# sudo ./healer -d bullseye.img --ssh-key bullseye.id_rsa -k bzImage_6.2_clang -j 2 -m 2048 -P syscallPair_final2.json -C codeblock_config.json -T config_tree.json -V vmlinux_6.2_clang -L /home/jiakai/linux -E