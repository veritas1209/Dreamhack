#!/bin/bash
cd /host/realdump
echo "--- byte0 센서: 01(correct) vs 02 vs ff ---"
B0="0x1016940 0x1019820 0x101c700 0x101d9c0 0x101ec80 0x101ff40 0x1021200 0x10224c0 0x1022e20"
for IN in 0101010101010101 0201010101010101 ff01010101010101; do
  echo -n "$IN"; for A in $B0; do r=$(/host/countread ./bin_0 $IN bin_0 $A|sed -E "s/.*reads=([0-9]+).*/\1/"); echo -n " $r"; done; echo
done
echo "B0_IDX=[3000, 3500, 4000, 4200, 4400, 4600, 4800, 5000, 5100]"
echo "--- byte6 센서: 6correct vs 7correct ---"
B6="0x1046a00 0x1048620 0x104a240 0x104be60 0x104da80 0x104f6a0 0x1050960 0x104b500 0x104d120 0x104ed40"
for IN in 018d93fe70f10101 018d93fe70f1ff01; do
  echo -n "$IN"; for A in $B6; do r=$(/host/countread ./bin_0 $IN bin_0 $A|sed -E "s/.*reads=([0-9]+).*/\1/"); echo -n " $r"; done; echo
done
echo "B6_IDX=[11200, 11500, 11800, 12100, 12400, 12700, 12900, 12000, 12300, 12600]"
