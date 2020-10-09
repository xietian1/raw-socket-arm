./ue_call_sim -c -R -O ATT -I rmnet_data2 -A +15174810565 -V 5177757243

./tcpdump -i any -w 

ip xfrm state

./ue_call_sim -c -R -O ATT -I rmnet_data1 -A +15174810565 -V 5177757243


adb push ue_call_sim /data/local/att/

