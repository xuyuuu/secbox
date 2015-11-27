# secbox  </br>   
</br>   
This is a simple module which show the process of LSM controlling</br>   
</br>   
===================================================================</br>   
</br>
1:	run Makefile to produce sec_box.ko</br>   
</br>   
2:	insmod sec_box.ko verified in kernel 2.6.32-431(Centos-6.5)</br>   
</br>   
3:	run sec_box_control to communicate with kernel module</br>   
</br>   
===================================================================</br>   
</br>   
</br>
There will be two list of file in /var/log!</br>   
</br>   
</br>   
DESCRIPTION:</br>   
</br>   
1. If the process be put in the protected list, it will avoid killing !</br>   
</br>   
2. If the process be put in the gray list, it will run in sandbox !</br>   
</br>   
3. If the process be put in the black list, it will avoid running !</br>   
</br>    
4. If eht access path or file be put in the protected list, it will avoid visiting !</br>   
</br>   
5. We can see list logfile in /var/log/sec_box_accesslist.log & /var/log/sec_box_blacklist.log</br>   
</br>   
</br>   
Thanks for looking !</br>   
</br>   
