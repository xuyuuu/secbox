# secbox</br>   
This is a simple module which show the process of LSM controlling   
1:run Makefile to produce sec_box.ko   
2:insmod sec_box.ko verified in kernel 2.6.32-431(Centos-6.5)   
3:run sec_box_control to communicate with kernel module   
</br>
There will be two list of file in /var/log!        
DESCRIPTION:      
1. If the process be put in the protected list, it will avoid killing !      
2. If the process be put in the gray list, it will run in sandbox !       
3. If the process be put in the black list, it will avoid running !       
4. If eht access path or file be put in the protected list, it will avoid visiting !      
5. We can see list logfile in /var/log/sec_box_accesslist.log & /var/log/sec_box_blacklist.log      
</br>   
Thanks for looking !       
