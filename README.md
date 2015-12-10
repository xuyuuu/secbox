# secbox</br>   
This is a simple module which show the process of LSM controlling   
1:run Makefile to produce sec_box.ko   
2:insmod sec_box.ko verified in kernel 2.6.32-431(Centos-6.5)   
3:run sec_box_control & sec_box_cleaner to communicate with kernel module   
</br>
There will be two list of file in /var/log!        
DESCRIPTION:      
1. We can release tcp fd source which is stay in CLOSE_WAIT.   
2. If the process be put in the protected list, it will avoid killing !      
3. If the process be put in the gray list, it will run in sandbox !       
4. If the process be put in the black list, it will avoid running !       
5. If the access path or file be put in the protected list, it will avoid visiting !      
6. We can see list logfile in /var/log/sec_box_accesslist.log & /var/log/sec_box_blacklist.log      
</br>   
Thanks for looking !       
