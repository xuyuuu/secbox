# secbox</br>   
=============================================================================
Project Introduction      
=============================================================================
This is a security project which needs to run in linux platform.  
It would cleanup resource with tcp socket.   
It would avoid running malicious process which in blacklist.   
It would avoid killing protected process which in protectlist.   
It would avoid accessing the directory which in blacklist.   

=============================================================================
Build and use    
=============================================================================
platform Introduction: must build in kernel 2.6.32-431(Centos-6.5).</br>     
1.Makefile
run 'make' commond to produce sec_box.ko.   
insmod the kernel module.</br>   
2.Makefile.control   
run 'make -f Makefile.control' commond to produce sec_box_control.    
run 'sec_box_control -h' commond for help.       
You can use 'sec_box_control ......' tools to communicate with kernel.   

3.Makefile.clean    
run 'make -f Makefile.clean' commond to produce sec_box_cleaner.    
run 'sec_box_cleaner -d[run in backgroud]' to scan tcp state and notify to kernel.   

4.clean shell
run './sec_box_netclean.sh -h' for help   
run 'flock -e sec_box_netclean.lck ./sec_box_netclean.sh ......' to produce file sec_box_netclean.file   
the program which run above step 3, it will notify dirty inode to kernel.   

Thanks for looking !       
