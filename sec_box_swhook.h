#ifndef __sec_box_swhook_h__
#define __sec_box_swhook_h__



struct sec_box_hook
{
	ulong	(* clear)(void);	
	void	(* recover)(ulong);
	int	(* sethook)(struct security_operations *security_point);
	int	(* resethook)(struct security_operations * security_point);
};
extern struct sec_box_hook sec_box_hook;


#endif
