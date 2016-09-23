#!/usr/bin/env python

hash_script="/sbin/tpm-luks-gen-tgrub2-pcr-values"
import sys

if len(sys.argv) > 1:
	hash_script=sys.argv[1]

if __name__ == "__main__":
	
	with open("/etc/crypttab") as f:
		for l in f:
			tl = l.strip()
			if len(tl) > 0 and not tl.startswith("#"):
				fields = tl.split()
				
				ask_boot = True
				
				if len(fields) >= 4:
					opts = set(fields[3].lower().split(','))
					if "noauto" in opts or "nofail" in opts:
						ask_boot  = False
				
				if len(fields) >= 3:
					passwd=fields[2].lower()
					if not (passwd == "-" or passwd == "none"):
						ask_boot = False
				
					
				# something probably went horribly wrong if <2 fields, 
				# or if we wouldn't ask for a passwd on boot, we don't
				# want to use tpm-luks.  Otherwise, let's set up the string 
				if len(fields) >= 2 and ask_boot:
					name=fields[0]
					dev_id=fields[1]
					
					print "%s:%s:%s" % (dev_id, ".key." + name, hash_script)
			
			# end parsing line
		# end parsing crypttab
	# end open crypttab		

