
srcdir = .

PROGS = basics c_variable cpp_variable var-cmd

MISCELLANEOUS = testcmds

all info install-info dvi install uninstall installcheck check:
	@echo "Nothing to be done for $@..."

clean mostlyclean:
	-rm -f *.ci *.o $(OBJS) $(PROGS) *~ core

distclean maintainer-clean realclean: clean
	-rm -f Makefile config.status config.log
