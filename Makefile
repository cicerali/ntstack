SUBDIRS := src

all:
	$(MAKE) -C $(SUBDIRS)	

clean:
	$(MAKE) -C $(SUBDIRS) clean 
