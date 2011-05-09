SUBDIRS:=$(shell find . -maxdepth 1 -type d -name '[a-z]*')

subdirs: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@

clean:
	@for dir in $(SUBDIRS); do $(MAKE) -C $$dir $@; done

.PHONY: subdirs $(SUBDIRS)

