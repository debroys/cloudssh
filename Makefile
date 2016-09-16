VERSION  := 1.0
TGZ_FILE := cloudssh-v${VERSION}-linux.tgz
ZIP_FILE := cloudssh-v${VERSION}-win.zip
OBJS := cloudssh.pyc

%.pyc: %.py
	@python -m compileall $<
	@chmod +x $@

${TGZ_FILE}: ${OBJS} cloudssh README.md LICENSE
	@tar -czf ${TGZ_FILE} $^

${ZIP_FILE}: ${OBJS} cloudssh.bat README.md LICENSE
	@zip ${ZIP_FILE} $^

all: ${TGZ_FILE} ${ZIP_FILE}

clean:
	@rm -f *.pyc ${TGZ_FILE} ${ZIP_FILE}
