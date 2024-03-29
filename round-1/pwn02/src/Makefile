
COPTIONS = -std=c11 -D_GLIBCXX_ASSERTIONS -fasynchronous-unwind-tables -fexceptions -fno-stack-protector -z relro -z noexecstack -pie -fpie -fPIE
CWARNS = -Wall -Wextra
CFLAGS = $(CWARNS) $(COPTIONS)

.PHONY = clean


build/linecrosser: main.c
	@echo "Ocio, cambia il docker-compose togliendo la flag"
	gcc $(CFLAGS) -o $@ $<
	cp $@ ../checker/linecrosser
	zip -r ../attachments/linecrosser.zip $@ docker-compose.yml

clean:
	rm build/linecrosser
