#!/bin/sh

cd bin 
java -Djava.library.path=. -classpath *:. Login
#gksu "java -Djava.library.path=. -classpath *:. Login"

