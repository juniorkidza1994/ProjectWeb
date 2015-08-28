#!/bin/sh

cd bin 
java -Djava.library.path=. -classpath *:. EmU_Login
#gksu "java -Djava.library.path=. -classpath *:. EmU_Login"


