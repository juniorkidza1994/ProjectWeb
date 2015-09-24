#!/usr/bin/env node

var java = require('java');

java.classpath.push("./");

//var MyClass = java.import('MyClass');

var instance = java.newInstanceSync("MyClass");

console.log(java.callMethodSync(instance, "getNum"));



