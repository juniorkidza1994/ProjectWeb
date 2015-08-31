#!/usr/bin/env node

var java = require('java');
var path = require('path');
var express = require('express');

var app = express();

var bodyParser = require('body-parser');

app.use(bodyParser.json()); // support json encoded bodies
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname,'..','webclient/public')));

java.classpath.push("../phrapp-0.30/bin/");
java.classpath.push("../phrapp-0.30/bin/commons-lang3-3.1.jar");
java.classpath.push("../phrapp-0.30/bin/paillier.jar");
java.classpath.push("../phrapp-0.30/bin/swingx-all-1.6.3.jar");

java.options.push('-Djava.library.path=../phrapp-0.30/bin/ -classpath *:../phrapp-0.30/bin/');

var instance = java.newInstanceSync("Login");

// Get from login class
var result_login;



app.get('/admin', function (req, res) {
  java.callMethodSync(instance, "login_main", "127.0.0.1","admin","bright23","Admin");
  console.log("TESTTT");
});

app.get('/user', function (req, res) {
  java.callMethodSync(instance, "login_main", "127.0.0.1","alice","kL8Um9d0","User");
  console.log("user");
});

app.post('/login', function (req, res) {

    var user = req.body.user;
    var pass = req.body.pass;
    var type = req.body.type;
    
  	console.log("USER : " + user);
  	console.log("PASS : " + pass);
  	console.log("TYPE : " + type);

    // Login and get account class (Admin, User)
    result_login = instance.loginSync("127.0.0.1",user,pass,type);

    console.log("CLASS : " + result_login);

    // Get table
    var result_table = result_login.getTableDataSync();

    console.log("TABLE : " + result_table);

    // Show value in table
    for (var i in result_table){
      console.log("I : " + result_table[i]);
    }


    res.send('LOGIN SUCCUESS !!');
});

app.get('/', function (req, res) {

    res.send('Hello World!');
});

  var server = app.listen(3000, function () {
  var host = "192.168.174.138";
  var port = server.address().port;

  console.log('Example app listening at http://%s:%s', host, port);
});


