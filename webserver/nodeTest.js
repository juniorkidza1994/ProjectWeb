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

var m_instance = java.newInstanceSync("Login");

//var booleanClass = java.import('java.lang.boolean');

var boolean_true = true;
var boolean_false = false;

// Get from login class
var m_result_login;



app.get('/admin', function (req, res) {
  java.callMethodSync(instancm_instancee, "login_main", "127.0.0.1","admin","bright23","Admin");
  console.log("TESTTT");
});

app.get('/user', function (req, res) {
  java.callMethodSync(m_instance, "login_main", "127.0.0.1","alice","kL8Um9d0","User");
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
    m_result_login = m_instance.loginSync("127.0.0.1",user,pass,type);

    console.log("CLASS : " + m_result_login);

    

});

app.get('/userinfo', function (req, res) {

    // Get table
    var result_table = m_result_login.getTableDataSync();
    var authorityName = m_result_login.getAuthorityNameSync();
    var username = m_result_login.getUsernameSync();
    var email_address = m_result_login.getemailAddressSync();
    console.log("------------- USER INFO -------------------");
    console.log("Authority Name : " + authorityName);
    console.log("Username : " + username);
    console.log("Email Address : " + email_address);

    console.log("TABLE : " + result_table);
    console.log("Attribute Table : ");
    // Show value in table
    for (var i in result_table){
      console.log("I : " + result_table[i]);
    }
});

app.post('/changepwd', function (req, res) {

  console.log("----------- CHANGE PASSWORD -------------");

  var objChangePwd = m_result_login.getChangePasswdClassSync();   

  console.log("CLASS CHANGE PASSWORD : " + objChangePwd);

  var current_passwd = req.body.current_passwd;
  var new_passwd  = req.body.new_passwd;
  var confirm_new_passwd = req.body.confirm_new_passwd;
  var send_new_passwd_flag = Boolean(req.body.send_new_passwd_flag);

  console.log("CURRENT PASSWORD : " + current_passwd);
  console.log("NEW PASSWORD : " + new_passwd);
  console.log("CONFIRM NEW PASSWORD : " + confirm_new_passwd);
  console.log("SEND NEW PASSWD FLAG : " + send_new_passwd_flag);

  // Change Password
  objChangePwd.change_passwdSync(current_passwd, new_passwd, confirm_new_passwd, send_new_passwd_flag);

  // Update Password
  if(objChangePwd.getResulFlagSync()){
    console.log("UPDATE PASSWORD");
    m_result_login.updateNewPasswdSync(new_passwd);
  }
});

app.post('/change_email', function (req, res) {

  console.log("----------- CHANGE Email Address -------------");

  var objChangeEmail = m_result_login.getChangeEmailClassSync();   

  console.log("CLASS CHANGE EMAIL ADDRESS : " + objChangeEmail);

  var new_email_address  = req.body.new_email_address;
  var confirm_new_passwd = req.body.confirm_new_passwd;

  console.log("NEW EMAIL ADDDRESS : " + new_email_address);
  console.log("CONFIRM NEW PASSWORD : " + confirm_new_passwd);

  objChangeEmail.change_emailSync(new_email_address, confirm_new_passwd);

  if(objChangeEmail.get_resultSync()){
    console.log("UPDATE EMAIL");
    m_result_login.updateNewEmailSync(new_email_address);
  }
});

app.get('/', function (req, res) {

    res.send('Hello World!');
});

  var server = app.listen(3000, function () {
  var host = "192.168.174.138";
  var port = server.address().port;

  console.log('Example app listening at http://%s:%s', host, port);
});