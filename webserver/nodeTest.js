var java = require('java');
var path = require('path');
var express = require('express');
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var methodOverride = require('method-override');

var app = express();



var bodyParser = require('body-parser');

app.use(methodOverride());
app.use(require('cookie-parser')());
app.use(require('body-parser').urlencoded({ extended: true }));
app.use(require('express-session')({ secret: 'keyboard cat', resave: false, saveUninitialized: false }));
app.use(passport.initialize());
app.use(passport.session());
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

// result boolean from login class
var m_result_login;

// result calss from login class
var m_main_class;

var m_authority_name_list = null;

// Serialized and deserialized methods when got from session
passport.serializeUser(function(user, done) {
    done(null, user);
});

passport.deserializeUser(function(user, done) {
    done(null, user);
});

// route to test if the user is logged in or not
app.get('/loggedin', function(req, res) {
  res.send(req.isAuthenticated() ? req.user : '0');
});

app.post('/login', passport.authenticate('local'), function(req, res) {
  res.send(req.user);
});

passport.use(new LocalStrategy(
  function(username, password, done) {
    console.log("USERNAME : " + username);
    console.log("PASSWORD : " + password);
    console.log("DONE : " + done);
    
    var bool = m_instance.loginSync("127.0.0.1",username,password,"User");

    console.log(bool);

    if (bool){ // stupid example
      m_main_class = m_instance.getMainClassSync();
      return done(null, {name: "admin"});
    }

    return done(null, false, { message: 'Incorrect username.' });
  }
));

app.get('/admin', function (req, res) {
  java.callMethodSync(instancm_instancee, "login_main", "127.0.0.1","admin","bright23","Admin");
  console.log("TESTTT");
});

app.get('/user', function (req, res) {
  java.callMethodSync(m_instance, "login_main", "127.0.0.1","alice","1jQClb1m","User");
  console.log("user");
});

app.post('/logins', function (req, res) {

    var username = req.body.username;
    var password = req.body.password;
    var type = req.body.type;
    
    console.log("USER : " + username);
    console.log("PASS : " + password);
    console.log("TYPE : " + type);

    // Login and get account class (Admin, User)
    m_result_login = m_instance.loginSync("127.0.0.1",username,password,type);

    if(m_result_login){
      console.log("NODE JS : LOGIN SUCCESS");
      m_main_class = m_instance.getMainClassSync();
      console.log("CLASS : " + m_main_class);
    }
    

});

var userinfo = {};

app.get('/userinfo', function (req, res) {

    if(Object.keys(userinfo).length == 0)
    {
      // Get table
      var attribute_list = m_main_class.getTableAttributeSync();
      var authorityName = m_main_class.getAuthorityNameSync();
      var username = m_main_class.getUsernameSync();
      var email_address = m_main_class.getemailAddressSync();
      console.log("------------- USER INFO -------------------");
      console.log("Authority Name : " + authorityName);
      console.log("Username : " + username);
      console.log("Email Address : " + email_address);

      console.log("TABLE : " + attribute_list);
      console.log("Attribute Table : ");
      // Show value in table
      for (var i in attribute_list){
        console.log("I : " + attribute_list[i]);
      }

      
      userinfo.username = username;
      userinfo.authorityName = authorityName;
      userinfo.email_address = email_address;
      userinfo.attribute_list = attribute_list;

    }
    
    res.send(userinfo);

});

app.post('/changepwd', function (req, res) {

  console.log("----------- CHANGE PASSWORD -------------");

  var objChangePwd = m_main_class.getChangePasswdClassSync();   

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

  result = objChangePwd.getResulFlagSync();
  // Update Password
  if(result){
    console.log("UPDATE PASSWORD");
    m_main_class.updateNewPasswdSync(new_passwd);

    res.send(req.result);
  }
});

var objChangeEmail ;

app.post('/change_email', function (req, res) {

  console.log("----------- CHANGE Email Address -------------");

  var objChangeEmail = m_main_class.getChangeEmailClassSync();   

  console.log("CLASS CHANGE EMAIL ADDRESS : " + objChangeEmail);

  var new_email_address  = req.body.email;
  var confirm_new_passwd = req.body.confirm_new_passwd;

  console.log("NEW EMAIL ADDDRESS : " + new_email_address);
  console.log("CONFIRM NEW PASSWORD : " + confirm_new_passwd);

  objChangeEmail.change_emailSync(new_email_address, confirm_new_passwd);

  var result = objChangeEmail.get_resultSync();

  if(result){
    console.log("UPDATE EMAIL");
    m_main_class.updateNewEmailSync(new_email_address);
    userinfo.email_address = m_main_class.getemailAddressSync();
    res.send(result);
  }
});

app.get('/authority_name_list', function (req, res) {

  if(authority_name_list == null)
    authority_name_list = m_main_class.getAuthorityNameListSync();

  console.log(authority_name_list);

  res.send(authority_name_list);
});

//------------DOWNLOAD PHR-----------------------//

var download_phr_list = null;

app.post('/download_self_phr_list', function (req, res) {

  m_main_class.initDownloadSelfPHR(function(err,result){
    if(!err) {
      m_main_class.getTableDownloadPHR(function(err,result){
        if(!err){
          download_phr_list = result;
          res.send(download_phr_list);
        }
      });
    }
  });

  console.log("DONWLOAD LIST : " + download_phr_list);

});

app.post('/downloadPHR', function (req, res) {

  var index = req.body.index;

  console.log("INDEX : " + index);
  if(download_phr_list.legth != 0){
    var data_description = download_phr_list[index][0];
    var phr_id = parseInt(download_phr_list[index][3],10);

    var result = m_main_class.downloadPHRSync(data_description, phr_id, "/home/bright/Desktop");
    console.log("RESULT FROM DOWNLOAD : " + result);
  }

});

//---------------------- DELETE PHR -----------------------//+

var delete_phr_list = null;

app.post('/delete_self_phr_list', function (req, res) {

  m_main_class.initDeleteSelfPHR(function(err,result){
    if(!err) {
      m_main_class.getTableDeletePHR(function(err,result){
        if(!err){
          delete_phr_list = result;
          res.send(delete_phr_list);
        }
      });
    }
  });

  console.log("Delete LIST : " + delete_phr_list);
});

app.post('/deletePHR', function (req, res) {

  var index = req.body.index;

  console.log("INDEX : " + index);

  if(delete_phr_list.legth != 0){
    var data_description = delete_phr_list[index][0];
    var phr_id = parseInt(delete_phr_list[index][3],10);
    var restricted_level_phr_flag  =  delete_phr_list[index][2] + "";

    var result = m_main_class.deletePHRSync(data_description, phr_id, restricted_level_phr_flag);
    console.log("RESULT FROM DOWNLOAD : " + result);
  }

});


app.use(function(req, res, next){
  res.status(404);
  
  res.redirect('/#error');
});


  var server = app.listen(3000, function () {
  var host = "192.168.174.138";
  var port = server.address().port;

  console.log('Example app listening at http://%s:%s', host, port);
});