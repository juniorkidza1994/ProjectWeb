var java = require('java');
var path = require('path');
var express = require('express');
var multer  = require('multer');
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var methodOverride = require('method-override');
var Type = require('type-of-is');

// USE TO OPEN FILES
var fs = require('fs');

// DELETE DIRECTORY THAT IS NOT EMPTY
var deleteFolderRecursive = function(path) {
  if( fs.existsSync(path) ) {
    fs.readdirSync(path).forEach(function(file,index){
      var curPath = path + "/" + file;
      if(fs.lstatSync(curPath).isDirectory()) { // recurse
        deleteFolderRecursive(curPath);
      } else { // delete file
        fs.unlinkSync(curPath);
      }
    });
    fs.rmdirSync(path);
  }
};

var deleteFilesRecursive = function(path) {
  if( fs.existsSync(path) ) {
    fs.readdirSync(path).forEach(function(file,index){
      var curPath = path + "/" + file;
      if(fs.lstatSync(curPath).isDirectory()) { // recurse
        deleteFolderRecursive(curPath);
      } else { // delete file
        fs.unlinkSync(curPath);
      }
    });
    // fs.rmdirSync(path);
  }
};

var app = express();

// TEMP PATH TO SAVE FILES
var path_files_upload_temp;

// SET PATH USE TO UPLOAD
var storage = multer.diskStorage({


  destination: function (req, file, cb) {

    path_files_upload_temp = '/home/bright/Desktop/Project/webserver/Upload/' + "temp" + '/';
    cb(null, path_files_upload_temp) 
   
  },
  filename: function (req, file, cb) {
    cb(null, file.originalname)
  }
})

// USE TO UPLOAD FILES
var upload = multer({  storage: storage })

//
var bodyParser = require('body-parser');

// SET EXPRESS
app.use(methodOverride());
app.use(require('cookie-parser')());
app.use(require('body-parser').urlencoded({ extended: true }));
app.use(require('express-session')({ secret: 'keyboard cat', resave: false, saveUninitialized: false }));
app.use(passport.initialize());
app.use(passport.session());
app.use(bodyParser.json()); // support json encoded bodies
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname,'..','webclient/public')));

// SET PACKAGE USE IN JAVA
java.classpath.push("../phrapp-0.30/bin/");
java.classpath.push("../phrapp-0.30/bin/commons-lang3-3.1.jar");
java.classpath.push("../phrapp-0.30/bin/paillier.jar");
java.classpath.push("../phrapp-0.30/bin/swingx-all-1.6.3.jar");
java.classpath.push("../phrapp-0.30/bin/paillier.jar");
java.classpath.push("../phrapp-0.30/bin/org-json.jar");

// SET OPTION TO COMPLIE JAVA
java.options.push('-Djava.library.path=../phrapp-0.30/bin/ -classpath *:../phrapp-0.30/bin/');

// CLASS TEST LOGIN
var m_instance = java.newInstanceSync("Login");

//var booleanClass = java.import('java.lang.boolean');

var boolean_true = true;
var boolean_false = false;

// result boolean from login class
var m_result_login;

// DEFINE VARIABLE 
var m_main_class= [];
var m_authority_name_list = [];
var m_download_phr_list = [];
var m_path_files = [];
var m_files = [];

// DELTE ALL FILE IN DIRECTORY
var rmDir = function(dirPath) {
      try { var files = fs.readdirSync(dirPath); }
      catch(e) { return; }
      if (files.length > 0)
        for (var i = 0; i < files.length; i++) {
          var filePath = dirPath + '/' + files[i];
          if (fs.statSync(filePath).isFile())
            fs.unlinkSync(filePath);
          else
            rmDir(filePath);
        }
      return true;
};

// Serialized and deserialized methods when got from session
passport.serializeUser(function(user, done) {
    done(null, user);
});

passport.deserializeUser(function(user, done) {
    done(null, user);
});

// route to test if the user is logged in or not
app.get('/api/loggedin', function(req, res) {
  res.send(req.isAuthenticated() ? req.user : '0');
});

// USE TO LOGIN 
app.post('/api/login', passport.authenticate('local'), function(req, res) {
//  console.log("REQ USER : " + req.user.name);
  res.send(req.user);
});

passport.use(new LocalStrategy(
  function(username, password, done) {
    console.log("--------------- LOGIN ------------------")
    console.log("USERNAME : " + username);
    console.log("PASSWORD : " + password);
   // console.log("DONE : " + done);
    
    // Call java function
    var bool = m_instance.loginSync("127.0.0.1",username,password,"User");

//    console.log(bool);

    if (bool){ // stupid example

/*      console.log("OLD MAIN CLASS : " + m_main_class);*/

      var main_class;

      // Call java function
      main_class = m_instance.getMainClassSync();

/*      console.log("CREATE MAIN CLASS : " + main_class);
*/
      var obj = {};

/*      for(var index in m_test){
        console.log("INDEX : " + index + " VALUE: " + m_test[index]);
      }
*/
      obj[username] = main_class;

//      console.log("OBJ : " + obj);

//      console.log("IN OBJ2 : " + obj[username]);

      m_main_class[username] = main_class;

    //  m_main_class.push(obj);
/*
      console.log("NEW MAIN CLASS : " + m_main_class);

      console.log("MAIN CLASS");*/

/*      for(var index in m_main_class){
        console.log("INDEX : " + index + " VALUE: " + m_main_class[index]);
      }*/

      deleteFolderRecursive('Download/' + username);
      deleteFolderRecursive('Upload/' + username);

      console.log("LOGIN SUCCESS");

      return done(null, {name: username});
    }

    console.log("LOGIN FAIL");
    console.log("----------------- END LOGIN --------------------");

    return done(null, false, { message: 'Incorrect username.' });
  }
));

// USE TO TEST LOGIN 
app.get('/api/admin', function (req, res) {
  // Call java function
  java.callMethodSync(m_instance, "login", "127.0.0.1","admin","bright23","Admin");
  console.log("TESTTT");
});

app.get('/api/user', function (req, res) {
  // Call java function
  java.callMethodSync(m_instance, "login_main", "127.0.0.1","alice","1jQClb1m","User");
  console.log("user");
});

// USE TO TEST LOGIN
app.post('/api/logins', function (req, res) {

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
      m_main_class[req.user.name] = m_instance.getMainClassSync();
      console.log("CLASS : " + m_main_class[req.user.name]);
    }
});

// API GET USERINFO
app.get('/api/userinfo', function (req, res) {

    var userinfo = {};

    if(Object.keys(userinfo).length == 0)
    {
      // Get table & Call java function
      var attribute_list = m_main_class[req.user.name].getTableUserAttributeSync();
      var authorityName = m_main_class[req.user.name].getAuthorityNameSync();
      var username = m_main_class[req.user.name].getUsernameSync();
      var email_address = m_main_class[req.user.name].getemailAddressSync();
      console.log("--------------------- USER INFO -------------------");
      console.log("Authority Name : " + authorityName);
      console.log("Username : " + username);
      console.log("Email Address : " + email_address);

      console.log("TABLE : " + attribute_list);
      console.log("Attribute Table : ");
      // Show value in table
      for (var i in attribute_list){
        console.log("I : " + attribute_list[i]);
      }

      // VARIABLE TO SEND TO CLIENT
      userinfo.username = username;
      userinfo.authorityName = authorityName;
      userinfo.email_address = email_address;
      userinfo.attribute_list = attribute_list;

    }
    
    res.send(userinfo);

    console.log("--------------------- END USER INFO ---------------------");

});

// API CHANGE PASSWORD
app.post('/api/changepwd', function (req, res) {

  console.log("----------- CHANGE PASSWORD -------------");

  // Call java function
  var objChangePwd = m_main_class[req.user.name].getChangePasswdClassSync();   

 // console.log("CLASS CHANGE PASSWORD : " + objChangePwd);

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
    console.log("UPDATE PASSWORD !!");

    // Call java function
    m_main_class[req.user.name].updateNewPasswdSync(new_passwd);

    res.send(req.result);
    console.log("-------------- END CHANGE PASSWORD-----------------");
  }
});

// API CHANGE EMAIL ADDRESS
app.post('/api/change_email', function (req, res) {

  console.log("----------- CHANGE Email Address -------------");

  // Call java function
  var objChangeEmail = m_main_class[req.user.name].getChangeEmailClassSync();   

 // console.log("CLASS CHANGE EMAIL ADDRESS : " + objChangeEmail);

  var new_email_address  = req.body.email;
  var confirm_new_passwd = req.body.confirm_new_passwd;

  console.log("NEW EMAIL ADDDRESS : " + new_email_address);
  console.log("CONFIRM NEW PASSWORD : " + confirm_new_passwd);

  // Call java function
  objChangeEmail.change_emailSync(new_email_address, confirm_new_passwd);

  // Call java function
  var result = objChangeEmail.get_resultSync();

  if(result){
    console.log("UPDATE EMAIL");

    // Call java function
    m_main_class[req.user.name].updateNewEmailSync(new_email_address);
    res.send(result);

    console.log("---------------- END CHANGE EMAIL ---------------");
  }
});

// API GET AUTHORITY NAME LIST
app.post('/api/authority_name_list', function (req, res) {

  console.log("------------------- GET AUTHORITY NAME LIST ------------------------");

  if(m_authority_name_list[req.user.name] == null){

    // Call java function
    m_authority_name_list[req.user.name]  = m_main_class[req.user.name].getAuthorityNameListSync();
  }

  console.log("AUTHORITY NAME LIST : ")
  console.log(m_authority_name_list[req.user.name]);

  res.send(m_authority_name_list[req.user.name]);

  console.log("------------------- END AUTHORITY NAME LIST ------------------------");
});

// -------------- DOWNLOAD SELF PHR -------------------------

// API GET LIST OF PHR
app.post('/api/download_self_phr_list', function (req, res) {
  console.log("------------------- GET DOWNLOAD PHR LIST ------------------------");

  console.log("OLD PHR LIST : " + m_download_phr_list[req.user.name]);

  // Call java function
    m_main_class[req.user.name].initDownloadSelfPHR(req.body.authorityName, req.body.username, function(err,result){
      if(result) {
        // Call java function
        m_main_class[req.user.name].getTableDownloadPHR(function(err,result){
          if(!err){
            console.log("RESULT : " + result);
            m_download_phr_list[req.user.name] = result;
            res.send(m_download_phr_list[req.user.name]);
            console.log("------------------- END DOWNLOAD PHR LIST ------------------------");
          }
        });
      }
      else{
        var empty_array = [];
        res.send(false);
      }
    });
});


// Function to download files and  save 
var downloadfile = function(phr_owner_authority_name, phr_owner_name, data_description, phr_id, path_files, username, callback){

    console.log("---------------- FUNCTION DOWNLOAD FILE ----------------------");

    // Call java function
    m_main_class[username].downloadPHR(phr_owner_authority_name, phr_owner_name, data_description, phr_id, path_files, function(err, result){    
      if(result){

        //  console.log("RESSULT FROM F DOWNLOAD : " + result);

        //  console.log("PATH FILES: " + path_files);
          
          var files = [];
          // process.nextTick(function() 

            // READ LIST FILES IN DIRECTORY
            fs.readdir(path_files,function(err, result){
                if (err) {
                      return console.error(err);
                } 

                else {
               //   console.log("RESULT : " + result);

                  files = result;

               //   console.log("result.length : " + files.length);

                  if(files.length != 0){

                      console.log("FILES : " + files);

                      m_files[username] = files[0];

                      // call calback function
                      if (callback && typeof(callback) === "function") {
                          callback(true);
                      }
                  }
                }

              });         
      }
      else {
          console.log("ERROR " + err);
            
            // call calback function
            if (callback && typeof(callback) === "function") {
                callback(false);
            }
      }

      console.log("---------------- END FUNCTION DOWNLOAD FILE ----------------------");

    });
}

// API DOWNLOAD PHR FILE
app.post('/api/downloadPHR', function (req, res) {

  console.log("------------------- DOWNLOAD FILES -------------------");

  var username = req.user.name;
  var index = req.body.index;
  var data_description = m_download_phr_list[username][index][0];
  var phr_id = parseInt(m_download_phr_list[username][index][3],10);

  m_path_files[username] = '/home/bright/Desktop/Project/webserver/Download/' + username + '/';

  console.log("USER PATH FILES : " +  m_path_files[username]);

  console.log("DATA : " + data_description);

  console.log("ID : " + phr_id);

  // CHECK HAVE DIRECTORY
  fs.stat( m_path_files[username], function(err,stat){

    // HAVE DIRECTORY
    if(err == null){

          // DELETE FILE IN DIRECTORY && DOWNLOAD FILE
          if(rmDir( m_path_files[username])){
              downloadfile(req.body.authorityName, req.body.username ,data_description, phr_id,  m_path_files[username], username, function(result){
              res.send(result);
              });
          }
    }

    // DON'T HAVE DIRECTORY
    else if(err.code == 'ENOENT'){

        // CREATE DIRECTORY
        fs.mkdir( m_path_files[username],function(err){
          if (err) {
              return console.error(err);
          }
           
          else {
            console.log("Directory created successfully!");

            // DOWNLOAD FILES
            downloadfile(req.body.authorityName, req.body.username, data_description, phr_id,  m_path_files[username], username, function(result){
              res.send(result);

              console.log("------------------- END DOWNLOAD FILES -------------------");
            });
          }
        });
    }
  });
});

// API OPEN DOWNLOAD WINDOW ON CLIENT
app.get('/api/downloadPHR', function (req, res) {

  console.log("-------------- OPEN WINDOW DOWNLOAD ------------------");
  console.log("Download Files !!");
  res.download( m_path_files[req.user.name] + m_files[req.user.name],function(err){
    if(!err){
        console.log("-------------- END OPEN WINDOW DOWNLOAD ------------------");

    }
  });
});

//---------------------- DELETE PHR -----------------------//+

var delete_phr_list = null;

app.post('/api/delete_self_phr_list', function (req, res) {

  // call java function
  m_main_class[req.user.name].initDeleteSelfPHR(function(err,result){
    if(!err) {

      // call java function
      m_main_class[req.user.name].getTableDeletePHR(function(err,result){
        if(!err){
          delete_phr_list = result;
          res.send(delete_phr_list);
        }
      });
    }
  });

  console.log("Delete LIST : " + delete_phr_list);
});

app.post('/api/deletePHR', function (req, res) {

  var index = req.body.index;

  console.log("INDEX : " + index);

  if(delete_phr_list.legth != 0){
    var data_description = delete_phr_list[index][0];
    var phr_id = parseInt(delete_phr_list[index][3],10);
    var restricted_level_phr_flag  =  delete_phr_list[index][2] + "";

    var result = m_main_class[req.user.name].deletePHRSync(data_description, phr_id, restricted_level_phr_flag);
    console.log("RESULT FROM DOWNLOAD : " + result);
  }

});

//--------------------------------------------------------------

//------------------ UPLOAD SELF PHR FILES -----------------------------

// SAVE FILE ON NODE JS FOLDER AND UPLOAD TO PHR SERVER
var savefile = function(old_path_file, path_files_upload, phr_owner_name, phr_owner_authority_name, 
             data_description, confidentiality_level, access_policy, threshold, truted_users, username, callback)
{
    console.log("---------------------- SAVEFILE FUNCTION ---------------------");

    console.log(old_path_file);

    // move files from temp to user directory
    fs.rename(old_path_file, path_files_upload, function(error){
    
    if(error) throw error;
    
    // Delete file in temp folder
    fs.unlink(old_path_file, function(){
      if(error) throw error;
      else {
        if(confidentiality_level == "Restricted level"){

          // call java function
          m_main_class.setThresholdValueSync(threshold);
          m_main_class.setNoTrustedUsersSync(truted_users);

          // call java function
          m_main_class[username].uploadSelfPHR(phr_owner_name, phr_owner_authority_name, 
                path_files_upload, data_description, confidentiality_level, 
                access_policy, function(err,result){
                if(!err) {
                    console.log("SUCCESS !!! : " + result);     
                    if (callback && typeof(callback) === "function") {
                        callback(result);
                    }
                    console.log("---------------------- END SAVEFILE FUNCTION ---------------------");
                }

          });
        }
        else {

          // call java function
          m_main_class[username].uploadSelfPHR(phr_owner_name, phr_owner_authority_name, 
                path_files_upload, data_description, confidentiality_level, 
                access_policy, function(err,result){
                if(result) {
                    console.log("SUCCESS !!! : " + result);     
                    if (callback && typeof(callback) === "function") {
                        callback(result);
                    }
                    console.log("---------------------- END SAVEFILE FUNCTION ---------------------");
                }

          });
        }
      }
    });             
  }); 
}

// API UPLOAD FILES TO NODE JS
app.post('/api/uploadPHR', upload.single('file'), function (req, res, next) {

  console.log("---------------------- UPLOAD PHR ---------------------");
  //console.log(req.body);
  //console.log(req.file);

  var path_files_upload = '/home/bright/Desktop/Project/webserver/Upload/' + req.body.phr_owner_name + '/';

  console.log("PATH : " + path_files_upload);

  // CHECK HAVE DIRECTORY
  fs.stat( path_files_upload, function(err,stat){

    console.log("ERROR:  "  + err);
    //if(!fs.existsSync(path_files_upload)){
    if(err != null){
        fs.mkdir(path_files_upload,function(err){
          if (err) {
               return console.error(err);
          }
          else {

            // save file on folder in node server
            savefile(req.file.path, path_files_upload + req.file.originalname, req.body.phr_owner_name, 
              req.body.phr_owner_authority_name, req.body.data_description, req.body.confidentiality_level,
              req.body.access_policy, req.body.threshold,  req.body.truted_users, req.user.name, function(result){
                  res.send(result);
              });   
          }
        });
   }
    else {
      savefile(req.file.path, path_files_upload + req.file.originalname, req.body.phr_owner_name, req.body.phr_owner_authority_name, 
              req.body.data_description, req.body.confidentiality_level, req.body.access_policy,
              req.body.threshold,  req.body.truted_users, req.user.name, function(result){
                  res.send(result);
              });
    }
  })
  console.log("---------------------- END UPLOAD PHR ---------------------");
});

// CHECK HAVE USER
app.post('/api/check_user_exist', function (req, res) {

    // call java function
    m_main_class[req.user.name].checkUserExist(req.body.authority_name, req.body.username, function(err,result){
      if(!err){
        res.send(result);
      }
      else
        console.log(err);
    });
});


// Verify upload permission
app.post('/api/verify_upload_permission_main', function (req, res) {

    console.log("---------------------- Verify upload permission---------------------");
    // call java function
    m_main_class[req.user.name].verifyUploadPermissionMain(req.body.username, req.body.authorityName, function(err,result){
      if(!err) {
        
        res.send(result);

        console.log("----------------------END Verify upload permission---------------------");
      }
      else {
        res.send(false);
        console.log("----------------------END Verify upload permission---------------------");
      }
    });

});

//-------------------------------------------------------------

//------------------ ACCESS PERMISSION MANAGER ------------------

// API GET ACCESS PERMISSION LIST

app.post('/api/access_permission_management_list', function (req, res) {

  console.log("-------------------- GET ACCESS PERMINSION LIST ------------------");
  var access_permission_list ;

  // call java function
  m_main_class[req.user.name].getTableAccessPermissionPHR(function(err,result){
    if(!err){
      access_permission_list = result;
      res.send(access_permission_list );
       console.log("-------------------- END ACCESS PERMINSION LIST ------------------");
    }
  });

});

// API EDIT ACCESS PERMISSION 
app.post('/api/edit_access_permission', function (req, res) {

  console.log("-------------------- EDIT ACCESS PERMINSION LIST ------------------");

  // call java function
  m_main_class[req.user.name].getClassAccessPermissionManagementEdit(req.body.row,function(err,result){  
    if(!err){
      var access_permission_management_class = result;

      // call java function
      access_permission_management_class.editAccessPermission(req.body.uploadflag, req.body.downloadflag, req.body.deleteflag, function(err,result){
      if(!err){
        var result_flag = result;

          // call java function
          m_main_class[req.user.name].update_assigned_access_permission_list(function(err,result){
            if(!err){
              res.send(result_flag);
            }
          });
      }
      else
        console.log(err);
      });
      console.log("-------------------- END EDIT ACCESS PERMINSION LIST ------------------");
    }
  });
});

// API ASSIGN ACCESS PERMISSION
app.post('/api/assign_access_permission', function (req, res) {
  console.log("-------------------- END EDIT ACCESS PERMINSION LIST ------------------");

  // call java function
  m_main_class[req.user.name].getClassAccessPermissionManagementAssign(function(err,result){  
    if(!err){
      var access_permission_management_class = result;

        // call java function
        access_permission_management_class.assignAccessPermission(req.body.authority, req.body.username ,
          req.body.uploadflag, req.body.downloadflag, req.body.deleteflag, function(err,result){
            if(!err){
                var result_flag = result;
                m_main_class[req.user.name].update_assigned_access_permission_list(function(err,result){
                  if(!err){
                      res.send(result_flag);
                  }
                });
            }
            else
              console.log(err);
        });
    }
  });
});

// API DELETE ACCESS PERMISSION
app.post('/api/delete_access_permission', function (req, res) {

    // call java function
    m_main_class[req.user.name].removeAccessPermission(req.body.delete_user, function(err,result){
      if(!err){
        var result_flag = result;
          if(result_flag){

            // call java function
            m_main_class[req.user.name].update_assigned_access_permission_list(function(err,result){
              if(!err){
                  res.send(result_flag);
              }
            });
          }
      }
      else
        console.log(err);
    });
});

//---------------------------------------------//

// GET ATTRIBUTE LIST
app.post('/api/attribute_table', function (req, res) {

  var attribute_table = null;

  var authorityName = m_main_class[req.user.name].getAuthorityNameSync();

  console.log("-------------- get attribute table ---------------");

  // call java function
  m_main_class[req.user.name].initTableAttributePHR(authorityName, function(err,result){
    if(result) {

      // call java function
      m_main_class[req.user.name].getTableAttribute(function(err,result){
        if(result){
          attribute_table = result;
          console.log("Attribute TABLE : " + result);

          console.log("-------------- END attribute table ---------------");
          res.send(attribute_table);
        }
      });
    }
  });
});

// HANDLER NOT FOUND PAGE
/*app.use(function(req, res, next){
  res.status(404);
  
  res.redirect('/#error');
});
*/
// START SERVER
var server = app.listen(3000, function () {
  var host = "192.168.174.138";
  var port = server.address().port;

  rmDir('Upload/temp');

   console.log('Example app listening at http://%s:%s', host, port);
});