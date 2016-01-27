var cluster = require('cluster');

if(cluster.isMaster){

  var express = require('express');
  var os = require('os');
  var app = express();
  var HashMap = require('hashmap');

  var list_server = new HashMap();
  var status_server = new HashMap();

  var port_worker = 3000;

  var workers = [];

  // Create a worker for each CPU
  for (var i = 1; i <= 2; i += 1) {
    workers[i] = cluster.fork();
    status_server.set((port_worker + i) + "", 0);
        
    workers[i].send(port_worker+i);

    console.log("PROCESS ID : " +  workers[i].process.pid);
  }

  app.get('/',function(req,res){
    var array_key = status_server.keys();

    var isBusy  = false;

    for(var i in array_key){
   //   console.log("i = " + i);
      console.log("port : " + array_key[i]);
      if(status_server.get(array_key[i]) == 0){
        console.log("FREE : " + array_key[i]);
        status_server.set(array_key[i],1);
        console.log("VALUE : " + status_server.get(array_key[i]));
        res.redirect("http://192.168.174.138:"+ array_key[i]);
        isBusy = false;
        break;
      }
      else{
        isBusy = true;
      }
    }
    if(isBusy){
      console.log("Busy Server");
      res.send("SERVER BUSY");
    }
  });

  app.listen(80);

}
else
{
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

      var path_files_upload = '/home/bright/Desktop/Project/webserver/Upload/' + req.body.phr_owner_name + '/';

      if(rmDir( path_files_upload)){

        console.log("REQ UPLOAD : " + req.body.phr_owner_name);

        
        cb(null, path_files_upload) 
     
      }

    },
    filename: function (req, file, cb) {
      cb(null, file.originalname)
    }
  })

  // USE TO UPLOAD FILES
  var upload = multer({  storage: storage  })

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
  var m_files_in_temp = [];

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
    console.log(user);
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
    console.log(req.user);
    res.send(req.user);
  });

  app.get('/api/logout', function(req, res){
    m_main_class[req.user.name].closeProgramSync();
    req.logout();
    res.redirect('/');

  });

  passport.use(new LocalStrategy(
    { passReqToCallback: true},
    function(req, username, password, done) {
      console.log("--------------- LOGIN ------------------")
      console.log(username);
      console.log(password);
      console.log(req.body.type);
     // console.log("DONE : " + done);
      
      // Call java function
      var bool = m_instance.loginSync("127.0.0.1",username,password,req.body.type);

  //    console.log(bool);

      if (bool){ // stupid example

  /*      console.log("OLD MAIN CLASS : " + m_main_class);*/

        var main_class;

        // Call java function
        main_class = m_instance.getMainClassSync();

        console.log("CREATE MAIN CLASS : ");
        console.log(main_class);

        var obj = {};

  /*      for(var index in m_test){
          console.log("INDEX : " + index + " VALUE: " + m_test[index]);
        }
  */
        obj[username] = main_class;

  //      console.log("OBJ : " + obj);

  //      console.log("IN OBJ2 : " + obj[username]);
        console.log("USERNAME : ");
        console.log(username);

        m_main_class[username] = main_class;
        console.log(m_main_class[username]);

      //  m_main_class.push(obj);
  /*
        console.log("NEW MAIN CLASS : " + m_main_class);

        console.log("MAIN CLASS");*/

  /*      for(var index in m_main_class){
          console.log("INDEX : " + index + " VALUE: " + m_main_class[index]);
        }*/

        deleteFolderRecursive('Download/' + username);
        deleteFolderRecursive('Upload/' + username);

        // CREATE UPLOAD FOLDER
        fs.mkdir('Upload/' + username,function(err){
        });

        // CREATE DOWNLOAD FOLDER
        fs.mkdir( 'Download/' + username,function(err){

        });

        console.log("LOGIN SUCCESS");

        return done(null, {name: username, type:req.body.type});
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

  // ------------------------ USER ---------------------------------
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

    var result_flag = objChangePwd.getResultFlagSync();
    var result_msg  = objChangePwd.getResultMsgSync();
    var result = [];

    result[0] = result_flag;
    result[1]  = result_msg;
    console.log(result_msg);
    console.log(result);


    // Update Password
    if(result_flag){
      console.log("UPDATE PASSWORD !!");

      // Call java function
      m_main_class[req.user.name].updateNewPasswdSync(new_passwd);
      res.send(result);
      console.log("-------------- END CHANGE PASSWORD-----------------");
    }
    else {
      console.log("Change PASSWORD Fail !!");
      res.send(result);
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
    var result      = [];
    var result_flag = objChangeEmail.getResultFlagSync();
    var result_msg  = objChangeEmail.getResultMsgSync();

    result[0] = result_flag;
    result[1] = result_msg;

    if(result_flag){
      console.log("UPDATE EMAIL");

      // Call java function
      m_main_class[req.user.name].updateNewEmailSync(new_email_address);
      res.send(result);

      console.log("---------------- END CHANGE EMAIL ---------------");
    }
    else {
      console.log("Change Email Failed");

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
  app.post('/api/download_phr_list', function (req, res) {
    console.log("------------------- GET DOWNLOAD PHR LIST ------------------------");

    console.log("OLD PHR LIST : " + m_download_phr_list[req.user.name]);

    // Call java function
      m_main_class[req.user.name].initDownloadPHRList(req.body.authorityName, req.body.username, function(err,result){
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

          // DELETE FILE IN DIRECTORY && DOWNLOAD FILE
          if(rmDir( m_path_files[username])){
              downloadfile(req.body.authorityName, req.body.username ,data_description, phr_id,  m_path_files[username], username, function(result){
                console.log("------------------- END DOWNLOAD FILES -------------------");
                res.send(result);
                });
          }
  });

  // Cancle download
  app.post('/api/cancelDownloadPHR', function (req, res) {

    console.log("------------------- Cancle Download FILES -------------------");
    m_main_class[req.user.name].setCancelDownload(function(err,result){
      if(!err){
          // DELETE FILE IN DIRECTORY && DOWNLOAD FILE
         res.send(true);
          console.log("------------------- END Cancle Download FILES -------------------");
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
  var savefile = function(path_files_upload, phr_owner_name, phr_owner_authority_name, 
               data_description, confidentiality_level, access_policy, threshold, truted_users, username, callback)
  {
      console.log("---------------------- SAVEFILE FUNCTION ---------------------");

            if(confidentiality_level == "Restricted level"){

              // call java function
              m_main_class.setThresholdValueSync(threshold);
              m_main_class.setNoTrustedUsersSync(truted_users);

              // call java function
              m_main_class[username].uploadPHR(phr_owner_name, phr_owner_authority_name, 
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
              m_main_class[username].uploadPHR(phr_owner_name, phr_owner_authority_name, 
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

  // Cancle Upload
  app.post('/api/cancelUploadPHR', function (req, res) {

    console.log("------------------- Cancle Upload FILES -------------------");
    m_main_class[req.user.name].setCancelUpload(function(err,result){
      if(!err){
          // DELETE FILE IN DIRECTORY && DOWNLOAD FILE
         res.send(true);
          console.log("------------------- END Cancle Upload FILES -------------------");
      }
    });
  });

  // API UPLOAD FILES TO NODE JS
  app.post('/api/uploadPHR', upload.single('file'), function (req, res, next) {

    console.log("---------------------- UPLOAD PHR ---------------------");
    //console.log(req.body);
    //console.log(req.file);

    var path_files_upload = '/home/bright/Desktop/Project/webserver/Upload/' + req.body.phr_owner_name + '/';

    console.log("PATH : " + path_files_upload);

         savefile(req.file.path, req.body.phr_owner_name, 
                req.body.phr_owner_authority_name, req.body.data_description, req.body.confidentiality_level,
                req.body.access_policy, req.body.threshold,  req.body.truted_users, req.user.name, function(result){
                    res.send(result);
                });   

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
    if(req.user.type == "User")
    {  m_main_class[req.user.name].getTableAccessPermissionPHR(function(err,result){
          if(!err){
            access_permission_list = result;
            res.send(access_permission_list );
             console.log("-------------------- END ACCESS PERMINSION LIST ------------------");
          }
        });}

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

  // --------------------------------------------//
  // Emergercy Access Manager
  // Trusted user
  app.post('/api/trusted_users_table', function (req, res) {

    var trusted_users_table = null;

    console.log("-------------- get TrustedUsers table ---------------");

    // call java function
    m_main_class[req.user.name].initTableTrustedUsers( function(err,result){
      if(result) {
        // call java function
        m_main_class[req.user.name].getTableTrustedUsers(function(err,result){
          if(result){
            trusted_users_table = result;
            console.log("Trusted Users TABLE : " + result);

            console.log("-------------- END TrustedUsers table ---------------");
            res.send(trusted_users_table);
          }
        });
      }
    });
  });

  app.post('/api/add_trusted_user', function (req, res) {

    console.log("-------------- ADD TrustedUsers table ---------------");
    var authority_name = m_main_class[req.user.name].getAuthorityNameSync();
    if(req.body.username == req.user.name && req.body.authorityName == authority_name){
      res.send(false);
      console.log("-------------- END TrustedUsers table ---------------");
    }
    else{
    // call java function
      m_main_class[req.user.name].addTrustedUsers(req.body.username, req.body.authorityName, function(err,result){
        if(result) {
          // call java function
              res.send(result);
              console.log("-------------- END TrustedUsers table ---------------");
          }
      });
    }
  });

  //--------------------------------------------------------------------//

  // --------------------------------------------//
  // Delegate 
  app.post('/api/delegate_table', function (req, res) {

    var delegate_table = null;

    console.log("-------------- get Delegate table ---------------");

    // call java function
    m_main_class[req.user.name].initTableDelegate( function(err,result){
      if(result) {
        // call java function
        m_main_class[req.user.name].getTableDelegate(function(err,result){
          if(result){
            delegate_table = result;
            console.log("Delegate TABLE : " + result);

            console.log("-------------- END Delegate table ---------------");
            res.send(delegate_table);
          }
        });
      }
    });
  });

  //--------------------------------------------------------------------//

  // --------------------------------------------//
  // Restricted
  app.post('/api/restricted_table', function (req, res) {

    var restricted_table = null;

    console.log("-------------- get Restricted table ---------------");

    // call java function
    m_main_class[req.user.name].initTableRestricted( function(err,result){
      if(result) {
        // call java function
        m_main_class[req.user.name].getTableRestricted(function(err,result){
          if(result){
            restricted_table = result;
            console.log("Restricted TABLE : " + result);

            console.log("-------------- END Restricted table ---------------");
            res.send(restricted_table);
          }
        });
      }
    });
  });

  app.post('/api/approve_restricted', function (req, res) {

    var restricted_table = null;

    console.log("-------------- get Restricted table ---------------");

    // call java function
    m_main_class[req.user.name].approveRestricted( req.body.phr_ownername, req.body.phr_owner_authority_name, 
        req.body.phr_id, req.body.phr_description, req.body.emergency_staff_name, req.body.emergency_unit_name, function(err,result){
      if(result) {
        res.send(result);
      }
    });
  });

  //--------------------------------------------------------------------//
  // --------------------------------------------//
  // Transaction auditing 
  app.post('/api/transaction_auditing', function (req, res) {

    console.log("-------------- get Transaction table ---------------");


    if(req.body.allFlag){
      // call java function
      m_main_class[req.user.name].setAllLog(req.body.transaction_log_type, function(err,result){
        if(result) {
          //console.log("result 1 : " + result);
          m_main_class[req.user.name].getLog( function(err,result){
            if(result) {
              //console.log("RESULT 2 :");
              console.log(result);
              res.send(result);
              console.log("-------------- End Transaction table ---------------");
            }
            else {
              console.log("ERROR : " + err);
            }
          });
        }
        else {
          console.log("ERROR : " + err);
        }
      });
    }
    else {
      // call java function
      m_main_class[req.user.name].setPeriodLog( req.body.transaction_log_type, req.body.start_year_index, req.body.start_month_index, 
            req.body.start_day_index, req.body.start_hour_index, req.body.start_minute_index, req.body.end_year_index, req.body.end_month_index, req.body.end_day_index, req.body.end_hour_index,  
            req.body.end_minute_index, function(err,result){
        if(result) {
          //console.log("result 1 : " + result);
          m_main_class[req.user.name].getLog( function(err,result){
            if(result) {
              //console.log("RESULT 2 :");
              //console.log(result);
              res.send(result);
              console.log("-------------- End Transaction table ---------------");
            }
            else {
              console.log("ERROR : " + err);
            }
          });
        }
        else {
          console.log("ERROR : " + err);
        }
      });
    }
  });

  //--------------------------------------------------------------------//

  //------------------------ ADMIN -------------------------------------//

  // GET ADMIN INFO
  app.get('/api/admininfo', function (req, res) {

      var admininfo = {};

      if(Object.keys(admininfo).length == 0)
      {
        // Get table & Call java function
        var authorityName = m_main_class[req.user.name].getAuthorityNameSync();
        var username = m_main_class[req.user.name].getUsernameSync();
        var email_address = m_main_class[req.user.name].getEmailSync();
        var audit_server_ip_addr = m_main_class[req.user.name].getAuditServerIPSync();
        var phr_server_ip_addr = m_main_class[req.user.name].getPhrServerIPSync();
        var emergency_server_ip_addr = m_main_class[req.user.name].getEmergencyServerIPSync();
        var mail_server_url = m_main_class[req.user.name].getMailServerSync();
        var authority_email_address = m_main_class[req.user.name].getAuthorityEmailSync();

        console.log("--------------------- Admin INFO -------------------");
        console.log("Authority Name : " + authorityName);
        console.log("Username : " + username);
        console.log("Email Address : " + email_address);

        // VARIABLE TO SEND TO CLIENT
        admininfo.username = username;
        admininfo.authorityName = authorityName;
        admininfo.email_address = email_address;
        admininfo.audit_server_ip_addr = audit_server_ip_addr;
        admininfo.phr_server_ip_addr = phr_server_ip_addr;
        admininfo.emergency_server_ip_addr = emergency_server_ip_addr;
        admininfo.mail_server_url = mail_server_url;
        admininfo.authority_email_address = authority_email_address;

      }


      // INIT TABLE
      m_main_class[req.user.name].initAttributeTableSync();
      m_main_class[req.user.name].initAdminTableSync();
      m_main_class[req.user.name].initAuthorityTableSync();
      
      res.send(admininfo);

      console.log("--------------------- END Admin INFO ---------------------");

  });

  // Change Config

  app.post('/api/changeConfig', function (req, res) {

    console.log("-------------- Change Config ---------------");

    var changeConfigClass ;
    var result = [] ;

    changeConfigClass =  m_main_class[req.user.name].getServerAddressConfigClassSync(); 
    changeConfigClass.changeSync(req.body.audit, req.body.phr,
      req.body.emergency, req.body.passwd); 


    var result_flag = changeConfigClass.getResultFlagSync();
    var result_msg = changeConfigClass.getResultMsgSync();

    if(result_flag)
      m_main_class[req.user.name].updateServerAddressConfigSync(changeConfigClass);

    result[0] = result_flag;
    result[1] = result_msg;

    res.send(result);

    console.log("--------------End Change Config ---------------");

  });

  app.post('/api/changemailserver', function (req, res) {

    console.log("-------------- Change Email Server ---------------");

    var changeMailServerClass ;
    var result = [];

    changeMailServerClass =  m_main_class[req.user.name].getMailServerConfigClassSync(); 
    changeMailServerClass.changeSync(req.body.mailserver, req.body.authorityemail,
      req.body.newpasswd, req.body.confirmpasswd, req.body.password, req.body.changepwd); 

    var result_flag = changeMailServerClass.getResultFlagSync();
    var result_msg  = changeMailServerClass.getResultMsgSync();

    result[0] = result_flag;
    result[1] = result_msg;

    if(result_flag)
      m_main_class[req.user.name].updateMailServerSync(changeMailServerClass);
    
    res.send(result);

     console.log("-------------- End Email Server ---------------");
  });

  app.post('/api/adminattribute', function (req, res) {

    console.log("-------------- Get Atrribute in admin---------------");

    var attribute_table ;

    m_main_class[req.user.name].getTableAttribute(function(err,result){
      if(!err){
        attribute_table = result;
        console.log(attribute_table);
        res.send(attribute_table);
        console.log("-------------- End Atrribute in admin---------------");
      }
    });    
  });

  app.post('/api/registerattribute', function (req, res) {

    console.log("-------------- Register Atrribute in admin---------------");

    var registrationAttribClass = m_main_class[req.user.name].getRegistrationAttributeSync();
    registrationAttribClass.registerSync(req.body.attributename, req.body.isnumerical);

    var result = [];
    var result_flag = registrationAttribClass.getRegistrationResultFlagSync();
    var result_msg  = registrationAttribClass.getRegistrationResultMsgSync();

    result[0] = result_flag;
    result[1] = result_msg;

    if(result)
      m_main_class[req.user.name].updateAttributeTableSync();

    res.send(result);

    console.log("--------------End Register Atrribute in admin---------------");

  });

  app.post('/api/deleteattribute', function (req, res) {

    console.log("-------------- Delete Atrribute in admin---------------");

    var result = m_main_class[req.user.name].removeAttributeSync(req.body.attributename);

    res.send(result);

    console.log("-------------- END Delete Atrribute in admin---------------");

  });

  app.post('/api/admin_transaction_auditing', function (req, res) {

    console.log("-------------- get Transaction table ---------------");


    if(req.body.allFlag){
      // call java function
      m_main_class[req.user.name].setAllLog(req.body.transaction_log_type, function(err,result){
        if(result) {
          //console.log("result 1 : " + result);
          m_main_class[req.user.name].getLog( function(err,result){
            if(result) {
              //console.log("RESULT 2 :");
              console.log(result);
              res.send(result);
              console.log("-------------- End Transaction table ---------------");
            }
            else {
              console.log("ERROR : " + err);
            }
          });
        }
        else {
          console.log("ERROR : " + err);
        }
      });
    }
    else {
      // call java function
      m_main_class[req.user.name].setPeriodLog( req.body.transaction_log_type, req.body.start_year_index, req.body.start_month_index, 
            req.body.start_day_index, req.body.start_hour_index, req.body.start_minute_index, req.body.end_year_index, req.body.end_month_index, req.body.end_day_index, req.body.end_hour_index,  
            req.body.end_minute_index, function(err,result){
        if(result) {
          //console.log("result 1 : " + result);
          m_main_class[req.user.name].getLog( function(err,result){
            if(result) {
              //console.log("RESULT 2 :");
              //console.log(result);
              res.send(result);
              console.log("-------------- End Transaction table ---------------");
            }
            else {
              console.log("ERROR : " + err);
            }
          });
        }
        else {
          console.log("ERROR : " + err);
        }
      });
    }
  });

  app.post('/api/adminlist', function (req, res) {

    console.log("-------------- Get Admin list---------------");

    var admin_table ;

    m_main_class[req.user.name].getTableAdmin(function(err,result){
      if(!err){
        admin_table = result;
        console.log(admin_table);
        res.send(admin_table);
        console.log("-------------- End Admin list---------------");
      }
    });    
  });

  app.post('/api/registeradmin', function (req, res) {

    console.log("-------------- Register Admin---------------");

    var registrationAdminClass = m_main_class[req.user.name].getRegisterAdminClassSync();
    registrationAdminClass.registerAdminSync(req.body.username, req.body.email);

    var result = registrationAdminClass.getResultSync();

    m_main_class[req.user.name].updateAdminListSync();

    res.send(result);

    console.log("--------------End Register Admin---------------");

  });

  app.post('/api/deleteadmin', function (req, res) {

    console.log("-------------- Delete Admin---------------");

    var result = m_main_class[req.user.name].removeAdminSync(req.body.username);

    res.send(result);

    console.log("-------------- END Delete Admin---------------");

  });

  app.post('/api/resetpasswordadmin', function (req, res) {

    console.log("-------------- Reset Password Admin---------------");

    var result = m_main_class[req.user.name].resetPasswordAdminSync(req.body.username);

    res.send(result);

    console.log("-------------- END Reset Password Admin---------------");

  });

  app.post('/api/initeditadmin', function (req, res) {

    console.log("-------------- Init edit Admin---------------");

    m_main_class[req.user.name].initEditAdminClassSync(req.body.username, req.body.email);

    res.send(true);
    console.log("--------------End Init edit Admin---------------");

  });

  app.post('/api/info_editadmin', function (req, res) {

    console.log("--------------Get info edit Admin---------------");

    var info = {};

    var editAdminClass = m_main_class[req.user.name].getEditAdminClassSync();

    info.username = editAdminClass.getCurrentUsernameSync();

    info.email = editAdminClass.getCurrentEmailSync();

    res.send(info);

    console.log("--------------End Get info edit Admin---------------");

  });

  app.post('/api/editadmin', function (req, res) {

    console.log("-------------- Edit Admin---------------");

    var editAdminClass = m_main_class[req.user.name].getEditAdminClassSync();

    editAdminClass.editAdminSync(req.body.username, req.body.email);

    var result = editAdminClass.getResultSync();

    m_main_class[req.user.name].updateAdminListSync();

    res.send(result);

    console.log("--------------End Edit Admin---------------");

  });

  app.post('/api/admin_authority_list', function (req, res) {

    console.log("-------------- Get Authority list in admin---------------");

    var authority_table ;

    m_main_class[req.user.name].getTableAuthority(function(err,result){
      if(!err){
        authority_table = result;
        console.log(authority_table);
        res.send(authority_table);
        console.log("-------------- End Authority list in admin---------------");
      }
    });   

  });

  app.post('/api/registerauthority', function (req, res) {

    console.log("-------------- Register Authority---------------");

    var registrationAuthorityClass = m_main_class[req.user.name].getAuthorityManagementRegisterClassSync();
    registrationAuthorityClass.authorityManagementSync(req.body.authorityname, req.body.ipaddress);

    var result = registrationAuthorityClass.getResultSync();

    m_main_class[req.user.name].updateAuthorityListSync();

    res.send(result);

    console.log("--------------End Register Authority---------------");

  });

  app.post('/api/initeditauthority', function (req, res) {

    console.log("-------------- Init edit Authority---------------");

    m_main_class[req.user.name].initAuthorityManagementEditClassSync(req.body.authorityname, req.body.ipaddress);

    res.send(true);
    console.log("--------------End Init edit Authority---------------");

  });

  app.post('/api/info_editauthority', function (req, res) {

    console.log("--------------Get info edit Authority---------------");

    var info = {};

    var editAuthorityClass = m_main_class[req.user.name].getAuthorityManagementEditClassSync();

    info.authority = editAuthorityClass.getAuthorityNameSync();

    info.ipaddress = editAuthorityClass.getCurrentIPSync();

    console.log(info);

    res.send(info);

    console.log("--------------End Get info edit Authority---------------");

  });

  app.post('/api/editauthority', function (req, res) {

    console.log("-------------- Edit Authority---------------");

    var editAuthorityClass = m_main_class[req.user.name].getAuthorityManagementEditClassSync();

    editAuthorityClass.authorityManagementSync(req.body.authority, req.body.ipaddress);

    var result = editAuthorityClass.getResultSync();

    m_main_class[req.user.name].updateAuthorityListSync();

    res.send(result);

    console.log("--------------End Edit Authority---------------");

  });

  app.post('/api/deleteauthority', function (req, res) {

    console.log("-------------- Delete Authority---------------");

    var result = m_main_class[req.user.name].removeAuthoritySync(req.body.authorityname);

    res.send(result);

    console.log("-------------- END Delete Authority---------------");

  });


  app.post('/api/user_list', function (req, res) {

    console.log("-------------- Get User List Authority---------------");

    // var result = m_main_class[req.user.name].initUserTableSync();

    var result = m_main_class[req.user.name].initAllUserNodeFromUserTreeTableSync();

    console.log(result);

    res.send(result);

    console.log("-------------- End User List Authority---------------");

  });


  app.post('/api/set_register_user', function (req, res) {

    console.log("-------------- Set Edit User Attribute User---------------");

    m_main_class[req.user.name].setUserManagementSync();

    console.log("--------------End Set Edit User User---------------");

  });


  app.post('/api/table_attribute_for_user_management', function (req, res) {

    console.log("-------------- Get Table Attribute User---------------");

    var UserManagementClass = m_main_class[req.user.name].getUserManagementSync();

    var result = UserManagementClass.getTableAttributeSync();

    console.log(result);

    res.send(result);

    console.log("--------------End Table Attribute User---------------");

  });

  app.post('/api/registeruser', function (req, res) {

    console.log("-------------- Register User---------------");

    var registrationUserClass = m_main_class[req.user.name].getUserManagementSync();

    var flag = "";
    
    for(x in req.body.attributeTable){

      console.log(req.body.attributeTable[x]);

      flag = flag +req.body.attributeTable[x][0].toString() + " ";
    }

    flag = flag + ",";

    for(x in req.body.attributeTable){

      console.log(req.body.attributeTable[x]);

      flag = flag +req.body.attributeTable[x][2].toString() + " ";
    }

    registrationUserClass.setTableAttributeSync(flag);

    registrationUserClass.registerUserSync(req.body.username, req.body.email);

    var result = [];

    result[0] = registrationUserClass.getResultFlagSync();
    result[1] = registrationUserClass.getResultMsgSync();

    console.log(result);

    m_main_class[req.user.name].updateAttributeTableSync();
    m_main_class[req.user.name].updateUserListSync();

    res.send(result);

    console.log("--------------End Register User---------------");

  });

  app.post('/api/resetpassworduser', function (req, res) {

    console.log("-------------- Reset Password User---------------");

    var result = [];

    m_main_class[req.user.name].resetPasswordUserSync(req.body.username);

    result[0] = m_main_class[req.user.name].getResultPwdSync();
    result[1] = m_main_class[req.user.name].getResultMsgSync();

    console.log(result);

    res.send(result);

    console.log("--------------End Reset Password User---------------");

  });

  app.post('/api/removeuser', function (req, res) {

    console.log("-------------- Remove User---------------");

    var result = [];

    m_main_class[req.user.name].removeUserSync(req.body.ID);

    console.log(result);

    res.send(result);

    console.log("-------------- End Remove User---------------");

  });

  app.post('/api/setedituser', function (req, res) {

    console.log("-------------- Set Edit User ---------------");

    m_main_class[req.user.name].setEditUserClassSync(req.body.ID);

    console.log("--------------End Set Edit User ---------------");

  });

  app.post('/api/info_for_edit_user', function (req, res) {

    console.log("-------------- Edit User---------------");

    var editUserClass = m_main_class[req.user.name].getUserManagementSync();

    console.log(editUserClass.getUserEditSync());
    console.log(editUserClass.getEmailEditSync());

    var result = [];
    result[0] = editUserClass.getUserEditSync();
    result[1]    = editUserClass.getEmailEditSync();

    res.send(result);
    console.log("--------------End Edit User ---------------");

  });

  app.post('/api/edituser', function (req, res) {

    console.log("-------------- Register User---------------");

    var editUserClass = m_main_class[req.user.name].getUserManagementSync();

    var flag = "";
    
    for(x in req.body.attributeTable){

      console.log(req.body.attributeTable[x]);

      flag = flag +req.body.attributeTable[x][0].toString() + " ";
    }

    flag = flag + ",";

    for(x in req.body.attributeTable){

      flag = flag +req.body.attributeTable[x][2].toString() + " ";
    }

    editUserClass.setTableAttributeSync(flag);

    editUserClass.editUserSync(req.body.username, req.body.email);

    // return value

    console.log("--------------End Register User---------------");

  });

  app.post('/api/seteditattribute', function (req, res) {

    console.log("-------------- Set Edit Attribute User---------------");

    m_main_class[req.user.name].setEditAttributeClassSync(req.body.ID);

    res.send(true);

    console.log("--------------End Set Edit Attribute User---------------");

  });

  app.post('/api/info_for_edit_attribute', function (req, res) {

    console.log("-------------- Get Info Attribute User---------------");

    var editAttributeClass = m_main_class[req.user.name].getEditAttributeClassSync();

    var result = [];
    result[0] = editAttributeClass.getUsernameSync();
    result[1] = editAttributeClass.getAttributeNameSync();
    result[2] = editAttributeClass.getAttributeValueSync();

    res.send(result);
    console.log("--------------End Get Info Attribute User ---------------");

  });

  app.post('/api/editattribute', function (req, res) {

    console.log("-------------- Edit User Attribute ---------------");

    var editAttributeClass = m_main_class[req.user.name].getEditAttributeClassSync();

    var result = [];

    editAttributeClass.editAttributeSync(req.body.username, req.body.attributename, req.body.attributevalue);

    result[0] = editAttributeClass.getResultSync();

    m_main_class[req.user.name].updateAttributeTableSync();
    m_main_class[req.user.name].updateUserListSync();

    result[1] = editAttributeClass.getResultMsgSync();

    res.send(result);


    console.log("--------------End Edit User Attribute---------------");

  });



  //----------------------------------------------------------------------

  // HANDLER NOT FOUND PAGE
  /*app.use(function(req, res, next){
    res.status(404);
    
    res.redirect('/#error');
  });
  */

  var port ;

  process.on('message', function(msg) {
    port = msg;
    app.listen(port);
    console.log("Started port : " + port);
    rmDir('Upload/temp');
  });


  // START SERVER
  // var server = app.listen(3000, function () {
  //   var host = "192.168.174.138";
  //   var port = server.address().port;

  //   rmDir('Upload/temp');

  //    console.log('Example app listening at http://%s:%s', host, port);
  // });
}