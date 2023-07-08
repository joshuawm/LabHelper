use std::fmt::format;

use crate::algo;
use crate::xencode;

use ureq;
use serde::{Serialize,Deserialize};
use serde_json;

#[derive(Debug,Default,Serialize,Deserialize)]
pub struct SrunConfig{
    auth_server:String,
    challenge_url:String,
    login_url:String,

    username:String,
    password:String,
    ip:String,
    
    acid:i32,
    double_stack:i32,
    os:String,
    name:String,

    token:String,
    n:i32,
    utype:i32,
    time:u64,
}

#[derive(Deserialize)]
struct ChallengeResponse{
    challenge:String,
    error:String,
    client_ip:String,
    ecode:i8,
    error_msg:String,
    expire:String,
    online_ip:String,
    res:String,
    srun_ver:String,
    st:i32
}

impl SrunConfig{
    pub fn new(username:String,password:String)->Self{
        SrunConfig { 
            username: username, 
            password: password,
            ..Default::default() 
        }
    }
    
    pub fn new_from_config_file(config_content:&str)->Self{
   
        match serde_json::from_str(config_content) {
            Ok(v)=>v,
            Err(e)=>panic!("Err contered: {}",e)
        }
    }


    pub fn login(&self,ip:Option<String>){
        let challenge = self.get_challenge();

        let password_hash = algo::hmd5(self.password.as_bytes(),challenge.challenge.as_bytes());
        
        let mut iii = String::from("");
        let i = match ip {
            Some(ipp)=>{
                iii.insert_str(0, ipp.as_str());
                &iii
            },
            None=>&challenge.client_ip
        };
        
        let info = xencode::param_i(&self.username, &self.password,i, self.acid, &self.token);

        let chk_sum = {
            let chk_vec =vec![
            "",
            &self.username,
            &password_hash,
            &self.acid.to_string(),
            &self.ip,
            &self.n.to_string(),
            &self.utype.to_string(),
            &info
        ].join(&self.token);

        algo::sha_hash(chk_vec.as_bytes())
        };
  

        let binding = self.n.to_string();
        let bindding1 = self.acid.to_string();
        let params = vec![
            ("callback","jsonp"),
            ("action","login"),
            ("username",&self.username),
            ("password",&self.password),
            ("acid",&bindding1),
            ("ip",&i),
            ("checksum",&chk_sum),
            ("info",&info),
            ("n",&binding),
            ("type","1"),
            ("double_stack","0"),
            ("name","linux"),
            ("os","linux")
        ];
        
        let url = format!("{}{}",self.auth_server,self.login_url);
        let req = ureq::get(url.as_str())
                        .set("CONTENT_TYPE", "application/json")
                        .set("ACCEPT", "application/json")
                        .query_pairs(params)
                        .call();
        let result = match  req {
            Ok(v)=>v,
            Err(e)=>panic!("Failed to send data to AUTH SERVER,Pls Check your Network")
        };
        let result =  result.into_string().unwrap();
        println!("Result:{}",result);

    }
    
    pub fn get_challenge(&self)->ChallengeResponse{
        let url = format!("{}{}",self.auth_server,self.challenge_url);
        let request = ureq::get(url.as_str())
                                        .set("CONTENT_TYPE", "application/json")
                                        .set("ACCEPT","application/json")
                                        .query("username", &self.username)
                                        .query("password", &self.password)
                                        .call();
        let response =match request {
            Ok(response)=>response,
            Err(e)=>panic!("Failed to get challenge, Err:{}",e)
        };
        match serde_json::from_str(response.into_string().unwrap().as_str()){
            Ok(v)=>v,
            Err(e)=>panic!("Failed to parse the response for challenge response, Err:{}",e)
        }
    }
}