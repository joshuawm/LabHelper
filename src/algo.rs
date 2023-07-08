use hmac::{Hmac,Mac};
use md5::Md5;
use sha1_smol::Sha1;

pub fn hmd5(token:&[u8],password:&[u8])->String{
    let mut mac =match  Hmac::<Md5>::new_from_slice(token){
        Ok(v)=>v,
        Err(e)=>panic!("Faile to encrypt it by hmd5,Err: {}",e)
    };
    mac.update(password);
    let result = mac.finalize();
    format!("{:x}",result.into_bytes())
}

pub fn sha_hash(data:&[u8])->String{
    let mut hasher = Sha1::new();
    hasher.update(data);
    hasher.digest().to_string()
}
