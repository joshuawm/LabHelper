use if_addrs;
use std::{
    net::{IpAddr},
    process::exit,
};

pub fn get_ifs()->Vec<(String,IpAddr)>{
    let ifs = match if_addrs::get_if_addrs() {
        Ok(ifs)=>ifs,
        Err(e)=>exit(500)
    };

    let mut ips = Vec::with_capacity(ifs.len());
    for i in ifs{
        if (!i.is_loopback()){
            ips.push((i.name.clone(),i.ip()));
        }
    }
    ips
}

pub fn get_ip_by_if_name(if_name:&str)->Option<String>{
    let ifs = get_ifs();
    for i in ifs{
        if i.0.contains(if_name) && i.1.is_ipv4(){
            return Some(i.1.to_string())
        }
    };
    None
}

// pub fn select_ip()->Option<String>{
//     let ips = get_ifs();
//     if (ips.is_empty()){
//         return None;
//     }
//     if (ips.len()==1){
//         return Some(ips[0].1.to_string());
//     }

// }