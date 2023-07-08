mod utils;
mod srun;
mod xencode;
mod algo;



use std::fs;

fn main() {
    let f = match fs::read_to_string("src/config.json")  {
        Ok(v)=>v,
        Err(e)=>panic!("{}",e)
    }; 

    let Srun = srun::SrunConfig::new_from_config_file(f.as_str());
    Srun.login(Option::None);
}
