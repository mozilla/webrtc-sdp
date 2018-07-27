use std::net::IpAddr;

pub fn maybe_print_param<T>(name: &str, param:T, default_value: T) -> String
                    where T: PartialEq+ToString {
    if param != default_value {
        name.to_owned() + &param.to_string()
    } else {
        "".to_string()
    }
}

pub fn maybe_print_bool_param(name: &str, param:bool, default_value: bool) -> String {
    if param != default_value {
        name.to_owned() + "=" + &(match param {
            true => "1",
            false => "0",
        }.to_string())
    } else {
        "".to_string()
    }
}

pub fn addr_to_string(addr: IpAddr) -> String {
    match addr {
        IpAddr::V4(ipv4) => format!("IN IP4 {}", ipv4.to_string()),
        IpAddr::V6(ipv6) => format!("IN IP4 {}", ipv6.to_string()),
    }
}
