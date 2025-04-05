use std::net::IpAddr;
use std::sync::Arc;

use maxminddb::geoip2;
use smallvec::SmallVec;

use crate::rule_dispatcher::RuleHandle;

pub(crate) type GeoIpRuleMap = SmallVec<[(String, RuleHandle); 2]>;

pub struct GeoIpSet {
    pub(crate) geoip_reader: maxminddb::Reader<Arc<[u8]>>,
    pub(crate) iso_code_rule: GeoIpRuleMap,
}

impl GeoIpSet {
    pub fn query(&self, ip: IpAddr) -> impl Iterator<Item = RuleHandle> {
        println!("正在查询 IP 的地理位置: {}", ip);
        let country: Option<geoip2::Country> = self.geoip_reader.lookup(ip).ok();

        match country {
            Some(c) => {
                if let Some(country) = c.country {
                    if let Some(iso_code) = country.iso_code {
                        println!("✅ IP {} 的国家/地区代码: {}", ip, iso_code);
                        if let Some((_, rule)) =
                            self.iso_code_rule.iter().find(|(rc, _)| rc == iso_code)
                        {
                            println!("✅ 匹配到规则: {:?}", rule);
                            return Some(*rule).into_iter();
                        }
                        println!("❌ 未找到对应的规则");
                    } else {
                        println!("❌ 无法获取国家/地区代码");
                    }
                } else {
                    println!("❌ 无法获取国家信息");
                }
            }
            None => println!("❌ GeoIP 查询失败"),
        }

        None.into_iter()
    }
}
