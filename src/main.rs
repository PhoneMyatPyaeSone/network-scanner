use iced::{theme, widget::{button, column, row, scrollable, text, text_input}, Alignment, Element, Length, Sandbox, Settings};
use std::{net::TcpStream, result};
use std::time::Duration;
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use std::fs::File;
use std::io::Write;
use trust_dns_resolver::config::*;
use trust_dns_resolver::Resolver;
use std::net::IpAddr;



#[derive(Debug, Serialize, Deserialize)]
enum Tab {
    Scan,
    Tools,
    Help,
    About
}

#[derive(Debug, Clone)]
enum Message {
    GoToScan,
    GoToTools,
    GoToHelp,
    GoToAbout,
    IpChange(String),
    PortChange(String),
    ScanNow,
    SaveScanResult,
    DomainChange(String),
    DnsScan
}
#[derive(Debug, Serialize, Deserialize)]
struct NetworkScanner{
    tab : Tab,
    ip_address: String,
    port_number: String,
    scan_result: Vec<ScanResult>,
    domain_name: String,
    dns_result: Vec<DnsScan>
}

#[derive(Debug, Serialize, Deserialize)]
struct ScanResult{
    port: u16,
    status: String,
    service: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct DnsScan {
    dns_ipv4: String,
    dns_ipv6: String,
}

impl Sandbox for NetworkScanner {
    type Message = Message;

    fn new() -> Self {
        Self {
            tab : Tab::Scan,
            ip_address: String::from("127.0.0.1"),
            port_number: String::from("80"),
            scan_result: Vec::new(),
            domain_name: String::from("www.test.com"),
            dns_result: Vec::new()
        }
    }

    fn title(&self) -> String {
        String::from("Network Scanner")
    }

    fn view(&self) -> Element<'_, Self::Message> {
        let content = match self.tab {
            Tab::Scan => {
                let mut result_display: Vec<Element<'_,Message>> = vec![
                    row![
                        text("PORT")
                            .width(Length::Fixed(100.0))
                            .size(15),
                        text("STATE").width(Length::Fixed(100.0)).size(15),
                        text("SERVICES").size(15)
                    ]
                    .spacing(10)
                    .padding(10)
                    .into()
                ];

                for result in &self.scan_result {
                    result_display.push(
                        row![
                            text(format!("{}/tcp", result.port)).width(Length::Fixed(100.0)).size(15),
                            text(result.status.clone()).width(Length::Fixed(100.0)).size(15),
                            text(result.service.clone()).size(15),
                        ]
                        .spacing(20)
                        .padding(5)
                        .into(),
                    );
                }

                let scrollable_content = scrollable(
                    column(result_display)
                    .width(Length::Fill)
                    .spacing(5)
                    .padding(10)
                )
                .height(Length::Fill);
                
                column![
                    row![
                        button("Scan").on_press(Message::GoToScan).padding(15).style(theme::Button::Secondary),
                        button("Tools").on_press(Message::GoToTools).padding(15).style(theme::Button::Secondary),
                        button("Help").on_press(Message::GoToHelp).padding(15).style(theme::Button::Secondary),
                        button("About").on_press(Message::GoToAbout).padding(15).style(theme::Button::Secondary),
                    ].width(Length::Fill),
                    row![
                        text("IP Address"),
                        text_input("Enter IP Address", &self.ip_address)
                        .on_input(Message::IpChange)
                        .width(Length::Fixed(200.))
                        .padding(10),
                        text("Port"),
                        text_input("Port Number", &self.port_number)
                        .on_input(Message::PortChange)
                        .width(Length::Fixed(100.))
                        .padding(10),
                        button("Scan").on_press(Message::ScanNow).padding(10).style(theme::Button::Secondary),
                        button("Save Result").on_press(Message::SaveScanResult).padding(10).style(theme::Button::Secondary)


                    ]
                    .spacing(10)
                    .padding(10)
                    .align_items(Alignment::Center),
                    scrollable_content,


                ]
                .into()
                
            }
            Tab::Tools => {
                let mut result_display: Vec<Element<'_, Message>> = vec![];

                for result in &self.dns_result {
                    result_display.push(
                        column![
                            text(format!("IPv4: {}", result.dns_ipv4)),
                            // text(format!("IPv6: {}", result.dns_ipv6)),
                        ]
                        .spacing(10)
                        .padding(10)
                        .into(),
                    );
                }
                column![
                row![
                    button("Scan").on_press(Message::GoToScan).padding(15).style(theme::Button::Secondary),
                    button("Tools").on_press(Message::GoToTools).padding(15).style(theme::Button::Secondary),
                    button("Help").on_press(Message::GoToHelp).padding(15).style(theme::Button::Secondary),
                    button("About").on_press(Message::GoToAbout).padding(15).style(theme::Button::Secondary),
                ].width(Length::Fill),
                column![
                    column![
                        text("DNS Scan"),
                        text_input("Enter Domain Name", &self.domain_name)
                        .on_input(Message::DomainChange)
                        .width(Length::Fixed(200.0))
                        .padding(10),
                        button("Scan").on_press(Message::DnsScan).padding(10).style(theme::Button::Secondary),
                        column(result_display)
                        
                    ]
                    .spacing(10)
                    .padding(10)
                    .align_items(Alignment::Center)
                    .width(Length::Fill)
                    .height(Length::Fill)
                    .align_items(Alignment::Center)
                ]
                

            ].into()
            },
            Tab::Help => column![
                row![
                    button("Scan").on_press(Message::GoToScan).padding(15).style(theme::Button::Secondary),
                    button("Tools").on_press(Message::GoToTools).padding(15).style(theme::Button::Secondary),
                    button("Help").on_press(Message::GoToHelp).padding(15).style(theme::Button::Secondary),
                    button("About").on_press(Message::GoToAbout).padding(15).style(theme::Button::Secondary),
                ],
                column![
                    text("How to use").size(30),
                    column![
                        text("Port Scan").size(20),
                        text("Input the IP Address: Enter the IP Address you want to scan. For example, 127.0.0.1"),
                        text("Input the Port(s): "),
                        text("- To scan a single port, input the port number. Example: 80"),
                        text("- To scan multiple ports, input a comma-seperate list of ports. Example 22,443,80"),
                        text("- To scan a range of ports, input the starting and ending port numbers using ..    |      Example: 1..1024 to scan port 1 to port 1024."),

                        text("DNS Scan").size(20),
                        text("Enter a domain name: Type full domain name you want to look up. For example, (www.google.com)"),
                        text("The scanner will return the IPV4 address only.")
                    ]
                    .spacing(15)
                    .padding(10)
                ]
                .padding(15)
            ],
            Tab::About => column![
                row![
                    button("Scan").on_press(Message::GoToScan).padding(15).style(theme::Button::Secondary),
                    button("Tools").on_press(Message::GoToTools).padding(15).style(theme::Button::Secondary),
                    button("Help").on_press(Message::GoToHelp).padding(15).style(theme::Button::Secondary),
                    button("About").on_press(Message::GoToAbout).padding(15).style(theme::Button::Secondary),
                ],

                column![
                    text("This is the final project for first semester using rust programming language").size(20),
                    text("Developed by:").size(20),
                    text("1. Phone Myat Pyae Sone - 67011642").size(20),
                    text("2. La Min Maung - 67011643").size(20),
                ]
                .spacing(15)
                .padding(10)
            ]
        };

        column![
            content
        ].into()
    }

    fn update(&mut self, message: Self::Message) {
        match message {
            Message::GoToScan => self.tab = Tab::Scan,
            Message::GoToTools => self.tab = Tab::Tools,
            Message::GoToHelp => self.tab = Tab::Help,
            Message::GoToAbout => self.tab = Tab::About,
            Message::IpChange(ip) => self.ip_address = ip,
            Message::PortChange(port) => self.port_number = port,
            Message::ScanNow => {
                self.scan_result = self.perform_scan();
                println!("Current IP : {}",self.ip_address);
                println!("Current Port: {}", self.port_number);
                println!("{:?}", self.scan_result)
            },
            Message::SaveScanResult => {
                println!("Save");
                let json_result = serde_json::to_string(&self.scan_result).unwrap();


                let mut file = File::create("Scan_Result.json").expect("Unable to create file");
        
                file.write_all(json_result.as_bytes()).expect("Unable to write data");

            },
            Message::DomainChange(dns) => {
                self.domain_name = dns;
            },
            Message::DnsScan => {
                println!("DNS {}", self.domain_name);
                self.dns_scan();
                println!("{:?}", self.dns_result)
            }
        }
    }

}

impl NetworkScanner {
    fn parse_ports(&self) -> Vec<u16>{
        let mut ports = Vec::new();

        for part in self.port_number.split(","){
            if part.contains("..") {
                let bounds: Vec<&str> = part.split("..").collect();
                if let (Ok(start), Ok(end)) = (bounds[0].trim().parse::<u16>(), bounds[1].trim().parse::<u16>()) {
                    ports.extend(start..=end); // inclusive range
                }
            }
            else {
                if let Ok(port) = part.trim().parse::<u16>(){
                    ports.push(port)
                }
            }
        }
        ports
    }

    fn perform_scan(&self) -> Vec<ScanResult> {
        let ip = &self.ip_address;
        let ports = self.parse_ports();

        println!("Starting scan on IP : {}, Ports : {:?} ", ip, ports);

        let mut result = Vec::new();

        for port in ports {
            let status = if Self::scan_port(ip, port){
                "Open".to_string()
            } else {
                "Closed".to_string()
            };
            let service = NetworkScanner::detect_service(port);
            result.push(ScanResult{port, status, service});
        }
        result
    }

    fn detect_service(port: u16) -> String {
        let mut services: HashMap<u16, &str> = HashMap::new();
        services.insert(21, "FTP");
        services.insert(22, "SSH");
        services.insert(23, "Telnet");
        services.insert(25, "SMTP");
        services.insert(53, "DNS");
        services.insert(80, "HTTP");
        services.insert(110, "POP3");
        services.insert(143, "IMAP");
        services.insert(443, "HTTPS");
        services.insert(3306, "MySQL");
        services.insert(8080, "HTTP Proxy");

        services.get(&port).unwrap_or(&"Unknown").to_string()
    }

    fn scan_port(ip: &str, port: u16) -> bool{
        let address = format!("{}:{}",ip,port);
        match TcpStream::connect_timeout(&address.parse().unwrap(), Duration::from_secs(1)) {
            Ok(_) => true,
            Err(_) => false
        }
    }

    fn dns_scan(&mut self) {
        let domain = self.domain_name.clone();
        let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default()).unwrap();
        let response = resolver.lookup_ip(domain);

        self.dns_result.clear();

        let mut dns_result = DnsScan{
            dns_ipv4: String::new(),
            dns_ipv6: String::new()
        };

        match response {
            Ok(lookup) => {
                for ip in lookup.iter() {
                    match ip {
                        IpAddr::V4(ipv4) => dns_result.dns_ipv4 = ipv4.to_string(),
                        IpAddr::V6(ipv6) => dns_result.dns_ipv6 = ipv6.to_string(),
                    }
                }
                if !dns_result.dns_ipv4.is_empty() || !dns_result.dns_ipv6.is_empty() {
                    self.dns_result.push(dns_result);
                }
            }
            Err(_e) => eprint!("Something wrong!")
        }


    }

}


fn main() -> iced::Result{
    NetworkScanner::run(Settings::default())
}
