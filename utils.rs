use regex::Regex;

pub fn is_valid_address(addr: &str) -> bool {
    let re = Regex::new(r"^0x[a-fA-F0-9]{40}$").unwrap();
    re.is_match(addr)
}

pub fn normalize_address(addr: &str) -> String {
    addr.to_lowercase()
}

pub fn extract_function_signature(code: &str) -> Vec<String> {
    let re = Regex::new(r"function\s+(\w+)\s*\(").unwrap();
    re.captures_iter(code)
        .filter_map(|cap| cap.get(1).map(|m| m.as_str().to_string()))
        .collect()
}

pub fn count_lines(code: &str) -> usize {
    code.matches('\n').count() + 1
}

pub fn get_code_snippet(content: &str, line: u32, context: u32) -> String {
    let lines: Vec<&str> = content.lines().collect();
    let start = line.saturating_sub(context + 1) as usize;
    let end = ((line + context) as usize).min(lines.len());
    lines[start..end].join("\n")
}
