use std::fs;
use syn::visit::Visit;
use walkdir::WalkDir;

struct DropVisitor<'a> {
    filepath: &'a str,
}

impl<'ast, 'a> Visit<'ast> for DropVisitor<'a> {
    fn visit_item_impl(&mut self, i: &'ast syn::ItemImpl) {
        if let Some((_, path, _)) = &i.trait_
            && let Some(segment) = path.segments.last()
            && segment.ident == "Drop"
        {
            let mut unwrap_visitor = UnwrapVisitor {
                filepath: self.filepath,
            };
            unwrap_visitor.visit_item_impl(i);
        }
        syn::visit::visit_item_impl(self, i);
    }
}

struct UnwrapVisitor<'a> {
    filepath: &'a str,
}

impl<'ast, 'a> Visit<'ast> for UnwrapVisitor<'a> {
    fn visit_expr_method_call(&mut self, i: &'ast syn::ExprMethodCall) {
        let method_name = i.method.to_string();
        if method_name.contains("unwrap") || method_name.contains("expect") {
            println!("{}: has {}", self.filepath, method_name);
        }
        syn::visit::visit_expr_method_call(self, i);
    }
    fn visit_macro(&mut self, m: &'ast syn::Macro) {
        if m.path.is_ident("unwrap") || m.path.is_ident("expect") || m.path.is_ident("panic") {
            println!(
                "{}: has macro {}",
                self.filepath,
                m.path.segments.last().unwrap().ident
            );
        }
        syn::visit::visit_macro(self, m);
    }
}

fn main() {
    let dirs_to_check = vec![
        "../src",
        "../asupersync-browser-core/src",
        "../asupersync-macros/src",
        "../asupersync-tokio-compat/src",
        "../asupersync-wasm/src",
    ];

    for dir in dirs_to_check {
        if !std::path::Path::new(dir).exists() {
            continue;
        }
        for entry in WalkDir::new(dir) {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("rs") {
                // Ignore test files based on path
                let path_str = path.to_string_lossy();
                if path_str.contains("/tests/")
                    || path_str.contains("/test_")
                    || path_str.contains("tests.rs")
                {
                    continue;
                }

                let content = match fs::read_to_string(path) {
                    Ok(c) => c,
                    Err(_) => continue,
                };

                match syn::parse_file(&content) {
                    Ok(file) => {
                        let mut visitor = DropVisitor {
                            filepath: &path_str,
                        };
                        visitor.visit_file(&file);
                    }
                    Err(e) => {
                        eprintln!("Failed to parse {}: {}", path_str, e);
                    }
                }
            }
        }
    }
}
