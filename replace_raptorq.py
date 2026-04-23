import os

replacements = {
    "src/decoding.rs": [
        ("let (columns, coefficients) = decoder.repair_equation(symbol.esi());",
         "let (columns, coefficients) = decoder.repair_equation(symbol.esi()).unwrap();")
    ],
    "src/raptorq/proof.rs": [
        ("let (cols, coefs) = decoder.repair_equation(esi);",
         "let (cols, coefs) = decoder.repair_equation(esi).unwrap();"),
        ("let (replacement_cols, replacement_coefs) = decoder.repair_equation(replacement_esi);",
         "let (replacement_cols, replacement_coefs) = decoder.repair_equation(replacement_esi).unwrap();")
    ],
    "src/raptorq/tests.rs": [
        ("let (cols, coefs) = decoder.repair_equation(esi);",
         "let (cols, coefs) = decoder.repair_equation(esi).unwrap();")
    ],
    "src/raptorq/decoder.rs": [
        ("pub fn repair_equation_rfc6330(&self, esi: u32) -> (Vec<usize>, Vec<Gf256>) {\n        self.repair_equation(esi)",
         "pub fn repair_equation_rfc6330(&self, esi: u32) -> (Vec<usize>, Vec<Gf256>) {\n        self.repair_equation(esi).unwrap()"),
        ("let (cols, coefs) = decoder.repair_equation(esi);",
         "let (cols, coefs) = decoder.repair_equation(esi).unwrap();"),
        ("decoder_eq, shared_eq,", "decoder_eq, shared_eq.unwrap(),")
    ],
    "src/raptorq/systematic.rs": [
        ("let (columns, coefficients) = self.params.rfc_repair_equation(esi);",
         "let (columns, coefficients) = self.params.rfc_repair_equation(esi).unwrap();"),
        ("let (columns, coefficients) = enc.params().rfc_repair_equation(esi);",
         "let (columns, coefficients) = enc.params().rfc_repair_equation(esi).unwrap();"),
        ("let (columns, _) = enc.params().rfc_repair_equation(symbol.esi);",
         "let (columns, _) = enc.params().rfc_repair_equation(symbol.esi).unwrap();")
    ]
}

for file_path, reps in replacements.items():
    if not os.path.exists(file_path):
        continue
    with open(file_path, "r") as f:
        content = f.read()
    for old, new in reps:
        content = content.replace(old, new)
    with open(file_path, "w") as f:
        f.write(content)
print("RaptorQ fixes applied.")
